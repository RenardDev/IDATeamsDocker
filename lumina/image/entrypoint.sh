#!/bin/bash

set -euo pipefail

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/lumina"

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/lumina_schema.lock"

GIT_WORK="${INSTALL_PATH}/_dbgit"
REMOTE_DIR="${GIT_WORK}/backups/${GIT_HOST_ID}"

GIT_DUMP_BASENAME="${MYSQL_DATABASE:-lumina}.sql"
GIT_DUMP_PATH="${INSTALL_PATH}/${GIT_DUMP_BASENAME}"

GIT_ARCHIVE_NAME="${GIT_DUMP_BASENAME}.zst"
GIT_ARCHIVE_PATH="${INSTALL_PATH}/${GIT_ARCHIVE_NAME}"

GIT_MANIFEST_NAME="manifest.json"

SKIP_SCHEMA_RECREATE=0

################################################################
# App Configuration (env with sane defaults)
################################################################

MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-lumina}"
MYSQL_USER="${MYSQL_USER:-lumina}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-lumina}"

LUMINA_HOST="${LUMINA_HOST:-localhost}"
LUMINA_PORT="${LUMINA_PORT:-443}"

AUTO_RESTART_SECONDS="${AUTO_RESTART_SECONDS:-0}"

################################################################
# Git DB Sync Configuration (env with sane defaults)
################################################################

GIT_SYNC_ENABLED="${GIT_SYNC_ENABLED:-false}"

GIT_REMOTE="${GIT_REMOTE:-}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_HOST_ID="${GIT_HOST_ID:-lumina}"

GIT_CHUNK_SIZE_MB="${GIT_CHUNK_SIZE_MB:-49}"

GIT_COMMIT_NAME="${GIT_COMMIT_NAME:-Lumina DB Backup}"
GIT_COMMIT_EMAIL="${GIT_COMMIT_EMAIL:-lumina-db@example.com}"

GIT_AUTH_TOKEN="${GIT_AUTH_TOKEN:-}"
GIT_SSH_PRIVATE_KEY="${GIT_SSH_PRIVATE_KEY:-}"
GIT_KNOWN_HOSTS="${GIT_KNOWN_HOSTS:-}"

################################################################
# Utils
################################################################

log() {
  local ts
  ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  printf '[%s] %s\n' "$ts" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

ensure_tools() {
  local t
  for t in git ssh-keyscan zstd jq tar sha256sum split mysql mysqldump nc openssl; do
    command -v "$t" >/dev/null 2>&1 || die "Missing tool: $t"
  done
}

now_utc() {
  date -u +'%Y-%m-%dT%H:%M:%SZ'
}

wait_for_db() {
  until nc -z "$MYSQL_HOST" "$MYSQL_PORT"; do
    log "Waiting DB ${MYSQL_HOST}:${MYSQL_PORT}…"
    sleep 3
  done
}

start_auto_restart_watchdog() {
  local t="${AUTO_RESTART_SECONDS:-0}"
  if [[ "$t" =~ ^[0-9]+$ ]] && (( t > 0 )); then
    (
      sleep "$t"
      log "Auto-restart: stopping PID 1 for scheduled refresh"
      kill -TERM 1
    ) &
  fi
}

################################################################
# DB Helpers (dump/import/inspect)
################################################################

mysql_query_scalar() {
  mysql \
    --batch \
    --skip-column-names \
    --protocol=TCP \
    -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
    -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
    -e "$1"
}

db_is_empty() {
  local cnt
  cnt="$(mysql_query_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MYSQL_DATABASE}';" | tr -d '\r')"
  [[ "${cnt:-0}" -eq 0 ]]
}

db_dump() {
  rm -f "$GIT_DUMP_PATH" "$GIT_ARCHIVE_PATH"

  mysqldump \
    --protocol=TCP \
    -h "$MYSQL_HOST" -P "$MYSQL_PORT" \
    -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
    --single-transaction \
    --quick \
    --routines \
    --events \
    --triggers \
    --hex-blob \
    --no-tablespaces \
    --databases "$MYSQL_DATABASE" \
    > "$GIT_DUMP_PATH"

  zstd -q -T0 -19 -o "$GIT_ARCHIVE_PATH" "$GIT_DUMP_PATH"

  local size sha
  size="$(stat -c '%s' "$GIT_ARCHIVE_PATH")"
  sha="$(sha256sum "$GIT_ARCHIVE_PATH" | awk '{print $1}')"

  printf '%s %s\n' "$size" "$sha"
}

db_import_archive() {
  zstd -dc "$1" \
    | mysql --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}"
}

################################################################
# Git Helpers
################################################################

git_setup() {
  [[ -n "$GIT_REMOTE" ]] || die "GIT_REMOTE is required"

  rm -rf "$GIT_WORK"
  mkdir -p "$GIT_WORK"

  git -C "$GIT_WORK" init
  git -C "$GIT_WORK" config user.name  "$GIT_COMMIT_NAME"
  git -C "$GIT_WORK" config user.email "$GIT_COMMIT_EMAIL"

  # Token for HTTPS remotes
  if [[ -n "$GIT_AUTH_TOKEN" && "$GIT_REMOTE" =~ ^https:// ]]; then
    GIT_REMOTE="https://x-access-token:${GIT_AUTH_TOKEN}@${GIT_REMOTE#https://}"
  fi

  # SSH setup if needed
  if [[ "$GIT_REMOTE" =~ ^git@ || "$GIT_REMOTE" =~ ^ssh:// ]]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    local dbkey
    if [[ -n "$GIT_SSH_PRIVATE_KEY" ]]; then
      dbkey="/root/.ssh/id_ed25519"
      grep -q "BEGIN OPENSSH PRIVATE KEY" <<<"$GIT_SSH_PRIVATE_KEY" || dbkey="/root/.ssh/id_rsa"
      printf '%s\n' "$GIT_SSH_PRIVATE_KEY" > "$dbkey"
      chmod 600 "$dbkey"
    fi

    if [[ -n "$GIT_KNOWN_HOSTS" ]]; then
      printf '%s\n' "$GIT_KNOWN_HOSTS" > /root/.ssh/known_hosts
      chmod 644 /root/.ssh/known_hosts
      export GIT_SSH_COMMAND="ssh -i ${dbkey:-/root/.ssh/id_ed25519} -o UserKnownHostsFile=/root/.ssh/known_hosts -o StrictHostKeyChecking=yes"
    else
      export GIT_SSH_COMMAND="ssh -i ${dbkey:-/root/.ssh/id_ed25519} -o StrictHostKeyChecking=no"
    fi
  fi

  git -C "$GIT_WORK" remote add origin "$GIT_REMOTE"
}

git_pull() {
  log "Fetching ${GIT_BRANCH}"

  if git -C "$GIT_WORK" ls-remote --heads origin "$GIT_BRANCH" | grep -q "$GIT_BRANCH"; then
    git -C "$GIT_WORK" fetch --depth=1 origin "$GIT_BRANCH"
    git -C "$GIT_WORK" checkout -B "$GIT_BRANCH" "origin/${GIT_BRANCH}"
  else
    git -C "$GIT_WORK" checkout --orphan "$GIT_BRANCH"
    rm -rf "${GIT_WORK:?}/"*
  fi

  mkdir -p "$REMOTE_DIR"
}

git_commit_push() {
  local msg="$1"

  git -C "$GIT_WORK" add -A
  if git -C "$GIT_WORK" diff --cached --quiet; then
    log "DB: nothing to commit"
    return 0
  fi

  git -C "$GIT_WORK" commit -m "$msg"
  git -C "$GIT_WORK" push origin "$GIT_BRANCH"
}

db_read_remote_manifest() {
  if [[ -f "${REMOTE_DIR}/${GIT_MANIFEST_NAME}" ]]; then
    cat "${REMOTE_DIR}/${GIT_MANIFEST_NAME}"
  else
    echo ""
  fi
}

db_split_into_remote() {
  local bs=$((GIT_CHUNK_SIZE_MB * 1000000))

  rm -f "${REMOTE_DIR}/${GIT_ARCHIVE_NAME}.part_"* "${REMOTE_DIR}/${GIT_MANIFEST_NAME}" || true

  split -b "$bs" -d -a 3 \
    "$GIT_ARCHIVE_PATH" \
    "${REMOTE_DIR}/${GIT_ARCHIVE_NAME}.part_"
}

db_assemble_from_remote() {
  local dest="$1"

  rm -f "$dest"
  # shellcheck disable=SC2046
  cat $(ls "${REMOTE_DIR}/${GIT_ARCHIVE_NAME}.part_"* | sort) > "$dest"
}

db_write_manifest() {
  local ts="$1"
  local size="$2"
  local sha="$3"

  jq -n \
    --arg    host_id "$GIT_HOST_ID" \
    --arg    db_name "$MYSQL_DATABASE" \
    --arg    timestamp_utc "$ts" \
    --argjson chunk_size_mb "$GIT_CHUNK_SIZE_MB" \
    --argjson archive_size_bytes "$size" \
    --arg    archive_sha256 "$sha" \
    --argjson chunk_count "$(ls "${REMOTE_DIR}/${GIT_ARCHIVE_NAME}.part_"* 2>/dev/null | wc -l)" \
    '{
      type:               "mysql_dump",
      host_id:            $host_id,
      database:           $db_name,
      timestamp_utc:      $timestamp_utc,
      chunk_size_mb:      $chunk_size_mb,
      chunk_count:        $chunk_count,
      archive_size_bytes: $archive_size_bytes,
      archive_sha256:     $archive_sha256
    }' > "${REMOTE_DIR}/${GIT_MANIFEST_NAME}"
}

################################################################
# DB Sync (pull-if-empty else push-if-different)
################################################################

perform_db_sync() {
  ensure_tools
  git_setup
  git_pull

  local man
  man="$(db_read_remote_manifest || true)"

  # If DB is empty — try restore from remote
  if db_is_empty; then
    if [[ -n "$man" ]]; then
      log "DB empty -> restoring from remote"

      local tmp sha_remote sha_local
      tmp="${INSTALL_PATH}/_dbrestore"

      rm -rf "$tmp"
      mkdir -p "$tmp"

      ls "${REMOTE_DIR}/${GIT_ARCHIVE_NAME}.part_"* >/dev/null 2>&1 || die "Remote DB parts not found"

      db_assemble_from_remote "$tmp/${GIT_ARCHIVE_NAME}"

      sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
      sha_local="$(sha256sum "$tmp/${GIT_ARCHIVE_NAME}" | awk '{print $1}')"

      [[ "$sha_remote" == "$sha_local" ]] || die "DB checksum mismatch"

      db_import_archive "$tmp/${GIT_ARCHIVE_NAME}"
      rm -rf "$tmp"

      SKIP_SCHEMA_RECREATE=1
    else
      log "DB empty and no remote snapshot"
    fi

    return 0
  fi

  # Local DB present — dump & optionally push
  log "DB present -> dump and compare"

  local size sha need_push sha_remote
  read -r size sha <<<"$(db_dump)"
  need_push="yes"

  if [[ -n "$man" ]]; then
    sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
    if [[ "$sha_remote" == "$sha" ]]; then
      log "Same as remote, skipping push"
      need_push="no"
    fi
  fi

  if [[ "$need_push" == "yes" ]]; then
    db_split_into_remote
    db_write_manifest "$(now_utc)" "$size" "$sha"
    git_commit_push "mysql-backup(${GIT_HOST_ID}/${MYSQL_DATABASE}): size=${size} sha256=${sha}"
  fi
}

################################################################
# Bootstrap filesystem & base config
################################################################

mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"
cd "$INSTALL_PATH" || die "Failed to cd"

wait_for_db

CONFIG_FILE="${CONFIG_PATH}/lumina.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
  {
    echo "CONNSTR=\"mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD;\""
    if [[ -n "${VAULT_HOST:-}" && -n "${VAULT_PORT:-}" ]]; then
      echo "VAULT_HOST=\"${VAULT_HOST}:${VAULT_PORT}\""
    fi
  } > "$CONFIG_FILE"
  chmod 640 "$CONFIG_FILE"
fi

if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
  echo "Missing CA files"
  sleep 5
  exit 1
fi

################################################################
# Optional: Git-based DB synchronization
################################################################

if [[ "${GIT_SYNC_ENABLED,,}" == "true" ]]; then
  perform_db_sync
else
  log "DB sync disabled"
fi

################################################################
# Patch, permissions, schema
################################################################

python3 "${INSTALL_PATH}/license_patch.py" lumina || die "Patch failed"

chown root:root \
  "${INSTALL_PATH}/lumina_server" \
  "${INSTALL_PATH}/lc" || true

chmod 755 \
  "${INSTALL_PATH}/lumina_server" \
  "${INSTALL_PATH}/lc" || true

if [[ ! -f "$SCHEMA_LOCK" ]]; then
  if [[ "$SKIP_SCHEMA_RECREATE" -eq 1 ]]; then
    log "Skipping schema recreation (restored from remote)"
  else
    SCHEMA_TYPE="lumina"
    if [[ -n "${VAULT_HOST:-}" && -n "${VAULT_PORT:-}" ]]; then
      SCHEMA_TYPE="vault"
    fi

    "${INSTALL_PATH}/lumina_server" \
      -f "$CONFIG_FILE" \
      --recreate-schema "$SCHEMA_TYPE"
  fi

  touch "$SCHEMA_LOCK"
fi

################################################################
# TLS: CSR & self-signed CRT via CA
################################################################

openssl req -newkey rsa:2048 \
  -keyout "${CONFIG_PATH}/lumina.key" \
  -out   "${CONFIG_PATH}/lumina.csr" \
  -nodes \
  -subj "/CN=${LUMINA_HOST}" \
  >/dev/null 2>&1 || die "CSR failed"

openssl x509 -req \
  -in "${CONFIG_PATH}/lumina.csr" \
  -CA "${CA_PATH}/CA.pem" \
  -CAkey "${CA_PATH}/CA.key" \
  -CAcreateserial \
  -out "${CONFIG_PATH}/lumina.crt" \
  -days 365 \
  -sha512 \
  -extfile <(cat <<-EOF
    [req]
    distinguished_name=req_distinguished_name
    [req_distinguished_name]
    [v3_req]
    keyUsage = critical, digitalSignature, keyEncipherment
    extendedKeyUsage = serverAuth
    subjectAltName = @alt_names
    [alt_names]
    DNS.1 = "$LUMINA_HOST"
EOF
) >/dev/null 2>&1 || die "CRT failed"

rm -f "${CONFIG_PATH}/lumina.csr"

chmod 640 \
  "$CONFIG_FILE" \
  "${CONFIG_PATH}/lumina.crt" \
  "${CONFIG_PATH}/lumina.key" \
  "${INSTALL_PATH}/lumina_server.hexlic"

################################################################
# Watchdog & Launch
################################################################

start_auto_restart_watchdog

exec "${INSTALL_PATH}/lumina_server" \
  -f "$CONFIG_FILE" \
  -p "$LUMINA_PORT" \
  -D "$DATA_PATH" \
  -l "${LOGS_PATH}/lumina_server.log" \
  -c "${CONFIG_PATH}/lumina.crt" \
  -k "${CONFIG_PATH}/lumina.key" \
  -L "${INSTALL_PATH}/lumina_server.hexlic"
