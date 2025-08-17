#!/bin/bash

set -euo pipefail

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/hexvault"

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/hexvault_schema.lock"

GIT_WORK="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${GIT_WORK}/backups/${GIT_HOST_ID:-hexvault}"

ARCHIVE_NAME="data.tar.zst"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"

################################################################
# App Configuration (env with sane defaults)
################################################################

VAULT_HOST="${VAULT_HOST:-localhost}"
VAULT_PORT="${VAULT_PORT:-65433}"

AUTO_RESTART_SECONDS="${AUTO_RESTART_SECONDS:-0}"

################################################################
# Git Sync Configuration (env with sane defaults)
################################################################

GIT_SYNC_ENABLED="${GIT_SYNC_ENABLED:-false}"

GIT_REMOTE="${GIT_REMOTE:-}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_HOST_ID="${GIT_HOST_ID:-hexvault}"

GIT_CHUNK_SIZE_MB="${GIT_CHUNK_SIZE_MB:-49}"

GIT_COMMIT_NAME="${GIT_COMMIT_NAME:-HexVault CI}"
GIT_COMMIT_EMAIL="${GIT_COMMIT_EMAIL:-hexvault@example.com}"

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
  for t in git ssh-keyscan tar zstd jq sha256sum split openssl; do
    command -v "$t" >/dev/null 2>&1 || die "Missing tool: $t"
  done
}

now_utc() {
  date -u +'%Y-%m-%dT%H:%M:%SZ'
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

    local key
    if [[ -n "$GIT_SSH_PRIVATE_KEY" ]]; then
      key="/root/.ssh/id_ed25519"
      grep -q "BEGIN OPENSSH PRIVATE KEY" <<<"$GIT_SSH_PRIVATE_KEY" || key="/root/.ssh/id_rsa"
      printf '%s\n' "$GIT_SSH_PRIVATE_KEY" > "$key"
      chmod 600 "$key"
    fi

    if [[ -n "$GIT_KNOWN_HOSTS" ]]; then
      printf '%s\n' "$GIT_KNOWN_HOSTS" > /root/.ssh/known_hosts
      chmod 644 /root/.ssh/known_hosts
      export GIT_SSH_COMMAND="ssh -i ${key:-/root/.ssh/id_ed25519} -o UserKnownHostsFile=/root/.ssh/known_hosts -o StrictHostKeyChecking=yes"
    else
      export GIT_SSH_COMMAND="ssh -i ${key:-/root/.ssh/id_ed25519} -o StrictHostKeyChecking=no"
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
    log "No FS changes to commit"
    return 0
  fi

  git -C "$GIT_WORK" commit -m "$msg"
  git -C "$GIT_WORK" push origin "$GIT_BRANCH"
}

read_remote_manifest() {
  if [[ -f "${REMOTE_DIR}/${MANIFEST_NAME}" ]]; then
    cat "${REMOTE_DIR}/${MANIFEST_NAME}"
  else
    echo ""
  fi
}

################################################################
# Packing / Splitting helpers
################################################################

pack_data_dir() {
  rm -f "$ARCHIVE_PATH"

  tar -C "$DATA_PATH" -cf - . \
    | zstd -q -T0 -19 -o "$ARCHIVE_PATH"

  local size sha
  size="$(stat -c '%s' "$ARCHIVE_PATH")"
  sha="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"

  printf '%s %s\n' "$size" "$sha"
}

split_archive_into_remote() {
  local bs=$((GIT_CHUNK_SIZE_MB * 1000000))

  rm -f "${REMOTE_DIR}/data.tar.zst.part_"* "${REMOTE_DIR}/${MANIFEST_NAME}" || true

  split -b "$bs" -d -a 3 \
    "$ARCHIVE_PATH" \
    "${REMOTE_DIR}/data.tar.zst.part_"
}

assemble_remote_archive() {
  local dest="$1"

  rm -f "$dest"
  # shellcheck disable=SC2046
  cat $(ls "${REMOTE_DIR}/data.tar.zst.part_"* | sort) > "$dest"
}

write_manifest() {
  local ts="$1"
  local size="$2"
  local sha="$3"

  jq -n \
    --arg host_id "$GIT_HOST_ID" \
    --arg timestamp_utc "$ts" \
    --argjson chunk_size_mb "$GIT_CHUNK_SIZE_MB" \
    --argjson archive_size_bytes "$size" \
    --arg archive_sha256 "$sha" \
    --argjson chunk_count "$(ls "${REMOTE_DIR}/data.tar.zst.part_"* 2>/dev/null | wc -l)" \
    '{
      host_id:             $host_id,
      timestamp_utc:       $timestamp_utc,
      chunk_size_mb:       $chunk_size_mb,
      chunk_count:         $chunk_count,
      archive_size_bytes:  $archive_size_bytes,
      archive_sha256:      $archive_sha256
    }' > "${REMOTE_DIR}/${MANIFEST_NAME}"
}

################################################################
# FS Sync (pull-if-empty else push-if-different)
################################################################

perform_fs_sync() {
  ensure_tools
  git_setup
  git_pull

  local man
  man="$(read_remote_manifest || true)"

  # If local FS empty — try restore from remote
  if [[ -z "$(ls -A "$DATA_PATH" 2>/dev/null)" ]]; then
    if [[ -n "$man" ]]; then
      log "FS empty -> restore"

      local tmp sha_remote sha_local
      tmp="${INSTALL_PATH}/_restore"

      rm -rf "$tmp"
      mkdir -p "$tmp"

      ls "${REMOTE_DIR}/data.tar.zst.part_"* >/dev/null 2>&1 || die "Remote parts not found"

      assemble_remote_archive "$tmp/${ARCHIVE_NAME}"

      sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
      sha_local="$(sha256sum "$tmp/${ARCHIVE_NAME}" | awk '{print $1}')"

      [[ "$sha_remote" == "$sha_local" ]] || die "Checksum mismatch"

      # Clean and extract
      rm -rf "${DATA_PATH:?}/"* "${DATA_PATH}/."[!.]* 2>/dev/null || true
      mkdir -p "$DATA_PATH"
      tar -C "$DATA_PATH" -xpf "$tmp/${ARCHIVE_NAME}"
      rm -rf "$tmp"
    else
      log "FS empty and no remote snapshot"
    fi

    return 0
  fi

  # Local FS present — package & optionally push
  log "FS present -> package & maybe push"

  local size sha need_push sha_remote
  read -r size sha <<<"$(pack_data_dir)"
  need_push="yes"

  if [[ -n "$man" ]]; then
    sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
    if [[ "$sha_remote" == "$sha" ]]; then
      log "Same as remote, skip push"
      need_push="no"
    fi
  fi

  if [[ "$need_push" == "yes" ]]; then
    split_archive_into_remote
    write_manifest "$(now_utc)" "$size" "$sha"
    git_commit_push "fs-backup(${GIT_HOST_ID}): size=${size} sha256=${sha}"
  fi
}

################################################################
# Bootstrap filesystem & base config
################################################################

mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"
cd "$INSTALL_PATH" || die "Failed to cd"

CONFIG_FILE="${CONFIG_PATH}/hexvault.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "sqlite3;Data Source=${DATA_PATH}/hexvault.sqlite3;" > "$CONFIG_FILE"
  chmod 640 "$CONFIG_FILE"
fi

if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
  echo "Missing CA files"
  sleep 5
  exit 1
fi

################################################################
# Optional: Git-based FS synchronization
################################################################

if [[ "${GIT_SYNC_ENABLED,,}" == "true" ]]; then
  perform_fs_sync
else
  log "FS sync disabled"
fi

################################################################
# Patch, permissions, schema
################################################################

python3 "${INSTALL_PATH}/license_patch.py" hexvault || die "Patch failed"

chown root:root \
  "${INSTALL_PATH}/vault_server" || true

chmod 755 \
  "${INSTALL_PATH}/vault_server" || true

if [[ ! -f "$SCHEMA_LOCK" ]]; then
  "${INSTALL_PATH}/vault_server" -f "$CONFIG_FILE" -d "$DATA_PATH" --recreate-schema
  touch "$SCHEMA_LOCK"
fi

################################################################
# TLS: CSR & self-signed CRT via CA
################################################################

openssl req -newkey rsa:2048 \
  -keyout "${CONFIG_PATH}/hexvault.key" \
  -out   "${CONFIG_PATH}/hexvault.csr" \
  -nodes \
  -subj "/CN=${VAULT_HOST}" \
  >/dev/null 2>&1 || die "CSR failed"

openssl x509 -req \
  -in "${CONFIG_PATH}/hexvault.csr" \
  -CA "${CA_PATH}/CA.pem" \
  -CAkey "${CA_PATH}/CA.key" \
  -CAcreateserial \
  -out "${CONFIG_PATH}/hexvault.crt" \
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
    DNS.1 = "$VAULT_HOST"
EOF
) >/dev/null 2>&1 || die "CRT failed"

rm -f "${CONFIG_PATH}/hexvault.csr"

chmod 640 \
  "$CONFIG_FILE" \
  "${CONFIG_PATH}/hexvault.crt" \
  "${CONFIG_PATH}/hexvault.key" \
  "${INSTALL_PATH}/teams_server.hexlic"

################################################################
# Watchdog & Launch
################################################################

start_auto_restart_watchdog

exec "${INSTALL_PATH}/vault_server" \
  -f "$CONFIG_FILE" \
  -p "$VAULT_PORT" \
  -l "${LOGS_PATH}/vault_server.log" \
  -c "${CONFIG_PATH}/hexvault.crt" \
  -k "${CONFIG_PATH}/hexvault.key" \
  -L "${INSTALL_PATH}/teams_server.hexlic" \
  -d "$DATA_PATH"
