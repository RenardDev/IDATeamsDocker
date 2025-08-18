#!/bin/bash

set -euo pipefail

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/hexlicsrv"

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/hexlicsrv_schema.lock"

GIT_WORK="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${GIT_WORK}/backups/${GIT_HOST_ID:-hexlicsrv}"

ARCHIVE_NAME="data.tar.zst"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"

################################################################
# App Configuration (env with sane defaults)
################################################################

LICENSE_HOST="${LICENSE_HOST:-localhost}"
LICENSE_PORT="${LICENSE_PORT:-65434}"

################################################################
# Git Sync Configuration (env with sane defaults)
################################################################

GIT_SYNC_ENABLED="${GIT_SYNC_ENABLED:-false}"

GIT_REMOTE="${GIT_REMOTE:-}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_HOST_ID="${GIT_HOST_ID:-hexlicsrv}"

GIT_CHUNK_SIZE_MB="${GIT_CHUNK_SIZE_MB:-49}"

GIT_COMMIT_NAME="${GIT_COMMIT_NAME:-HexLicSrv CI}"
GIT_COMMIT_EMAIL="${GIT_COMMIT_EMAIL:-hexlicsrv@example.com}"

GIT_AUTH_TOKEN="${GIT_AUTH_TOKEN:-}"
GIT_SSH_PRIVATE_KEY="${GIT_SSH_PRIVATE_KEY:-}"
GIT_KNOWN_HOSTS="${GIT_KNOWN_HOSTS:-}"

################################################################
# Utils
################################################################

log() {
  local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
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

now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

################################################################
# Git Helpers (clone-if-empty; always hard-pull if no creds)
################################################################

git_can_push() {
  [[ -n "$GIT_AUTH_TOKEN" || -n "$GIT_SSH_PRIVATE_KEY" ]]
}

git_setup() {
  [[ -n "$GIT_REMOTE" ]] || die "GIT_REMOTE is required"
  mkdir -p "$GIT_WORK"

  local url="$GIT_REMOTE"
  if [[ -n "$GIT_AUTH_TOKEN" && "$GIT_REMOTE" =~ ^https:// ]]; then
    url="https://x-access-token:${GIT_AUTH_TOKEN}@${GIT_REMOTE#https://}"
  fi

  if [[ "$GIT_REMOTE" =~ ^git@ || "$GIT_REMOTE" =~ ^ssh:// ]]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    local key=""
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

  if [[ ! -d "$GIT_WORK/.git" ]]; then
    if [[ -z "$(ls -A "$GIT_WORK" 2>/dev/null)" ]]; then
      log "Cloning repo (branch: ${GIT_BRANCH}) into ${GIT_WORK}"
      if ! git clone --depth=1 --branch "$GIT_BRANCH" "$url" "$GIT_WORK" 2>/dev/null; then
        git clone --depth=1 "$url" "$GIT_WORK"
        git -C "$GIT_WORK" checkout -B "$GIT_BRANCH"
      fi
    else
      die "GIT_WORK exists but is not a git repo: $GIT_WORK"
    fi
  else
    if git -C "$GIT_WORK" remote | grep -q '^origin$'; then
      git -C "$GIT_WORK" remote set-url origin "$url"
    else
      git -C "$GIT_WORK" remote add origin "$url"
    fi
  fi

  git -C "$GIT_WORK" config user.name  "$GIT_COMMIT_NAME"
  git -C "$GIT_WORK" config user.email "$GIT_COMMIT_EMAIL"
  mkdir -p "$REMOTE_DIR"
}

git_pull() {
  log "Syncing ${GIT_BRANCH} (read-only=$([[ git_can_push ]] && echo no || echo yes))"
  git -C "$GIT_WORK" remote | grep -q '^origin$' || die "No 'origin' remote in $GIT_WORK"

  if git -C "$GIT_WORK" ls-remote --heads origin "$GIT_BRANCH" | grep -q "$GIT_BRANCH"; then
    git -C "$GIT_WORK" fetch --depth=1 origin "$GIT_BRANCH"
    git -C "$GIT_WORK" checkout -B "$GIT_BRANCH" "origin/${GIT_BRANCH}"
    git -C "$GIT_WORK" reset --hard "origin/${GIT_BRANCH}"
    git -C "$GIT_WORK" clean -xfd
  else
    log "Remote branch '${GIT_BRANCH}' not found; keeping empty local branch"
    git -C "$GIT_WORK" checkout --orphan "$GIT_BRANCH"
    git -C "$GIT_WORK" reset --hard
    git -C "$GIT_WORK" clean -xfd
  fi

  mkdir -p "$REMOTE_DIR"
}

git_commit_push() {
  local msg="$1"
  if ! git_can_push; then
    log "Read-only mode (no token/SSH) -> skipping commit/push"
    return 0
  fi
  git -C "$GIT_WORK" add -A
  if git -C "$GIT_WORK" diff --cached --quiet; then
    log "Nothing to commit"
    return 0
  fi
  git -C "$GIT_WORK" commit -m "$msg"
  git -C "$GIT_WORK" push origin "$GIT_BRANCH"
}

################################################################
# Packing / Splitting helpers (FS)
################################################################

pack_data_dir() {
  rm -f "$ARCHIVE_PATH"
  tar -C "$DATA_PATH" -cf - . | zstd -q -T0 -19 -o "$ARCHIVE_PATH"
  local size sha
  size="$(stat -c '%s' "$ARCHIVE_PATH")"
  sha="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  printf '%s %s\n' "$size" "$sha"
}

split_archive_into_remote() {
  local bs=$((GIT_CHUNK_SIZE_MB * 1000000))
  mkdir -p "$REMOTE_DIR"
  rm -f "${REMOTE_DIR}/data.tar.zst.part_"* "${REMOTE_DIR}/${MANIFEST_NAME}" || true
  split -b "$bs" -d -a 3 "$ARCHIVE_PATH" "${REMOTE_DIR}/data.tar.zst.part_"
}

assemble_remote_archive() {
  local dest="$1"
  rm -f "$dest"
  # shellcheck disable=SC2046
  cat $(ls "${REMOTE_DIR}/data.tar.zst.part_"* | sort) > "$dest"
}

write_manifest() {
  local ts="$1" size="$2" sha="$3"
  jq -n \
    --arg host_id "$GIT_HOST_ID" \
    --arg timestamp_utc "$ts" \
    --argjson chunk_size_mb "$GIT_CHUNK_SIZE_MB" \
    --argjson archive_size_bytes "$size" \
    --arg archive_sha256 "$sha" \
    --argjson chunk_count "$(ls "${REMOTE_DIR}/data.tar.zst.part_"* 2>/dev/null | wc -l)" \
    '{
      host_id: $host_id,
      timestamp_utc: $timestamp_utc,
      chunk_size_mb: $chunk_size_mb,
      chunk_count: $chunk_count,
      archive_size_bytes: $archive_size_bytes,
      archive_sha256: $archive_sha256
    }' > "${REMOTE_DIR}/${MANIFEST_NAME}"
}

read_remote_manifest() {
  if [[ -f "${REMOTE_DIR}/${MANIFEST_NAME}" ]]; then cat "${REMOTE_DIR}/${MANIFEST_NAME}"; else echo ""; fi
}

################################################################
# FS Sync (pull-if-empty, else push-if-allowed)
################################################################

perform_fs_sync() {
  ensure_tools
  git_setup
  git_pull

  local man; man="$(read_remote_manifest || true)"

  # If local FS empty — try restore from remote
  if [[ -z "$(ls -A "$DATA_PATH" 2>/dev/null)" ]]; then
    if [[ -n "$man" ]]; then
      log "FS empty -> restore from remote"
      local tmp sha_remote sha_local; tmp="${INSTALL_PATH}/_restore"
      rm -rf "$tmp"; mkdir -p "$tmp"
      ls "${REMOTE_DIR}/data.tar.zst.part_"* >/dev/null 2>&1 || die "Remote parts not found"
      assemble_remote_archive "$tmp/${ARCHIVE_NAME}"
      sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
      sha_local="$(sha256sum "$tmp/${ARCHIVE_NAME}" | awk '{print $1}')"
      [[ "$sha_remote" == "$sha_local" ]] || die "Checksum mismatch"
      rm -rf "${DATA_PATH:?}/"* "${DATA_PATH}/."[!.]* 2>/dev/null || true
      mkdir -p "$DATA_PATH"
      tar -C "$DATA_PATH" -xpf "$tmp/${ARCHIVE_NAME}"
      rm -rf "$tmp"
    else
      log "FS empty and no remote snapshot"
    fi
    return 0
  fi

  # Local FS present
  if ! git_can_push; then
    log "Read-only: local FS present -> skip packaging/push"
    return 0
  fi

  log "FS present -> package & maybe push"
  local size sha need_push sha_remote
  read -r size sha <<<"$(pack_data_dir)"
  need_push="yes"
  if [[ -n "$man" ]]; then
    sha_remote="$(echo "$man" | jq -r '.archive_sha256')"
    if [[ "$sha_remote" == "$sha" ]]; then
      log "Same as remote, skip push"; need_push="no"
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
cd "$INSTALL_PATH" || die "Failed to cd into $INSTALL_PATH"

CONFIG_FILE="${CONFIG_PATH}/hexlicsrv.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "sqlite3;Data Source=${DATA_PATH}/hexlicsrv.sqlite3;" > "$CONFIG_FILE"
  chmod 640 "$CONFIG_FILE"
fi

if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
  echo "Missing CA files"; sleep 5; exit 1
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

python3 "${INSTALL_PATH}/license_patch.py" hexlicsrv || die "Patch failed"

chown root:root "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm" || true
chmod 755 "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm" || true

if [[ ! -f "$SCHEMA_LOCK" ]]; then
  "${INSTALL_PATH}/license_server" -f "$CONFIG_FILE" --recreate-schema
  touch "$SCHEMA_LOCK"
fi

################################################################
# TLS: CSR & self-signed CRT via CA
################################################################

openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/hexlicsrv.key" -out "${CONFIG_PATH}/hexlicsrv.csr" -nodes -subj "/CN=${LICENSE_HOST}" >/dev/null 2>&1 || die "CSR failed"
openssl x509 -req -in "${CONFIG_PATH}/hexlicsrv.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/hexlicsrv.crt" -days 365 -sha512 -extfile <(cat <<-EOF
  [req]
  distinguished_name=req_distinguished_name
  [req_distinguished_name]
  [v3_req]
  keyUsage = critical, digitalSignature, keyEncipherment
  extendedKeyUsage = serverAuth
  subjectAltName = @alt_names
  [alt_names]
  DNS.1 = ${LICENSE_HOST}
EOF
) >/dev/null 2>&1 || die "CRT failed"
rm -f "${CONFIG_PATH}/hexlicsrv.csr"

chown hexlicsrv:hexlicsrv "$CONFIG_FILE" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic" || true
chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"

################################################################
# Launch
################################################################

exec "${INSTALL_PATH}/license_server" -f "$CONFIG_FILE" -p "$LICENSE_PORT" -l "${LOGS_PATH}/license_server.log" -c "${CONFIG_PATH}/hexlicsrv.crt" -k "${CONFIG_PATH}/hexlicsrv.key" -L "${INSTALL_PATH}/license_server.hexlic"
