#!/bin/bash

set -euo pipefail
shopt -s nullglob

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/lumina"

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/lumina_schema.lock"

GH_WORK="${INSTALL_PATH}/_dbgit"
REMOTE_DIR="${GH_WORK}/backups/${GH_HOST_ID:-lumina}"

DUMP_PATH="${INSTALL_PATH}/dump.sql"
ARCHIVE_NAME="dump.sql.zst"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"

SKIP_SCHEMA_RECREATE=0

################################################################
# App Configuration
################################################################

MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-lumina}"
MYSQL_USER="${MYSQL_USER:-lumina}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-lumina}"

LUMINA_HOST="${LUMINA_HOST:-localhost}"
LUMINA_PORT="${LUMINA_PORT:-443}"

################################################################
# GitHub Releases Storage
################################################################

RELEASE_SYNC_ENABLED="${RELEASE_SYNC_ENABLED:-false}"
GH_OWNER="${GH_OWNER:-}"
GH_REPO="${GH_REPO:-}"
GH_RELEASE_TAG="${GH_RELEASE_TAG:-lumina-snapshot}"
GH_RELEASE_NAME="${GH_RELEASE_NAME:-Lumina Snapshot}"
GH_TOKEN="${GH_TOKEN:-${GH_AUTH_TOKEN:-}}"

GH_CHUNK_SIZE_MB="${GH_CHUNK_SIZE_MB:-49}"

GH_API="https://api.github.com"
GH_UPLOAD="https://uploads.github.com"

################################################################
# Utils
################################################################

now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] %s\n' "$(now_utc)" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2; exit 1; }

ensure_tools() {
  local miss=()
  for t in curl zstd jq sha256sum split mysql mysqldump nc openssl mktemp; do
    command -v "$t" >/dev/null 2>&1 || miss+=("$t")
  done
  ((${#miss[@]}==0)) || die "Missing tools: ${miss[*]}"
}

wait_for_db() {
  log "Waiting for MySQL ${MYSQL_HOST}:${MYSQL_PORT}..."
  until nc -z "$MYSQL_HOST" "$MYSQL_PORT"; do sleep 3; done
  log "MySQL is reachable"
}

chown_if_user() {
  local u="$1"; shift
  if id -u "$u" >/dev/null 2>&1; then chown "$u:$u" "$@"; else chown root:root "$@"; fi
}

mysql_query_scalar() {
  mysql --batch --skip-column-names --protocol=TCP \
    -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
    -e "$1"
}

db_is_empty() {
  local cnt
  cnt="$(mysql_query_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MYSQL_DATABASE}';" | tr -d '\r' || echo 0)"
  [[ "${cnt:-0}" -eq 0 ]]
}

################################################################
# Dump / Import
################################################################

db_dump() {
  rm -f "$DUMP_PATH" "$ARCHIVE_PATH"
  log "Dumping DB '${MYSQL_DATABASE}' -> $ARCHIVE_PATH"
  mysqldump --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
    --single-transaction --quick --routines --events --triggers --hex-blob --no-tablespaces \
    --databases "$MYSQL_DATABASE" > "$DUMP_PATH"
  zstd -q -T0 -19 -o "$ARCHIVE_PATH" "$DUMP_PATH"
  local size sha
  size="$(stat -c '%s' "$ARCHIVE_PATH")"
  sha="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  printf '%s %s\n' "$size" "$sha"
}

db_import_archive() {
  log "Importing DB from '$1'"
  zstd -dc "$1" | mysql --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}"
}

split_archive_into_remote() {
  local bs=$((GH_CHUNK_SIZE_MB * 1000000))
  mkdir -p "$REMOTE_DIR"
  rm -f "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"* "${REMOTE_DIR}/${MANIFEST_NAME}" || true
  log "Splitting DB archive to ${REMOTE_DIR} by ${GH_CHUNK_SIZE_MB}MB"
  split -b "$bs" -d -a 3 "$ARCHIVE_PATH" "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"
}

write_manifest() {
  local ts="$1" size="$2" sha="$3"
  local parts=( "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"* )
  local cnt="${#parts[@]}"
  jq -n --arg host_id "${GH_HOST_ID:-lumina}" \
        --arg timestamp_utc "$ts" \
        --argjson chunk_size_mb "$GH_CHUNK_SIZE_MB" \
        --argjson archive_size_bytes "$size" \
        --arg archive_sha256 "$sha" \
        --argjson chunk_count "$cnt" \
        '{host_id:$host_id,timestamp_utc:$timestamp_utc,chunk_size_mb:$chunk_size_mb,chunk_count:$chunk_count,archive_size_bytes:$archive_size_bytes,archive_sha256:$archive_sha256}' \
    > "${REMOTE_DIR}/${MANIFEST_NAME}"
  log "Wrote manifest ${REMOTE_DIR}/${MANIFEST_NAME} (chunks=$cnt sha=$sha size=$size)"
}

################################################################
# GitHub Releases helpers (same pattern)
################################################################

gh_init_auth() {
  GH_AUTH_HEADER=()
  if [[ -n "$GH_TOKEN" ]]; then
    GH_AUTH_HEADER=(-H "Authorization: Bearer ${GH_TOKEN}" -H "X-GitHub-Api-Version: 2022-11-28")
    log "GitHub mode: read-write (token present)"
  else
    log "GitHub mode: read-only (no token)"
  fi
}

HTTP_STATUS=""; HTTP_BODY_FILE=""
http_json() {
  local method="$1" url="$2" data="${3:-}" ctype="${4:-application/json}"
  local tmp; tmp="$(mktemp)"; local code
  if [[ -n "$data" ]]; then
    code="$(curl -sS -w '%{http_code}' "${GH_AUTH_HEADER[@]}" -H "Accept: application/vnd.github+json" -H "Content-Type: ${ctype}" -X "$method" --data "$data" "$url" -o "$tmp" || true)"
  else
    code="$(curl -sS -w '%{http_code}' "${GH_AUTH_HEADER[@]}" -H "Accept: application/vnd.github+json" -X "$method" "$url" -o "$tmp" || true)"
  fi
  HTTP_STATUS="$code"; HTTP_BODY_FILE="$tmp"
}

gh_get_release_id_by_tag() {
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${GH_RELEASE_TAG}"
  http_json "GET" "$url"
  case "$HTTP_STATUS" in
    200) jq -r '.id // empty' <"$HTTP_BODY_FILE";;
    404) echo "";;
    *)   die "GET $url failed (HTTP $HTTP_STATUS)";;
  esac
}

gh_create_release() {
  [[ -n "$GH_TOKEN" ]] || die "GH_TOKEN is required to create release ${GH_RELEASE_TAG}"
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases"
  local body; body=$(jq -n --arg tag "$GH_RELEASE_TAG" --arg name "$GH_RELEASE_NAME" '{tag_name:$tag,name:$name,prerelease:true,draft:false}')
  http_json "POST" "$url" "$body"
  [[ "$HTTP_STATUS" == "201" ]] || die "POST $url failed (HTTP $HTTP_STATUS)"
  jq -r '.id' <"$HTTP_BODY_FILE"
}

gh_ensure_release() {
  local id; id="$(gh_get_release_id_by_tag)"
  if [[ -z "$id" ]]; then
    if [[ -n "$GH_TOKEN" ]]; then
      log "Release '${GH_RELEASE_TAG}' not found -> creating"
      id="$(gh_create_release)"
    else
      log "Release '${GH_RELEASE_TAG}' not found and no GH_TOKEN -> staying in read-only (skip)"
      GH_REL_ID=""
      return 0
    fi
  fi
  GH_REL_ID="$id"
  log "Using release id=$GH_REL_ID tag=${GH_RELEASE_TAG}"
}

gh_list_assets() {
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?per_page=100"
  http_json "GET" "$url"
  [[ "$HTTP_STATUS" == "200" ]] || die "GET $url failed (HTTP $HTTP_STATUS)"
  cat "$HTTP_BODY_FILE"
}

gh_delete_asset_id() {
  local id="$1"; local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"
  http_json "DELETE" "$url"
  [[ "$HTTP_STATUS" =~ ^20[04]$ ]] || die "DELETE asset $id failed (HTTP $HTTP_STATUS)"
  log "Deleted asset id=$id"
}

gh_delete_assets_by_prefix() {
  local prefix="$1"; local assets ids
  assets="$(gh_list_assets)"
  ids="$(jq -r --arg p "$prefix" '.[] | select(.name | startswith($p)) | .id' <<<"$assets")"
  if [[ -z "$ids" ]]; then
    log "No assets to delete with prefix '$prefix'"
    return 0
  fi
  while read -r id; do [[ -n "$id" ]] && gh_delete_asset_id "$id"; done <<< "$ids"
}

gh_upload_asset() {
  local file="$1" name; name="$(basename "$file")"
  local url="${GH_UPLOAD}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?name=${name}"
  local code; code="$(curl -sS -w '%{http_code}' "${GH_AUTH_HEADER[@]}" -H "Content-Type: application/octet-stream" --data-binary @"$file" "$url" -o /dev/null || true)"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || die "UPLOAD ${name} failed (HTTP ${code})"
  log "Uploaded asset ${name}"
}

gh_download_asset_to() {
  local name="$1" out="$2"
  [[ -n "$GH_REL_ID" ]] || return 1
  local assets id; assets="$(gh_list_assets || true)"
  id="$(jq -r --arg n "$name" '.[] | select(.name==$n) | .id' <<<"$assets" || true)"
  [[ -n "$id" && "$id" != "null" ]] || return 1
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"
  local code; code="$(curl -L -sS -w '%{http_code}' "${GH_AUTH_HEADER[@]}" -H "Accept: application/octet-stream" -o "$out" "$url" || true)"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || die "DOWNLOAD ${name} failed (HTTP ${code})"
  log "Downloaded asset ${name} -> ${out}"
}

################################################################
# Releases-based DB sync
################################################################

perform_releases_db_sync() {
  ensure_tools; wait_for_db; gh_init_auth
  if [[ "${RELEASE_SYNC_ENABLED,,}" != "true" ]]; then log "Release sync disabled -> skip"; return 0; fi
  if [[ -z "$GH_OWNER" || -z "$GH_REPO" ]]; then log "GH_OWNER/GH_REPO not set -> skip"; return 0; fi

  gh_ensure_release
  [[ -n "$GH_REL_ID" ]] || { log "No release id (likely RO with no release) -> skip"; return 0; }

  local tmp="${INSTALL_PATH}/_ghrel"; rm -rf "$tmp"; mkdir -p "$tmp"

  if gh_download_asset_to "${MANIFEST_NAME}" "${tmp}/${MANIFEST_NAME}"; then
    local man sha_remote
    man="$(cat "${tmp}/${MANIFEST_NAME}")"
    sha_remote="$(jq -r '.archive_sha256' <<<"$man")"

    if db_is_empty; then
      log "DB is empty -> restoring from release '${GH_RELEASE_TAG}'"
      local cnt i part
      cnt="$(jq -r '.chunk_count' <<<"$man")"
      [[ -n "$cnt" && "$cnt" != "null" ]] || die "Invalid manifest (chunk_count)"
      for ((i=0;i<cnt;i++)); do
        part=$(printf '%s.part_%03d' "$ARCHIVE_NAME" "$i")
        gh_download_asset_to "$part" "${tmp}/${part}" || die "Missing asset $part"
      done
      cat "${tmp}/${ARCHIVE_NAME}.part_"* > "${tmp}/${ARCHIVE_NAME}"
      local sha_local; sha_local="$(sha256sum "${tmp}/${ARCHIVE_NAME}" | awk '{print $1}')"
      [[ "$sha_local" == "$sha_remote" ]] || die "DB checksum mismatch: remote=$sha_remote local=$sha_local"
      db_import_archive "${tmp}/${ARCHIVE_NAME}"
      SKIP_SCHEMA_RECREATE=1
      log "DB restore completed"
      rm -rf "$tmp"
      return 0
    fi

    if [[ -n "$GH_TOKEN" ]]; then
      local size sha; read -r size sha <<<"$(db_dump)"
      if [[ "$sha" != "$sha_remote" ]]; then
        log "DB differs from release -> uploading new dump"
        split_archive_into_remote
        gh_delete_assets_by_prefix "${ARCHIVE_NAME}.part_"
        gh_delete_assets_by_prefix "${MANIFEST_NAME}"
        for f in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do gh_upload_asset "$f"; done
        write_manifest "$(now_utc)" "$size" "$sha"
        gh_upload_asset "${REMOTE_DIR}/${MANIFEST_NAME}"
      else
        log "DB matches release (sha=$sha) -> nothing to upload"
      fi
    else
      log "No GH_TOKEN -> read-only mode, skipping upload"
    fi
    rm -rf "$tmp"; return 0
  fi

  if [[ -n "$GH_TOKEN" && ! db_is_empty ]]; then
    log "No manifest at release but token present -> publishing initial dump"
    local size sha; read -r size sha <<<"$(db_dump)"
    split_archive_into_remote
    gh_delete_assets_by_prefix "${ARCHIVE_NAME}.part_"
    gh_delete_assets_by_prefix "${MANIFEST_NAME}"
    for f in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do gh_upload_asset "$f"; done
    write_manifest "$(now_utc)" "$size" "$sha"
    gh_upload_asset "${REMOTE_DIR}/${MANIFEST_NAME}"
  else
    log "No manifest and no token -> nothing to do (RO)"
  fi
  rm -rf "$tmp"; return 0
}

################################################################
# Bootstrap & Launch
################################################################

log "Bootstrap: creating directories"
mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"
cd "$INSTALL_PATH" || die "Failed to cd into $INSTALL_PATH"

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
  log "Created default config $CONFIG_FILE"
fi

if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
  printf '[%s] ERROR: Missing CA files\n' "$(now_utc)" >&2
  sleep 5
  exit 1
fi

if [[ "${RELEASE_SYNC_ENABLED,,}" == "true" ]]; then perform_releases_db_sync; else log "Release sync disabled"; fi

log "Patching license"
python3 "${INSTALL_PATH}/license_patch.py" lumina || die "Patch failed"

chown root:root "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" || true
chmod 755 "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" || true

if [[ ! -f "$SCHEMA_LOCK" ]]; then
  if [[ "$SKIP_SCHEMA_RECREATE" -eq 0 ]]; then
    SCHEMA_TYPE="lumina"; [[ -n "${VAULT_HOST:-}" && -n "${VAULT_PORT:-}" ]] && SCHEMA_TYPE="vault"
    log "Recreating schema ($SCHEMA_TYPE)..."
    "${INSTALL_PATH}/lumina_server" -f "$CONFIG_FILE" --recreate-schema "$SCHEMA_TYPE"
  else
    log "Schema recreate skipped (restored from release)"
  fi
  touch "$SCHEMA_LOCK"
fi

log "Generating TLS cert via local CA"
openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/lumina.key" -out "${CONFIG_PATH}/lumina.csr" -nodes -subj "/CN=${LUMINA_HOST}" >/dev/null 2>&1 || die "CSR failed"
openssl x509 -req -in "${CONFIG_PATH}/lumina.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/lumina.crt" -days 365 -sha512 -extfile <(cat <<-EOF
  [req]
  distinguished_name=req_distinguished_name
  [req_distinguished_name]
  [v3_req]
  keyUsage = critical, digitalSignature, keyEncipherment
  extendedKeyUsage = serverAuth
  subjectAltName = @alt_names
  [alt_names]
  DNS.1 = ${LUMINA_HOST}
EOF
) >/dev/null 2>&1 || die "CRT failed"
rm -f "${CONFIG_PATH}/lumina.csr"

chown_if_user lumina \
  "$CONFIG_FILE" \
  "${CONFIG_PATH}/lumina.crt" \
  "${CONFIG_PATH}/lumina.key" \
  "${INSTALL_PATH}/lumina_server.hexlic" || true

chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"

log "Starting lumina_server on :${LUMINA_PORT}"
exec "${INSTALL_PATH}/lumina_server" \
  -f "$CONFIG_FILE" \
  -p "$LUMINA_PORT" \
  -D "$DATA_PATH" \
  -l "${LOGS_PATH}/lumina_server.log" \
  -c "${CONFIG_PATH}/lumina.crt" \
  -k "${CONFIG_PATH}/lumina.key" \
  -L "${INSTALL_PATH}/lumina_server.hexlic"
