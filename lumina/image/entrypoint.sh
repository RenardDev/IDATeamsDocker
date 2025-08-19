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

WORK_DIR="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${WORK_DIR}/backups/${SYNC_HOST_ID:-lumina}"

DUMP_PATH="${INSTALL_PATH}/dump.sql"
ARCHIVE_NAME="dump.sql.zst"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"

SKIP_SCHEMA_RECREATE=0

################################################################
# App Configuration (MySQL)
################################################################
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-lumina}"
MYSQL_USER="${MYSQL_USER:-lumina}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-lumina}"

LUMINA_HOST="${LUMINA_HOST:-localhost}"
LUMINA_PORT="${LUMINA_PORT:-443}"

# optional (affects schema type only)
VAULT_HOST="${VAULT_HOST:-}"
VAULT_PORT="${VAULT_PORT:-}"

################################################################
# Unified Sync Configuration
################################################################
SYNC_ENABLED="${SYNC_ENABLED:-false}"
SYNC_METHOD="${SYNC_METHOD:-commits}"               # commits|releases
SYNC_AUTH_TOKEN="${SYNC_AUTH_TOKEN:-}"              # empty -> RO

SYNC_HOST_ID="${SYNC_HOST_ID:-lumina}"
SYNC_CHUNK_SIZE_MB="${SYNC_CHUNK_SIZE_MB:-49}"

GH_REMOTE="${GH_REMOTE:-}"
GH_BRANCH="${GH_BRANCH:-main}"
GH_COMMIT_NAME="${GH_COMMIT_NAME:-Lumina CI}"
GH_COMMIT_EMAIL="${GH_COMMIT_EMAIL:-lumina@example.com}"
GH_SSH_PRIVATE_KEY="${GH_SSH_PRIVATE_KEY:-}"
GH_KNOWN_HOSTS="${GH_KNOWN_HOSTS:-}"

GH_RELEASE_TAG="${GH_RELEASE_TAG:-lumina-snapshot}"
GH_RELEASE_NAME="${GH_RELEASE_NAME:-Lumina Snapshot}"
GH_API="${GH_API:-}"
GH_UPLOAD="${GH_UPLOAD:-}"

################################################################
# Utils
################################################################
now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] %s\n' "$(now_utc)" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2; exit 1; }
ensure_int() { local __v="$1" __d="$2"; if [[ -z "${!__v:-}" || ! "${!__v}" =~ ^[0-9]+$ ]]; then printf -v "$__v" '%s' "$__d"; fi; }
ensure_dirs() { mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH" "$WORK_DIR" "$REMOTE_DIR"; }
chown_if_user() { local u="$1"; shift; if id -u "$u" >/dev/null 2>&1; then chown "$u:$u" "$@"; else chown root:root "$@"; fi; }

ensure_tools_common() {
  local m=(); for t in zstd jq sha256sum split mysql mysqldump nc tar openssl; do command -v "$t" >/dev/null 2>&1 || m+=("$t"); done
  ((${#m[@]}==0)) || die "Missing tools: ${m[*]}"
}

wait_for_db() {
  log "Waiting for MySQL ${MYSQL_HOST}:${MYSQL_PORT}..."
  until nc -z "$MYSQL_HOST" "$MYSQL_PORT"; do sleep 3; done
  log "MySQL is reachable"
}

mysql_query_scalar() {
  mysql --batch --skip-column-names --protocol=TCP \
    -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" -e "$1"
}
db_is_empty() {
  local cnt; cnt="$(mysql_query_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MYSQL_DATABASE}';" | tr -d '\r' || echo 0)"
  [[ "${cnt:-0}" -eq 0 ]]
}

################################################################
# Payload (DB) — pack/import
################################################################
pack_payload() {  # -> "size sha"
  rm -f "$DUMP_PATH" "$ARCHIVE_PATH"
  log "Dumping DB '${MYSQL_DATABASE}' -> $ARCHIVE_PATH" >&2
  mysqldump --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
    --single-transaction --quick --routines --events --triggers --hex-blob --no-tablespaces \
    --databases "$MYSQL_DATABASE" > "$DUMP_PATH"
  zstd -q -T0 -19 -o "$ARCHIVE_PATH" "$DUMP_PATH"
  local size sha; size="$(stat -c '%s' "$ARCHIVE_PATH")"; sha="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  printf '%s %s\n' "$size" "$sha"
}
import_payload() {  # $1=archive -> mysql < dump
  log "Importing DB from '$1'"
  zstd -dc "$1" | mysql --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}"
}

################################################################
# Chunk helpers (common)
################################################################
split_archive_into_remote() { local bs=$((SYNC_CHUNK_SIZE_MB * 1000000)); mkdir -p "$REMOTE_DIR"; rm -f "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"* "${REMOTE_DIR}/${MANIFEST_NAME}" || true; log "Splitting DB archive to ${REMOTE_DIR} by ${SYNC_CHUNK_SIZE_MB}MB"; split -b "$bs" -d -a 3 "$ARCHIVE_PATH" "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"; }
assemble_remote_archive() { local dest="$1"; rm -f "$dest"; local parts=( "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"* ); ((${#parts[@]} > 0)) || die "Remote DB parts not found"; cat "${parts[@]}" > "$dest"; }
write_manifest() {
  local ts="$1" size="$2" sha="$3"; local parts=( "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"* ); local cnt="${#parts[@]}"
  jq -n \
    --arg host_id "${SYNC_HOST_ID}" --arg timestamp_utc "$ts" \
    --arg chunk_size_mb "${SYNC_CHUNK_SIZE_MB:-0}" \
    --arg archive_size_bytes "${size:-0}" \
    --arg archive_sha256 "$sha" \
    --arg chunk_count "${cnt:-0}" '
    {host_id:$host_id,timestamp_utc:$timestamp_utc,
     chunk_size_mb:(try($chunk_size_mb|tonumber)catch 0),
     chunk_count:(try($chunk_count|tonumber)catch 0),
     archive_size_bytes:(try($archive_size_bytes|tonumber)catch 0),
     archive_sha256:$archive_sha256}' > "${REMOTE_DIR}/${MANIFEST_NAME}"
  log "Wrote manifest ${REMOTE_DIR}/${MANIFEST_NAME} (chunks=${cnt} sha=${sha} size=${size})"
}
read_remote_manifest() { [[ -f "${REMOTE_DIR}/${MANIFEST_NAME}" ]] && cat "${REMOTE_DIR}/${MANIFEST_NAME}" || echo ""; }
restore_from_remote() {
  local tmp sha_remote sha_local; tmp="${INSTALL_PATH}/_dbrestore"
  rm -rf "$tmp"; mkdir -p "$tmp"
  assemble_remote_archive "$tmp/${ARCHIVE_NAME}"
  sha_remote="$(jq -r '.archive_sha256' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  sha_local="$(sha256sum "${tmp}/${ARCHIVE_NAME}" | awk '{print $1}')"
  [[ "$sha_remote" == "$sha_local" ]] || die "DB checksum mismatch: remote=$sha_remote local=$sha_local"
  # try to recreate database (best-effort)
  if ! mysql --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
       -e "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;"; then
    log "WARN: DROP/CREATE DATABASE failed (insufficient privileges?) — importing over existing schema"
  fi
  import_payload "$tmp/${ARCHIVE_NAME}"; rm -rf "$tmp"; SKIP_SCHEMA_RECREATE=1; log "DB restore completed (sha=$sha_remote)"
}

################################################################
# Commits mode (Git)
################################################################
ensure_tools_commits() { local m=(); for t in git ssh-keyscan zstd jq tar sha256sum split mysql mysqldump nc openssl; do command -v "$t" >/dev/null 2>&1 || m+=("$t"); done; ((${#m[@]}==0)) || die "Missing tools: ${m[*]}"; }
GH_MODE=""
gh_git_mode_detect() { [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for commits mode"; if [[ "$GH_REMOTE" =~ ^https:// ]]; then [[ -n "$SYNC_AUTH_TOKEN" ]] && GH_MODE="SYNC" || GH_MODE="HTTPS_PULLONLY"; elif [[ "$GH_REMOTE" =~ ^git@ || "$GH_REMOTE" =~ ^ssh:// ]]; then [[ -n "$GH_SSH_PRIVATE_KEY" ]] || die "SSH remote requires GH_SSH_PRIVATE_KEY"; GH_MODE="SYNC"; else die "Unsupported GH_REMOTE scheme"; fi; log "Commits mode: ${GH_MODE}"; }
gh_git_setup() {
  mkdir -p "$WORK_DIR"

  # Если рабочая папка существует, но НЕ git-репозиторий — подчистим.
  if [[ -d "$WORK_DIR" && ! -d "$WORK_DIR/.git" ]]; then
    # Подчищаем ТОЛЬКО наши рабочие каталоги внутри INSTALL_PATH.
    case "$WORK_DIR" in
      "$INSTALL_PATH"/_gitmirror*|"$INSTALL_PATH"/_dbgit*)
        log "Workdir exists but is not a git repo -> cleaning: $WORK_DIR"
        rm -rf "$WORK_DIR"
        ;;
      *)
        die "Workdir exists and is not a git repo (won't remove): $WORK_DIR"
        ;;
    esac
    mkdir -p "$WORK_DIR"
  fi

  local url="$GH_REMOTE"
  if [[ "$GH_MODE" == "SYNC" && "$GH_REMOTE" =~ ^https:// && -n "$SYNC_AUTH_TOKEN" ]]; then
    url="https://x-access-token:${SYNC_AUTH_TOKEN}@${GH_REMOTE#https://}"
  fi

  # SSH подготовка
  if [[ "$GH_REMOTE" =~ ^git@ || "$GH_REMOTE" =~ ^ssh:// ]]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    local key="/root/.ssh/id_ed25519"
    if [[ -n "${GH_SSH_PRIVATE_KEY:-}" ]]; then
      grep -q "BEGIN OPENSSH PRIVATE KEY" <<<"$GH_SSH_PRIVATE_KEY" || key="/root/.ssh/id_rsa"
      printf '%s\n' "$GH_SSH_PRIVATE_KEY" > "$key"; chmod 600 "$key"
    fi
    if [[ -n "${GH_KNOWN_HOSTS:-}" ]]; then
      printf '%s\n' "$GH_KNOWN_HOSTS" > /root/.ssh/known_hosts; chmod 644 /root/.ssh/known_hosts
      export GIT_SSH_COMMAND="ssh -i ${key} -o UserKnownHostsFile=/root/.ssh/known_hosts -o StrictHostKeyChecking=yes"
    else
      export GIT_SSH_COMMAND="ssh -i ${key} -o StrictHostKeyChecking=no"
    fi
  fi

  if [[ ! -d "$WORK_DIR/.git" ]]; then
    log "Cloning repo (branch: ${GH_BRANCH}) into ${WORK_DIR}"
    if ! git clone --depth=1 --branch "$GH_BRANCH" "$url" "$WORK_DIR" 2>/dev/null; then
      git clone --depth=1 "$url" "$WORK_DIR"
      git -C "$WORK_DIR" checkout -B "$GH_BRANCH"
    fi
  else
    if git -C "$WORK_DIR" remote | grep -q '^origin$'; then
      git -C "$WORK_DIR" remote set-url origin "$url"
    else
      git -C "$WORK_DIR" remote add origin "$url"
    fi
  fi

  git -C "$WORK_DIR" config user.name  "${GH_COMMIT_NAME:-Hex CI}"
  git -C "$WORK_DIR" config user.email "${GH_COMMIT_EMAIL:-hex@example.com}"
  mkdir -p "$REMOTE_DIR"
}

gh_git_pull_hard() {
  log "Fetching ${GH_BRANCH} (mode=${GH_MODE})"; git -C "$WORK_DIR" remote | grep -q '^origin$' || die "No 'origin' remote"
  if git -C "$WORK_DIR" ls-remote --heads origin "$GH_BRANCH" | grep -q "$GH_BRANCH"; then git -C "$WORK_DIR" fetch --depth=1 origin "$GH_BRANCH"; git -C "$WORK_DIR" checkout -B "$GH_BRANCH" "origin/${GH_BRANCH}"; git -C "$WORK_DIR" reset --hard "origin/${GH_BRANCH}"; git -C "$WORK_DIR" clean -xfd;
  else log "Remote branch '${GH_BRANCH}' not found"; git -C "$WORK_DIR" checkout --orphan "$GH_BRANCH"; git -C "$WORK_DIR" reset --hard; git -C "$WORK_DIR" clean -xfd; fi
  mkdir -p "$REMOTE_DIR"
}
perform_commits_sync() {
  ensure_tools_commits; ensure_int SYNC_CHUNK_SIZE_MB 49; wait_for_db
  gh_git_mode_detect; gh_git_setup; gh_git_pull_hard
  local man; man="$(read_remote_manifest || true)"
  if [[ "$GH_MODE" == "HTTPS_PULLONLY" ]]; then if [[ -n "$man" ]]; then log "RO: force-restore DB snapshot from repo"; restore_from_remote; else log "RO: no DB snapshot in repo -> keep local"; fi; return 0; fi
  if db_is_empty && [[ -n "$man" ]]; then log "DB empty -> restore from repo snapshot"; restore_from_remote; return 0; fi
  local size sha need_push="yes" sha_remote; read -r size sha <<<"$(pack_payload)"
  if [[ -n "$man" ]]; then sha_remote="$(echo "$man" | jq -r '.archive_sha256')"; [[ "$sha_remote" == "$sha" ]] && { log "Same as remote, skipping push"; need_push="no"; }; fi
  if [[ "$need_push" == "yes" ]]; then split_archive_into_remote; write_manifest "$(now_utc)" "$size" "$sha"; git -C "$WORK_DIR" add -A; if git -C "$WORK_DIR" diff --cached --quiet; then log "DB: nothing to commit"; return 0; fi; git -C "$WORK_DIR" commit -m "mysql-backup(${SYNC_HOST_ID}/${MYSQL_DATABASE}): size=${size} sha256=${sha}"; git -C "$WORK_DIR" push origin "$GH_BRANCH"; log "Pushed DB snapshot commit"; fi
}

################################################################
# Releases mode
################################################################
ensure_tools_releases() { local m=(); for t in curl zstd jq sha256sum split mysql mysqldump nc openssl mktemp; do command -v "$t" >/dev/null 2>&1 || m+=("$t"); done; ((${#m[@]}==0)) || die "Missing tools: ${m[*]}"; }
GH_OWNER="" GH_REPO=""
parse_gh_remote() {
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for releases mode"
  local url="$GH_REMOTE" tmp host path
  if [[ "$url" =~ ^https?:// ]]; then tmp="${url#*://}"; host="${tmp%%/*}"; path="${tmp#*/}"
  elif [[ "$url" =~ ^ssh://([^/]+)/(.+)$ ]]; then host="${BASH_REMATCH[1]}"; host="${host#*@}"; path="${BASH_REMATCH[2]}"
  elif [[ "$url" =~ ^[^@]+@([^:]+):(.*)$ ]]; then host="${BASH_REMATCH[1]}"; path="${BASH_REMATCH[2]}"
  else die "Unsupported GH_REMOTE: $GH_REMOTE"; fi
  path="${path%.git}"; GH_OWNER="${path%%/*}"; GH_REPO="${path#*/}"
  [[ -n "$GH_OWNER" && -n "$GH_REPO" && "$GH_REPO" != "$GH_OWNER" ]] || die "Cannot parse owner/repo from GH_REMOTE ($GH_REMOTE)"
  if [[ -z "$GH_API" ]];   then [[ "$host" == "github.com" ]] && GH_API="https://api.github.com"    || GH_API="https://${host}/api/v3"; fi
  if [[ -z "$GH_UPLOAD" ]]; then [[ "$host" == "github.com" ]] && GH_UPLOAD="https://uploads.github.com" || GH_UPLOAD="https://${host}/api/uploads"; fi
  log "Releases: parsed host=${host} owner=${GH_OWNER} repo=${GH_REPO}"
}
AUTH_HEADER=() HTTP_STATUS="" HTTP_BODY_FILE=""
gh_auth_header() { AUTH_HEADER=(); if [[ -n "$SYNC_AUTH_TOKEN" ]]; then AUTH_HEADER=(-H "Authorization: Bearer ${SYNC_AUTH_TOKEN}" -H "X-GitHub-Api-Version: 2022-11-28"); log "GitHub mode: read-write (token present)"; else log "GitHub mode: read-only (no token)"; fi; }
http_json() { local method="$1" url="$2" data="${3:-}" ctype="${4:-application/json}"; local tmp; tmp="$(mktemp)"; local code; if [[ -n "$data" ]]; then code="$(curl -sS -w '%{http_code}' "${AUTH_HEADER[@]}" -H "Accept: application/vnd.github+json" -H "Content-Type: ${ctype}" -X "$method" --data "$data" "$url" -o "$tmp" || true)"; else code="$(curl -sS -w '%{http_code}' "${AUTH_HEADER[@]}" -H "Accept: application/vnd.github+json" -X "$method" "$url" -o "$tmp" || true)"; fi; HTTP_STATUS="$code"; HTTP_BODY_FILE="$tmp"; }
gh_get_release_id_by_tag() { local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${GH_RELEASE_TAG}"; http_json "GET" "$url"; case "$HTTP_STATUS" in 200) jq -r '.id // empty' <"$HTTP_BODY_FILE";; 404) echo "";; *) die "GET $url failed (HTTP $HTTP_STATUS)";; esac; }
gh_create_release() { [[ -n "$SYNC_AUTH_TOKEN" ]] || die "SYNC_AUTH_TOKEN is required to create release ${GH_RELEASE_TAG}"; local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases"; local body; body=$(jq -n --arg tag "$GH_RELEASE_TAG" --arg name "$GH_RELEASE_NAME" '{tag_name:$tag,name:$name,prerelease:true,draft:false}'); http_json "POST" "$url" "$body"; [[ "$HTTP_STATUS" == "201" ]] || die "POST $url failed (HTTP $HTTP_STATUS)"; jq -r '.id' <"$HTTP_BODY_FILE"; }
GH_REL_ID=""
gh_ensure_release() { local id; id="$(gh_get_release_id_by_tag)"; if [[ -z "$id" ]]; then if [[ -n "$SYNC_AUTH_TOKEN" ]]; then log "Release '${GH_RELEASE_TAG}' not found -> creating"; id="$(gh_create_release)"; else log "Release not found and no token -> RO skip"; GH_REL_ID=""; return 0; fi; fi; GH_REL_ID="$id"; log "Using release id=$GH_REL_ID tag=${GH_RELEASE_TAG}"; }
gh_list_assets() { local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?per_page=100"; http_json "GET" "$url"; [[ "$HTTP_STATUS" == "200" ]] || die "GET $url failed (HTTP $HTTP_STATUS)"; cat "$HTTP_BODY_FILE"; }
gh_delete_asset_id() { local id="$1"; local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"; http_json "DELETE" "$url"; [[ "$HTTP_STATUS" =~ ^20[04]$ ]] || die "DELETE asset $id failed (HTTP $HTTP_STATUS)"; log "Deleted asset id=$id"; }
gh_delete_assets_by_prefix() { local prefix="$1"; local assets ids; assets="$(gh_list_assets)"; ids="$(jq -r --arg p "$prefix" '.[] | select(.name | startswith($p)) | .id' <<<"$assets")"; if [[ -z "$ids" ]]; then log "No assets to delete with prefix '$prefix'"; return 0; fi; while read -r id; do [[ -n "$id" ]] && gh_delete_asset_id "$id"; done <<< "$ids"; }
gh_upload_asset() { local file="$1" name; name="$(basename "$file")"; local url="${GH_UPLOAD}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?name=${name}"; local code; code="$(curl -sS -w '%{http_code}' "${AUTH_HEADER[@]}" -H "Content-Type: application/octet-stream" --data-binary @"$file" "$url" -o /dev/null || true)"; [[ "$code" =~ ^2[0-9][0-9]$ ]] || die "UPLOAD ${name} failed (HTTP ${code})"; log "Uploaded asset ${name}"; }
gh_download_asset_to() { local name="$1" out="$2"; [[ -n "$GH_REL_ID" ]] || return 1; local assets id; assets="$(gh_list_assets || true)"; id="$(jq -r --arg n "$name" '.[] | select(.name==$n) | .id' <<<"$assets" || true)"; [[ -n "$id" && "$id" != "null" ]] || return 1; local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"; local code; code="$(curl -L -sS -w '%{http_code}' "${AUTH_HEADER[@]}" -H "Accept: application/octet-stream" -o "$out" "$url" || true)"; [[ "$code" =~ ^2[0-9][0-9]$ ]] || die "DOWNLOAD ${name} failed (HTTP ${code})"; log "Downloaded asset ${name} -> ${out}"; }

perform_releases_sync() {
  ensure_tools_releases; ensure_int SYNC_CHUNK_SIZE_MB 49; wait_for_db
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for releases mode"
  parse_gh_remote; gh_auth_header; gh_ensure_release
  [[ -n "$GH_REL_ID" ]] || { log "No release id (RO without release) -> skip"; return 0; }

  local tmp="${INSTALL_PATH}/_ghrel"; rm -rf "$tmp"; mkdir -p "$tmp"
  if gh_download_asset_to "${MANIFEST_NAME}" "${tmp}/${MANIFEST_NAME}"; then
    local man sha_remote; man="$(cat "${tmp}/${MANIFEST_NAME}")"; sha_remote="$(jq -r '.archive_sha256' <<<"$man")"
    if [[ -n "$SYNC_AUTH_TOKEN" ]]; then
      if db_is_empty; then
        log "DB is empty -> restoring from release '${GH_RELEASE_TAG}'"
        local cnt i part; cnt="$(jq -r '.chunk_count' <<<"$man")"; [[ -n "$cnt" && "$cnt" != "null" ]] || die "Invalid manifest (chunk_count)"
        for ((i=0;i<cnt;i++)); do part=$(printf '%s.part_%03d' "$ARCHIVE_NAME" "$i"); gh_download_asset_to "$part" "${tmp}/${part}" || die "Missing asset $part"; done
        cat "${tmp}/${ARCHIVE_NAME}.part_"* > "${tmp}/${ARCHIVE_NAME}"; local sha_local; sha_local="$(sha256sum "${tmp}/${ARCHIVE_NAME}" | awk '{print $1}')"
        [[ "$sha_local" == "$sha_remote" ]] || die "DB checksum mismatch: remote=$sha_remote local=$sha_local"
        import_payload "${tmp}/${ARCHIVE_NAME}"; SKIP_SCHEMA_RECREATE=1; log "DB restore completed"; rm -rf "$tmp"; return 0
      fi
      local size sha; read -r size sha <<<"$(pack_payload)"
      if [[ "$sha" != "$sha_remote" ]]; then
        log "DB differs from release -> uploading new dump"
        split_archive_into_remote; gh_delete_assets_by_prefix "${ARCHIVE_NAME}.part_"; gh_delete_assets_by_prefix "${MANIFEST_NAME}"
        for f in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do gh_upload_asset "$f"; done
        write_manifest "$(now_utc)" "$size" "$sha"; gh_upload_asset "${REMOTE_DIR}/${MANIFEST_NAME}"
      else
        log "DB matches release (sha=$sha) -> nothing to upload"
      fi
      rm -rf "$tmp"; return 0
    else
      # RO: всегда форс-restore
      log "RO: force-restore DB from release '${GH_RELEASE_TAG}'"
      local cnt i part; cnt="$(jq -r '.chunk_count' <<<"$man")"; [[ -n "$cnt" && "$cnt" != "null" ]] || die "Invalid manifest (chunk_count)"
      for ((i=0;i<cnt;i++)); do part=$(printf '%s.part_%03d' "$ARCHIVE_NAME" "$i"); gh_download_asset_to "$part" "${tmp}/${part}" || die "Missing asset $part"; done
      cat "${tmp}/${ARCHIVE_NAME}.part_"* > "${tmp}/${ARCHIVE_NAME}"; local sha_local; sha_local="$(sha256sum "${tmp}/${ARCHIVE_NAME}" | awk '{print $1}')"
      [[ "$sha_local" == "$sha_remote" ]] || die "DB checksum mismatch: remote=$sha_remote local=$sha_local"
      # best-effort recreate
      if ! mysql --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" "-p${MYSQL_PASSWORD}" \
           -e "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;"; then
        log "WARN: DROP/CREATE DATABASE failed — importing over existing schema"
      fi
      import_payload "${tmp}/${ARCHIVE_NAME}"; SKIP_SCHEMA_RECREATE=1; log "RO DB restore done (sha=$sha_remote)"; rm -rf "$tmp"; return 0
    fi
  fi

  if [[ -n "$SYNC_AUTH_TOKEN" && ! db_is_empty ]]; then
    log "No manifest at release but token present -> publishing initial dump"
    local size sha; read -r size sha <<<"$(pack_payload)"
    split_archive_into_remote; gh_delete_assets_by_prefix "${ARCHIVE_NAME}.part_"; gh_delete_assets_by_prefix "${MANIFEST_NAME}"
    for f in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do gh_upload_asset "$f"; done
    write_manifest "$(now_utc)" "$size" "$sha"; gh_upload_asset "${REMOTE_DIR}/${MANIFEST_NAME}"
  else
    log "RO mode or empty DB: release has no manifest -> leaving DB as-is"
  fi
  rm -rf "$tmp"; return 0
}

################################################################
# Bootstrap & Launch
################################################################
log "Bootstrap: creating directories"; ensure_dirs; ensure_int SYNC_CHUNK_SIZE_MB 49
cd "$INSTALL_PATH" || die "Failed to cd into $INSTALL_PATH"

wait_for_db

CONFIG_FILE="${CONFIG_PATH}/lumina.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
  {
    echo "CONNSTR=\"mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD;\""
    if [[ -n "${VAULT_HOST}" && -n "${VAULT_PORT}" ]]; then echo "VAULT_HOST=\"${VAULT_HOST}:${VAULT_PORT}\""; fi
  } > "$CONFIG_FILE"
  chmod 640 "$CONFIG_FILE"
  log "Created default config $CONFIG_FILE"
fi

if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then printf '[%s] ERROR: Missing CA files\n' "$(now_utc)" >&2; sleep 5; exit 1; fi

if [[ "${SYNC_ENABLED,,}" == "true" ]]; then
  case "${SYNC_METHOD,,}" in
    commits)  perform_commits_sync ;;
    releases) perform_releases_sync ;;
    *) die "Unknown SYNC_METHOD='${SYNC_METHOD}'. Use 'commits' or 'releases'." ;;
  esac
else
  log "Sync disabled"
fi

log "Patching license"; python3 "${INSTALL_PATH}/license_patch.py" lumina || die "Patch failed"

chown root:root "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" || true
chmod 755 "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" || true

if [[ ! -f "$SCHEMA_LOCK" ]]; then
  if [[ "$SKIP_SCHEMA_RECREATE" -eq 0 ]]; then
    SCHEMA_TYPE="lumina"; [[ -n "${VAULT_HOST}" && -n "${VAULT_PORT}" ]] && SCHEMA_TYPE="vault"
    log "Recreating schema ($SCHEMA_TYPE)..."
    "${INSTALL_PATH}/lumina_server" -f "$CONFIG_FILE" --recreate-schema "$SCHEMA_TYPE"
  else
    log "Schema recreate skipped (restored from snapshot)"
  fi
  touch "$SCHEMA_LOCK"
fi

log "Generating TLS cert via local CA"
openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/lumina.key" -out "${CONFIG_PATH}/lumina.csr" -nodes -subj "/CN=${LUMINA_HOST}" >/dev/null 2>&1 || die "CSR failed"
openssl x509 -req -in "${CONFIG_PATH}/lumina.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/lumina.crt" -days 365 -sha512 -extfile <(cat <<-EOF
  [v3_req]
  keyUsage=critical, digitalSignature, keyEncipherment
  extendedKeyUsage=serverAuth
  subjectAltName=@alt_names
  [alt_names]
  DNS.1=${LUMINA_HOST}
EOF
) >/dev/null 2>&1 || die "CRT failed"
rm -f "${CONFIG_PATH}/lumina.csr"

chown_if_user lumina \
  "$CONFIG_FILE" "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" \
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
