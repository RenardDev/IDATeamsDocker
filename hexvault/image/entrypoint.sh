#!/bin/bash

set -Eeuo pipefail
shopt -s nullglob inherit_errexit
umask 077

################################################################
# Global cleanup (tmp files/dirs)
################################################################

declare -a CLEANUP_FILES=()
declare -a CLEANUP_DIRS=()

cleanup_add_file() { CLEANUP_FILES+=("$1"); }
cleanup_add_dir()  { CLEANUP_DIRS+=("$1"); }

cleanup_remove_dir() {
  local target="$1" dir
  local -a remaining=()
  for dir in "${CLEANUP_DIRS[@]:-}"; do
    [[ "$dir" == "$target" ]] || remaining+=("$dir")
  done
  CLEANUP_DIRS=("${remaining[@]:-}")
}

cleanup_remove_file() {
  local target="$1" file
  local -a remaining=()
  for file in "${CLEANUP_FILES[@]:-}"; do
    [[ "$file" == "$target" ]] || remaining+=("$file")
  done
  CLEANUP_FILES=("${remaining[@]:-}")
}

cleanup() {
  set +e
  for f in "${CLEANUP_FILES[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] && rm -f -- "$f"
  done
  for d in "${CLEANUP_DIRS[@]:-}"; do
    [[ -n "$d" && -d "$d" ]] && rm -rf -- "$d"
  done
}
trap cleanup EXIT

################################################################
# App Configuration
################################################################

VAULT_HOST="${VAULT_HOST:-localhost}"
VAULT_PORT="${VAULT_PORT:-65433}"
VAULT_PASSWORD="${VAULT_PASSWORD:-}"

################################################################
# Unified Sync Configuration
################################################################

SYNC_ENABLED="${SYNC_ENABLED:-false}"
SYNC_METHOD="${SYNC_METHOD:-commits}"
SYNC_AUTH_TOKEN="${SYNC_AUTH_TOKEN:-}"
SYNC_ENCRYPTION_PASSPHRASE="${SYNC_ENCRYPTION_PASSPHRASE:-}"
SYNC_FORCE_RESTORE="${SYNC_FORCE_RESTORE:-false}"
SYNC_READ_ONLY="${SYNC_READ_ONLY:-false}"

SYNC_HOST_ID="${SYNC_HOST_ID:-hexvault}"
SYNC_CHUNK_SIZE_MB="${SYNC_CHUNK_SIZE_MB:-49}"
SYNC_INTERVAL_SECONDS="${SYNC_INTERVAL_SECONDS:-3600}"
SYNC_NETWORK_TIMEOUT_SECONDS="${SYNC_NETWORK_TIMEOUT_SECONDS:-300}"
SYNC_LOCK_TIMEOUT_SECONDS="${SYNC_LOCK_TIMEOUT_SECONDS:-30}"
SYNC_FINAL_TIMEOUT_SECONDS="${SYNC_FINAL_TIMEOUT_SECONDS:-300}"
SYNC_RELEASE_KEEP="${SYNC_RELEASE_KEEP:-3}"
SYNC_MAX_RESTORE_MB="${SYNC_MAX_RESTORE_MB:-10240}"
SYNC_MAX_EXTRACT_MB="${SYNC_MAX_EXTRACT_MB:-20480}"

GH_REMOTE="${GH_REMOTE:-}"

GH_BRANCH="${GH_BRANCH:-main}"
GH_COMMIT_NAME="${GH_COMMIT_NAME:-HexVault CI}"
GH_COMMIT_EMAIL="${GH_COMMIT_EMAIL:-hexvault@example.com}"
GH_SSH_PRIVATE_KEY="${GH_SSH_PRIVATE_KEY:-}"
GH_KNOWN_HOSTS="${GH_KNOWN_HOSTS:-}"

GH_RELEASE_TAG="${GH_RELEASE_TAG:-hexvault}"
GH_RELEASE_NAME="${GH_RELEASE_NAME:-HexVault}"
GH_API="${GH_API:-}"
GH_UPLOAD="${GH_UPLOAD:-}"

# Keep secrets in the entrypoint shell only. Child processes receive them solely
# through a dedicated file descriptor or a root-only ephemeral file.
export -n VAULT_PASSWORD SYNC_AUTH_TOKEN SYNC_ENCRYPTION_PASSPHRASE \
  GH_SSH_PRIVATE_KEY GH_KNOWN_HOSTS 2>/dev/null || true

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/hexvault"
ENTRYPOINT_SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"
RECOVERY_PATH="${INSTALL_PATH}/recovery"
DB_FILE="${DATA_PATH}/hexvault.sqlite3"
SCHEMA_VERSION="940"
SCHEMA_VERSION_FILE="${RECOVERY_PATH}/hexvault_schema.version"
SNAPSHOT_SCHEMA_IDENTITY_NAME=".hexvault_schema.identity"
SCHEMA_UPGRADE_BACKUP="${RECOVERY_PATH}/.hexvault.preupgrade.sqlite3"
SCHEMA_UPGRADE_IDENTITY_BACKUP="${RECOVERY_PATH}/.hexvault.preupgrade-schema.identity"
SCHEMA_RECREATE_MARKER="${RECOVERY_PATH}/.schema-recreate-in-progress"
RESTORE_MARKER="${RECOVERY_PATH}/.restore-in-progress"
RESTORE_ROLLBACK_PREFIX="restore-txn-rollback."
TLS_ROTATION_MARKER="${RECOVERY_PATH}/.tls-rotation-in-progress"
TLS_PREVIOUS_DIR="${RECOVERY_PATH}/tls-previous"
TLS_NEW_KEY="${CONFIG_PATH}/.hexvault.tls.new.key"
TLS_NEW_CERT="${CONFIG_PATH}/.hexvault.tls.new.crt"
TLS_NEW_CSR="${CONFIG_PATH}/.hexvault.tls.new.csr"
TLS_CERT="${CONFIG_PATH}/hexvault.crt"
TLS_KEY="${CONFIG_PATH}/hexvault.key"
TLS_SERIAL="${CONFIG_PATH}/CA.srl"
KEYRING_PATH="/var/lib/hexvault/.local/share/keyrings"
SERVICE_USER="hexvault"
CA_KEY_FILE="/run/hexvault-ca-key/CA.key"
SYNC_GNUPG_HOME="/run/hexvault-sync-gnupg"

WORK_DIR="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${WORK_DIR}/backups/${SYNC_HOST_ID}"

ARCHIVE_NAME="data.tar.zst.gpg"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"
RELEASE_NAMESPACE="hexvault--${SYNC_HOST_ID}--"

PACK_SIZE=""
PACK_SHA=""
PACK_PAYLOAD_SHA=""
PACK_ENCRYPTION=""
PACK_ARCHIVE_HMAC=""
PACK_SCHEMA_VERSION=""
PACK_SCHEMA_FINGERPRINT=""

MANIFEST_ARCHIVE_NAME=""
MANIFEST_ARCHIVE_SIZE=""
MANIFEST_ARCHIVE_SHA=""
MANIFEST_PAYLOAD_SHA=""
MANIFEST_CHUNK_SIZE_MB=""
MANIFEST_CHUNK_COUNT=""
MANIFEST_ENCRYPTION=""
MANIFEST_ASSET_PREFIX=""
MANIFEST_SNAPSHOT_ID=""
MANIFEST_SCHEMA_VERSION=""
MANIFEST_SCHEMA_FINGERPRINT=""
VAULT_HOST_KIND=""
GH_API_MAX_JSON_BYTES=20971520
GH_HEADER_MAX_BYTES=1048576

################################################################
# Utils
################################################################

now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

log() { printf '[%s] %s\n' "$(now_utc)" "$*"; }

warn() { printf '[%s] WARNING: %s\n' "$(now_utc)" "$*" >&2; }

die() {
  printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2
  exit 1
}

durable_sync_path() {
  local path="$1"
  python3 - "$path" <<'PY'
import errno
import os
import stat
import sys

path = sys.argv[1]
info = os.lstat(path)
if stat.S_ISLNK(info.st_mode):
    raise SystemExit(f"refusing to fsync symlink: {path}")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
if stat.S_ISDIR(info.st_mode):
    flags |= getattr(os, "O_DIRECTORY", 0)
descriptor = os.open(path, flags)
try:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in {errno.EINVAL, errno.EROFS}:
            raise
        os.sync()
finally:
    os.close(descriptor)
PY
}

path_is_safe_regular_file() {
  [[ -f "$1" && ! -L "$1" ]]
}

path_is_safe_directory() {
  [[ -d "$1" && ! -L "$1" ]]
}

read_single_line_file() {
  local file="$1" line size
  local -a lines=()
  size="$(stat -c '%s' "$file" 2>/dev/null)" || return 1
  [[ "$size" =~ ^[1-9][0-9]{0,3}$ ]] || return 1
  ((10#$size <= 4096)) || return 1
  mapfile -t lines <"$file" || return 1
  ((${#lines[@]} == 1)) || return 1
  line="${lines[0]%$'\r'}"
  [[ "$line" != *$'\r'* ]] || return 1
  printf '%s\n' "$line"
}

ensure_runtime_directory() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    path_is_safe_directory "$path" || die "Runtime path is not a real directory: $path"
  else
    mkdir -p -- "$path"
  fi
}

validate_bool() {
  local name="$1" value="${2,,}"
  [[ "$value" == true || "$value" == false ]] \
    || die "$name must be 'true' or 'false'"
}

validate_uint_range() {
  local name="$1" value="$2" min="$3" max="$4"
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || die "$name must be an integer"
  ((${#value} <= ${#max})) || die "$name must be between $min and $max"
  ((10#$value >= min && 10#$value <= max)) \
    || die "$name must be between $min and $max"
}

validate_configuration() {
  validate_bool SYNC_ENABLED "$SYNC_ENABLED"
  validate_bool SYNC_FORCE_RESTORE "$SYNC_FORCE_RESTORE"
  validate_bool SYNC_READ_ONLY "$SYNC_READ_ONLY"
  if [[ "${SYNC_FORCE_RESTORE,,}" == true && "${SYNC_ENABLED,,}" == false ]]; then
    die "SYNC_FORCE_RESTORE=true requires SYNC_ENABLED=true"
  fi
  validate_uint_range VAULT_PORT "$VAULT_PORT" 1024 65535
  validate_uint_range SYNC_CHUNK_SIZE_MB "$SYNC_CHUNK_SIZE_MB" 1 49
  validate_uint_range SYNC_INTERVAL_SECONDS "$SYNC_INTERVAL_SECONDS" 0 2147483647
  validate_uint_range SYNC_NETWORK_TIMEOUT_SECONDS "$SYNC_NETWORK_TIMEOUT_SECONDS" 10 3600
  validate_uint_range SYNC_LOCK_TIMEOUT_SECONDS "$SYNC_LOCK_TIMEOUT_SECONDS" 1 3600
  validate_uint_range SYNC_FINAL_TIMEOUT_SECONDS "$SYNC_FINAL_TIMEOUT_SECONDS" 30 540
  validate_uint_range SYNC_RELEASE_KEEP "$SYNC_RELEASE_KEEP" 1 20
  validate_uint_range SYNC_MAX_RESTORE_MB "$SYNC_MAX_RESTORE_MB" 1 1048576
  validate_uint_range SYNC_MAX_EXTRACT_MB "$SYNC_MAX_EXTRACT_MB" 1 1048576
  if ((10#$SYNC_INTERVAL_SECONDS > 0 && 10#$SYNC_INTERVAL_SECONDS < 60)); then
    die "SYNC_INTERVAL_SECONDS must be 0 or at least 60"
  fi
  VAULT_HOST_KIND="$(python3 - "$VAULT_HOST" <<'PY'
import ipaddress
import re
import sys

host = sys.argv[1]
try:
    ipaddress.ip_address(host)
except ValueError:
    if not (1 <= len(host) <= 253) or host.endswith(".") or ".." in host:
        raise SystemExit(1)
    label = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if any(not label.fullmatch(part) for part in host.split(".")):
        raise SystemExit(1)
    print("dns")
else:
    print("ip")
PY
)" || die "VAULT_HOST must be a valid IP address or DNS name with valid labels"
  [[ "$SYNC_HOST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
    || die "SYNC_HOST_ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
  case "${SYNC_METHOD,,}" in commits|releases) ;; *) die "Invalid SYNC_METHOD" ;; esac
  [[ "$GH_BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$ && \
     "$GH_BRANCH" != *..* && "$GH_BRANCH" != *//* && "$GH_BRANCH" != */ && \
     "$GH_BRANCH" != *.lock ]] || die "GH_BRANCH is not a safe branch name"
  [[ "$GH_RELEASE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$ && \
     "$GH_RELEASE_TAG" != *..* && "$GH_RELEASE_TAG" != *//* ]] \
    || die "GH_RELEASE_TAG is not a safe release tag"
  [[ "$GH_COMMIT_NAME" != *$'\n'* && "$GH_COMMIT_NAME" != *$'\r'* && \
     "$GH_COMMIT_EMAIL" != *$'\n'* && "$GH_COMMIT_EMAIL" != *$'\r'* ]] \
    || die "Git commit identity must not contain line breaks"
  [[ "$GH_REMOTE" != *[[:space:][:cntrl:]]* && "$GH_REMOTE" != *\\* ]] \
    || die "GH_REMOTE must not contain whitespace, control characters, or backslashes"
  [[ -z "$GH_REMOTE" ]] || validate_gh_remote_syntax "$GH_REMOTE"
  [[ "$SYNC_AUTH_TOKEN" != *[[:cntrl:]]* ]] \
    || die "SYNC_AUTH_TOKEN must not contain control characters"
  [[ "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\n'* && \
     "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\r'* ]] \
    || die "SYNC_ENCRYPTION_PASSPHRASE must not contain line breaks"
  [[ "$VAULT_PASSWORD" != *$'\n'* && "$VAULT_PASSWORD" != *$'\r'* ]] \
    || die "VAULT_PASSWORD must not contain line breaks"
  if [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" && \
        ${#SYNC_ENCRYPTION_PASSPHRASE} -lt 20 ]]; then
    die "SYNC_ENCRYPTION_PASSPHRASE must contain at least 20 characters"
  fi
  if [[ "${SYNC_ENABLED,,}" == true ]]; then
    [[ -n "$GH_REMOTE" ]] \
      || die "GH_REMOTE is required when SYNC_ENABLED=true"
    [[ ${#SYNC_ENCRYPTION_PASSPHRASE} -ge 20 ]] \
      || die "SYNC_ENCRYPTION_PASSPHRASE is required for current encrypted snapshots"

    case "${SYNC_METHOD,,}" in
      releases)
        [[ "$GH_REMOTE" =~ ^https:// ]] || gh_remote_uses_ssh "$GH_REMOTE" \
          || die "Unsupported GH_REMOTE for releases mode"
        if [[ "${SYNC_READ_ONLY,,}" == false && -z "$SYNC_AUTH_TOKEN" ]]; then
          die "Releases write sync requires SYNC_AUTH_TOKEN; set SYNC_READ_ONLY=true for anonymous restore-only access"
        fi
        ;;
      commits)
        if [[ "$GH_REMOTE" =~ ^https:// ]]; then
          if [[ "${SYNC_READ_ONLY,,}" == false && -z "$SYNC_AUTH_TOKEN" ]]; then
            die "HTTPS commits write sync requires SYNC_AUTH_TOKEN; set SYNC_READ_ONLY=true for anonymous restore-only access"
          fi
        elif gh_remote_uses_ssh "$GH_REMOTE"; then
          [[ -n "$GH_SSH_PRIVATE_KEY" ]] \
            || die "SSH commits sync requires GH_SSH_PRIVATE_KEY"
          [[ -n "$GH_KNOWN_HOSTS" ]] \
            || die "SSH commits sync requires pinned GH_KNOWN_HOSTS"
        else
          die "Unsupported GH_REMOTE scheme (use https://, ssh://, or git@)"
        fi
        ;;
    esac
  fi
}

ensure_secret_service_bus() {
  local machine_id_file="/etc/machine-id"
  local dbus_compat_machine_id_file="/var/lib/dbus/machine-id"
  local default_bus_address="unix:path=/run/hexvault-dbus/session-bus"
  local service_uid service_gid bus_socket=""
  local health_id health_secret health_read
  local -a bus_info=()
  local -a service_identity_env=(
    "HOME=/var/lib/hexvault"
    "USER=${SERVICE_USER}"
    "LOGNAME=${SERVICE_USER}"
    "XDG_DATA_HOME=/var/lib/hexvault/.local/share"
    "XDG_CONFIG_HOME=/var/lib/hexvault/.config"
  )

  unset DISPLAY WAYLAND_DISPLAY

  service_uid="$(id -u "$SERVICE_USER")"
  service_gid="$(id -g "$SERVICE_USER")"
  mkdir -p /var/lib/dbus /run/hexvault-dbus \
    "/run/user/${service_uid}" "$KEYRING_PATH" /var/lib/hexvault/.config

  if [[ ! -s "$machine_id_file" ]]; then
    rm -f -- "$machine_id_file"
    dbus-uuidgen --ensure="$machine_id_file" \
      || die "Failed to generate D-Bus machine-id"
  fi

  [[ ! -d "$dbus_compat_machine_id_file" || -L "$dbus_compat_machine_id_file" ]] \
    || die "D-Bus compatibility machine-id path must not be a directory"
  ln -sfn "$machine_id_file" "$dbus_compat_machine_id_file"

  export DBUS_SESSION_BUS_ADDRESS="$default_bus_address"
  export XDG_RUNTIME_DIR="/run/user/${service_uid}"
  export XDG_DATA_HOME="/var/lib/hexvault/.local/share"
  export XDG_CONFIG_HOME="/var/lib/hexvault/.config"
  export HOME="/var/lib/hexvault" USER="$SERVICE_USER" LOGNAME="$SERVICE_USER"
  chown "$service_uid:$service_gid" /run/hexvault-dbus \
    "$XDG_RUNTIME_DIR" "$KEYRING_PATH" "$XDG_CONFIG_HOME"
  chmod 700 /run/hexvault-dbus "$XDG_RUNTIME_DIR" "$KEYRING_PATH" \
    "$XDG_CONFIG_HOME"

  if ! timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
       -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
       -u GH_SSH_PRIVATE_KEY \
       "${service_identity_env[@]}" \
       DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
       XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
       dbus-send --bus="$DBUS_SESSION_BUS_ADDRESS" --type=method_call \
       --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
       org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
    if [[ "$DBUS_SESSION_BUS_ADDRESS" == unix:path=/run/hexvault-dbus/* ]]; then
      bus_socket="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
      bus_socket="${bus_socket%%,*}"
      rm -f -- "$bus_socket"
    fi

    mapfile -t bus_info < <(
      timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
        -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
        -u GH_SSH_PRIVATE_KEY \
        "${service_identity_env[@]}" \
        DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
        dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" \
          --fork --print-address=1 --print-pid=1
    )

    ((${#bus_info[@]} >= 2)) \
      || die "Failed to start the D-Bus session bus"

    export DBUS_SESSION_BUS_ADDRESS="${bus_info[0]}"
    if [[ -n "$bus_socket" && -S "$bus_socket" ]]; then
      chown "$service_uid:$service_gid" "$bus_socket"
      chmod 600 "$bus_socket"
    fi
    log "Started D-Bus session bus (pid=${bus_info[1]})"
  fi

  printf '\n' | timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    gnome-keyring-daemon --unlock >/dev/null \
    || die "Failed to create/unlock the headless Secret Service keyring"

  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    gnome-keyring-daemon --start --components=secrets >/dev/null \
    || die "Failed to start the Secret Service"

  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    dbus-send --bus="$DBUS_SESSION_BUS_ADDRESS" --type=method_call \
    --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets \
    org.freedesktop.DBus.Peer.Ping \
    >/dev/null 2>&1 \
    || die "Secret Service is not reachable through D-Bus"

  health_id="$(openssl rand -hex 12)"
  health_secret="$(openssl rand -hex 24)"
  printf '%s' "$health_secret" | timeout --kill-after=5s 20s \
    runuser -u "$SERVICE_USER" -- env \
    -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    secret-tool store --label='HexVault secret-storage health check' \
      service hexvault-health check "$health_id" >/dev/null \
    || die "Secret Service is reachable but not writable/unlocked"
  if ! health_read="$(timeout --kill-after=5s 20s \
      runuser -u "$SERVICE_USER" -- env \
      -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
      -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
      DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
      XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
      secret-tool lookup service hexvault-health check "$health_id")"; then
    die "Secret Service lookup health check failed"
  fi
  [[ "$health_read" == "$health_secret" ]] \
    || die "Secret Service write/read health check failed"
  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    secret-tool clear service hexvault-health check "$health_id" >/dev/null \
    || warn "Could not remove Secret Service health-check item"
  log "Secret Service is writable as ${SERVICE_USER}"
}

################################################################
# Payload - pack/import
################################################################

data_has_meaningful_content() {
  local row total found
  if [[ -L "$DB_FILE" ]]; then
    return 0
  elif [[ -s "$DB_FILE" ]]; then
    if row="$(sqlite3 -readonly -separator ' ' "$DB_FILE" \
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';" \
        2>/dev/null)" && [[ "$row" =~ ^[0-9]+$ ]]; then
      total="$row"
      ((10#$total == 0)) || return 0
    else
      # Unknown/corrupt local state is meaningful: never overwrite it by an
      # automatic restore. Full validation later reports the real problem.
      return 0
    fi
  fi
  if [[ -d "$DATA_PATH/store" && ! -L "$DATA_PATH/store" ]]; then
    found="$(find "$DATA_PATH/store" -mindepth 1 ! -name '.gitignore' \
      -print -quit 2>/dev/null || true)"
    [[ -z "$found" ]] || return 0
  elif [[ -e "$DATA_PATH/store" || -L "$DATA_PATH/store" ]]; then
    return 0
  fi
  found="$(find "$DATA_PATH" -mindepth 1 -maxdepth 1 \
    ! -name '.gitignore' ! -name "$(basename "$DB_FILE")" ! -name store \
    -print -quit 2>/dev/null || true)"
  [[ -n "$found" ]]
}

validate_data_namespace() {
  local root="$1" mode="$2" entry name unsafe
  path_is_safe_directory "$root" || die "Unsafe HexVault data root"
  [[ "$mode" == live || "$mode" == snapshot ]] \
    || die "Invalid data-namespace validation mode"
  while IFS= read -r -d '' entry; do
    name="$(basename "$entry")"
    case "$name" in
      .gitignore)
        path_is_safe_regular_file "$entry" \
          || die "Unsafe .gitignore entry in HexVault data" ;;
      hexvault.sqlite3)
        path_is_safe_regular_file "$entry" \
          || die "Unsafe SQLite entry in HexVault data" ;;
      hexvault.sqlite3-wal|hexvault.sqlite3-shm|hexvault.sqlite3-journal)
        if [[ "$mode" != live ]] || ! path_is_safe_regular_file "$entry"; then
          die "Unsafe or unexpected SQLite sidecar in HexVault data"
        fi ;;
      store)
        path_is_safe_directory "$entry" \
          || die "Unsafe object-store directory" ;;
      "$SNAPSHOT_SCHEMA_IDENTITY_NAME")
        if [[ "$mode" != snapshot ]] || ! path_is_safe_regular_file "$entry"; then
          die "Reserved schema-identity entry is invalid in HexVault data"
        fi ;;
      *) die "Unexpected HexVault data entry requires manual review: $entry" ;;
    esac
  done < <(find "$root" -mindepth 1 -maxdepth 1 -print0)
  if [[ -d "$root/store" && ! -L "$root/store" ]]; then
    unsafe="$(find "$root/store" -xdev -mindepth 1 ! -type f ! -type d -print -quit)"
    [[ -z "$unsafe" ]] || die "Unsupported object-store entry: $unsafe"
  fi
}

sqlite_schema_state() {
  local database="$1" check row total expected
  [[ ! -L "$database" ]] || return 2
  [[ -e "$database" ]] || return 1
  [[ -f "$database" ]] || return 2
  [[ -s "$database" ]] || return 1
  if ! check="$(sqlite3 -readonly -cmd '.timeout 30000' "$database" \
      'PRAGMA quick_check;' 2>/dev/null)"; then
    return 2
  fi
  [[ "$check" == ok ]] || return 2
  if ! row="$(sqlite3 -readonly -cmd '.timeout 30000' -separator ' ' "$database" \
      "SELECT count(*),coalesce(sum(CASE WHEN name='users' THEN 1 ELSE 0 END),0) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';" \
      2>/dev/null)"; then
    return 2
  fi
  read -r total expected <<<"$row"
  [[ "$total" =~ ^[0-9]+$ && "$expected" =~ ^[0-9]+$ ]] || return 2
  ((10#$total == 0)) && return 1
  ((10#$expected == 1)) || return 2
}

vault_user_exists() {
  local database="$1" username="$2"
  python3 - "$database" "$username" <<'PY'
import sqlite3
import sys

database, username = sys.argv[1:]
try:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    columns = [row[1] for row in connection.execute("PRAGMA table_info(users)")]
except sqlite3.Error:
    raise SystemExit(2)
by_name = {column.lower(): column for column in columns}
selected = next((by_name[name] for name in (
    "username", "user_name", "user", "login", "login_name", "name"
) if name in by_name), None)
if selected is None:
    raise SystemExit(2)
quoted = f'"{selected.replace(chr(34), chr(34) * 2)}"'
try:
    exists = connection.execute(
        f"SELECT 1 FROM users WHERE CAST({quoted} AS TEXT)=? LIMIT 1", (username,)
    ).fetchone()
except sqlite3.Error:
    raise SystemExit(2)
raise SystemExit(0 if exists else 1)
PY
}

read_schema_marker() {
  local marker="$1" line version fingerprint extra=""
  path_is_safe_regular_file "$marker" || return 1
  line="$(read_single_line_file "$marker")" || return 1
  read -r version fingerprint extra <<<"$line" || return 1
  [[ "$version" =~ ^[1-9][0-9]*$ && ${#version} -le 10 && \
     "$fingerprint" =~ ^[0-9a-f]{64}$ && -z "$extra" ]] || return 1
  ((10#$version <= 2147483647)) || return 1
  printf '%s %s\n' "$version" "$fingerprint"
}

schema_identity_is_root_only() {
  local metadata
  path_is_safe_regular_file "$1" || return 1
  metadata="$(stat -c '%u:%a' "$1" 2>/dev/null)" || return 1
  [[ "$metadata" == 0:600 ]]
}

schema_identity_metadata_for_database() (
  set -Eeuo pipefail
  local marker="$1" database="$2" metadata version fingerprint actual
  sqlite_schema_state "$database"
  metadata="$(read_schema_marker "$marker")" || return 1
  read -r version fingerprint <<<"$metadata"
  actual="$(schema_fingerprint_for "$database")" || return 1
  [[ "$actual" =~ ^[0-9a-f]{64}$ && "$actual" == "$fingerprint" ]] || return 1
  printf '%s %s\n' "$version" "$fingerprint"
)

validate_snapshot_schema_identity() {
  local extracted_root="$1" database marker metadata version fingerprint actual
  database="${extracted_root}/$(basename "$DB_FILE")"
  marker="${extracted_root}/${SNAPSHOT_SCHEMA_IDENTITY_NAME}"
  metadata="$(read_schema_marker "$marker")" \
    || die "Snapshot is missing valid authenticated schema identity metadata"
  read -r version fingerprint <<<"$metadata"
  [[ "$version" == "$MANIFEST_SCHEMA_VERSION" && \
     "$fingerprint" == "$MANIFEST_SCHEMA_FINGERPRINT" ]] \
    || die "Snapshot schema identity does not match its authenticated manifest"
  ((10#$version <= 10#$SCHEMA_VERSION)) \
    || die "Snapshot schema version $version is newer than image schema $SCHEMA_VERSION"
  actual="$(schema_fingerprint_for "$database")"
  [[ "$actual" == "$fingerprint" ]] \
    || die "Snapshot schema fingerprint does not match the restored SQLite schema"
}

compute_hmac_file() {
  local file="$1" context="$2"
  python3 - "$file" "$context" 3<<<"$SYNC_ENCRYPTION_PASSPHRASE" <<'PY'
import hashlib
import hmac
import os
import sys

secret = os.fdopen(3, "rb", closefd=False).read()
if secret.endswith(b"\n"):
    secret = secret[:-1]
if not secret:
    raise SystemExit("missing sync passphrase")
context = sys.argv[2].encode()
key = hashlib.pbkdf2_hmac("sha256", secret, b"hexvault-sync-v3-hmac", 600_000, 32)
digest = hmac.new(key, context + b"|", hashlib.sha256)
with open(sys.argv[1], "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}

pack_payload() {
  local stage raw archive_hmac marker_metadata marker_version marker_fingerprint
  local actual_fingerprint attempt before after before_sha after_sha unsafe_entry
  local stable=false
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Write sync requires SYNC_ENCRYPTION_PASSPHRASE"
  [[ -f "$DB_FILE" && ! -L "$DB_FILE" && -s "$DB_FILE" ]] \
    || die "Refusing to publish a missing SQLite database"
  validate_data_namespace "$DATA_PATH" live
  sqlite_schema_state "$DB_FILE" \
    || die "Refusing to publish an invalid SQLite schema"
  marker_metadata="$(read_schema_marker "$SCHEMA_VERSION_FILE")" \
    || die "Refusing to publish without valid schema identity metadata"
  read -r marker_version marker_fingerprint <<<"$marker_metadata"
  ((10#$marker_version <= 10#$SCHEMA_VERSION)) \
    || die "Refusing to publish future schema version $marker_version"
  [[ "$marker_version" == "$SCHEMA_VERSION" ]] \
    || die "Refusing to publish schema $marker_version before its image upgrade"
  actual_fingerprint="$(schema_fingerprint_for "$DB_FILE")"
  [[ "$actual_fingerprint" == "$marker_fingerprint" ]] \
    || die "Refusing to publish a database whose live schema fingerprint changed"

  stage="$(mktemp -d "${INSTALL_PATH}/_pack.XXXXXX")"
  raw="$(mktemp "${INSTALL_PATH}/_payload.XXXXXX.tar.zst")"
  cleanup_add_dir "$stage"
  cleanup_add_file "$raw"
  rm -f -- "$raw"

  # The object store is copied only while two online SQLite backups remain
  # byte-identical. A DB commit concurrent with the store copy therefore causes
  # a bounded retry instead of publishing a cross-generation snapshot.
  for ((attempt=1; attempt<=3; attempt++)); do
    find "$stage" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    before="$(mktemp "${INSTALL_PATH}/_db-before.XXXXXX.sqlite3")"
    after="$(mktemp "${INSTALL_PATH}/_db-after.XXXXXX.sqlite3")"
    cleanup_add_file "$before"; cleanup_add_file "$after"
    rm -f -- "$before" "$after"

    if ! sqlite3 -readonly -cmd '.timeout 30000' "$DB_FILE" ".backup '$before'" || \
       ! sqlite_schema_state "$before"; then
      rm -f -- "$before" "$after"
      cleanup_remove_file "$before"; cleanup_remove_file "$after"
      ((attempt < 3)) && { warn "SQLite changed during snapshot preparation; retrying"; sleep 1; continue; }
      die "Could not create the first consistent SQLite backup"
    fi

    if ! tar -C "$DATA_PATH" --exclude='./.gitignore' \
        --exclude="./$(basename "$SCHEMA_UPGRADE_BACKUP")" \
        --exclude='./.hexvault.preupgrade.*' \
        --exclude="./${SNAPSHOT_SCHEMA_IDENTITY_NAME}" \
        --exclude='./.hexvault.rollback.*.sqlite3' \
        --exclude="./$(basename "$DB_FILE")" \
        --exclude="./$(basename "$DB_FILE")-wal" \
        --exclude="./$(basename "$DB_FILE")-shm" \
        --exclude="./$(basename "$DB_FILE")-journal" \
        -cf - . | \
        tar -C "$stage" --no-same-owner --no-same-permissions -xf -; then
      rm -f -- "$before" "$after"
      cleanup_remove_file "$before"; cleanup_remove_file "$after"
      ((attempt < 3)) && { warn "Object store changed while being copied; retrying"; sleep 1; continue; }
      die "Could not obtain a stable object-store copy"
    fi

    if ! sqlite3 -readonly -cmd '.timeout 30000' "$DB_FILE" ".backup '$after'" || \
       ! sqlite_schema_state "$after"; then
      rm -f -- "$before" "$after"
      cleanup_remove_file "$before"; cleanup_remove_file "$after"
      ((attempt < 3)) && { warn "SQLite changed during snapshot finalization; retrying"; sleep 1; continue; }
      die "Could not create the second consistent SQLite backup"
    fi

    before_sha="$(sha256sum "$before" | awk '{print $1}')"
    after_sha="$(sha256sum "$after" | awk '{print $1}')"
    if [[ "$before_sha" == "$after_sha" ]]; then
      mv -f -- "$after" "$stage/$(basename "$DB_FILE")"
      cleanup_remove_file "$after"
      rm -f -- "$before"
      cleanup_remove_file "$before"
      stable=true
      break
    fi

    rm -f -- "$before" "$after"
    cleanup_remove_file "$before"; cleanup_remove_file "$after"
    ((attempt < 3)) && { warn "SQLite commit overlapped object-store copy; retrying"; sleep 1; }
  done
  [[ "$stable" == true ]] \
    || die "Could not obtain a stable HexVault snapshot after 3 attempts"

  cp -- "$SCHEMA_VERSION_FILE" "$stage/$SNAPSHOT_SCHEMA_IDENTITY_NAME" \
    || die "Could not stage root-owned schema identity metadata"
  chmod 600 "$stage/$SNAPSHOT_SCHEMA_IDENTITY_NAME"
  marker_metadata="$(read_schema_marker "$stage/$SNAPSHOT_SCHEMA_IDENTITY_NAME")" \
    || die "Staged snapshot lost schema identity metadata"
  read -r PACK_SCHEMA_VERSION PACK_SCHEMA_FINGERPRINT <<<"$marker_metadata"
  actual_fingerprint="$(schema_fingerprint_for "$stage/$(basename "$DB_FILE")")"
  [[ "$PACK_SCHEMA_VERSION" == "$SCHEMA_VERSION" && \
     "$PACK_SCHEMA_FINGERPRINT" == "$actual_fingerprint" ]] \
    || die "Staged SQLite/schema identity mismatch"

  unsafe_entry="$(find "$stage" -mindepth 1 ! -type f ! -type d -print -quit)"
  [[ -z "$unsafe_entry" ]] \
    || die "Refusing to back up unsupported filesystem entry: $unsafe_entry"

  log "Packing consistent filesystem snapshot" >&2
  if ! tar -C "$stage" --sort=name --mtime=@0 --owner=0 --group=0 \
      --numeric-owner --hard-dereference -cf - . | zstd -q -T0 -19 -o "$raw"; then
    die "Failed to create the compressed payload"
  fi
  [[ -s "$raw" ]] || die "Compressed payload is empty"
  PACK_PAYLOAD_SHA="$(sha256sum "$raw" | awk '{print $1}')"

  rm -f -- "$ARCHIVE_PATH"
  mkdir -p "$SYNC_GNUPG_HOME"; chmod 700 "$SYNC_GNUPG_HOME"
  cleanup_add_dir "$SYNC_GNUPG_HOME"
  gpg --homedir "$SYNC_GNUPG_HOME" --no-options \
    --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback \
    --passphrase-fd 3 --symmetric --cipher-algo AES256 --force-mdc \
    --s2k-digest-algo SHA512 --s2k-count 16777216 --compress-algo none \
    --output "$ARCHIVE_PATH" "$raw" 3<<<"$SYNC_ENCRYPTION_PASSPHRASE" \
    || die "Failed to encrypt the payload"
  PACK_ENCRYPTION="gpg-aes256-v1"
  PACK_SIZE="$(stat -c '%s' "$ARCHIVE_PATH")"
  ((10#$PACK_SIZE <= 10#$SYNC_MAX_RESTORE_MB * 1000000)) \
    || die "Encrypted snapshot exceeds SYNC_MAX_RESTORE_MB"
  PACK_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  archive_hmac="$(compute_hmac_file "$ARCHIVE_PATH" archive)"
  [[ "$archive_hmac" =~ ^[0-9a-f]{64}$ ]] || die "Could not authenticate archive"
  PACK_ARCHIVE_HMAC="$archive_hmac"
  cleanup_add_file "$ARCHIVE_PATH"
  rm -rf -- "$stage"
  rm -f -- "$raw"
}

validate_tar_archive() {
  local tar_file="$1"
  python3 - "$tar_file" "$SYNC_MAX_EXTRACT_MB" <<'PY'
import pathlib
import sys
import tarfile

limit = int(sys.argv[2]) * 1_000_000
total = 0
count = 0
seen = set()
with tarfile.open(sys.argv[1], "r:") as archive:
    for member in archive:
        count += 1
        if count > 1_000_000:
            raise SystemExit("archive contains too many entries")
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe archive path: {member.name!r}")
        normalized = str(path)
        if normalized in seen:
            raise SystemExit(f"duplicate archive path: {member.name!r}")
        seen.add(normalized)
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"unsupported archive entry: {member.name!r}")
        total += max(member.size, 0)
        if total > limit:
            raise SystemExit("archive expands beyond SYNC_MAX_EXTRACT_MB")
PY
}

clear_data_contents() {
  [[ "$DATA_PATH" == /opt/hexvault/data ]] \
    || die "Refusing to clear unexpected DATA_PATH"
  find "$DATA_PATH" -mindepth 1 -maxdepth 1 ! -name '.gitignore' \
    -exec rm -rf -- {} +
}

ACTIVE_RESTORE_ROLLBACK=""
RESTORE_MARKER_STATE=""

install_schema_identity_from() {
  local source="$1" metadata temporary
  metadata="$(read_schema_marker "$source")" \
    || die "Refusing to install invalid schema identity metadata"
  if [[ -e "$SCHEMA_VERSION_FILE" || -L "$SCHEMA_VERSION_FILE" ]]; then
    path_is_safe_regular_file "$SCHEMA_VERSION_FILE" \
      || die "Schema identity target is not replaceable"
  fi
  temporary="$(mktemp "${RECOVERY_PATH}/.hexvault-schema.XXXXXX.tmp")"
  cleanup_add_file "$temporary"
  printf '%s\n' "$metadata" >"$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary"
  mv -f -- "$temporary" "$SCHEMA_VERSION_FILE"
  cleanup_remove_file "$temporary"
  durable_sync_path "$RECOVERY_PATH"
}

write_restore_marker() {
  local state="$1" rollback_basename="$2" temporary
  [[ "$state" == preparing || "$state" == prepared ]] \
    || die "Invalid restore transaction state"
  [[ "$rollback_basename" =~ ^restore-txn-rollback\.[A-Za-z0-9]+$ ]] \
    || die "Invalid restore rollback basename"
  path_is_safe_directory "$RECOVERY_PATH" \
    || die "Recovery path is not a safe directory"
  temporary="$(mktemp "${RECOVERY_PATH}/.restore-in-progress.XXXXXX.tmp")"
  cleanup_add_file "$temporary"
  printf '%s %s\n' "$state" "$rollback_basename" >"$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary"
  mv -f -- "$temporary" "$RESTORE_MARKER"
  cleanup_remove_file "$temporary"
  durable_sync_path "$RECOVERY_PATH"
}

load_restore_marker() {
  local line state rollback_basename extra=""
  path_is_safe_regular_file "$RESTORE_MARKER" \
    || die "Unsafe restore transaction marker; inspect $RECOVERY_PATH manually"
  line="$(read_single_line_file "$RESTORE_MARKER")" \
    || die "Unreadable restore transaction marker"
  read -r state rollback_basename extra <<<"$line" \
    || die "Unreadable restore transaction marker"
  [[ "$state" == preparing || "$state" == prepared ]] \
    || die "Unknown restore transaction state"
  [[ "$rollback_basename" =~ ^restore-txn-rollback\.[A-Za-z0-9]+$ && -z "$extra" ]] \
    || die "Invalid restore transaction marker contents"
  ACTIVE_RESTORE_ROLLBACK="${RECOVERY_PATH}/${rollback_basename}"
  [[ "$ACTIVE_RESTORE_ROLLBACK" == "${RECOVERY_PATH}/${RESTORE_ROLLBACK_PREFIX}"* ]] \
    || die "Restore rollback escaped the recovery path"
  RESTORE_MARKER_STATE="$state"
}

remove_restore_transaction_state() {
  local rollback="$1"
  [[ "$rollback" == "${RECOVERY_PATH}/${RESTORE_ROLLBACK_PREFIX}"* ]] \
    || die "Refusing to remove unexpected restore rollback path"
  rm -f -- "$RESTORE_MARKER"
  durable_sync_path "$RECOVERY_PATH"
  rm -rf -- "$rollback"
  durable_sync_path "$RECOVERY_PATH"
  ACTIVE_RESTORE_ROLLBACK=""
}

begin_restore_transaction() {
  local rollback rollback_basename
  [[ ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]] \
    || die "A restore transaction is already active"
  rollback="$(mktemp -d "${RECOVERY_PATH}/${RESTORE_ROLLBACK_PREFIX}XXXXXX")"
  path_is_safe_directory "$rollback" || die "Could not create a safe restore rollback"
  chown root:root "$rollback"
  chmod 700 "$rollback"
  mkdir -m 700 "$rollback/data"
  rollback_basename="$(basename "$rollback")"
  ACTIVE_RESTORE_ROLLBACK="$rollback"
  write_restore_marker preparing "$rollback_basename"
  if ! cp -a -- "$DATA_PATH/." "$rollback/data/"; then
    remove_restore_transaction_state "$rollback"
    die "Could not stage current data for durable restore rollback"
  fi
  if path_is_safe_regular_file "$SCHEMA_VERSION_FILE"; then
    cp -- "$SCHEMA_VERSION_FILE" "$rollback/schema.version" \
      || die "Could not preserve canonical schema identity for rollback"
    chown root:root "$rollback/schema.version"
    chmod 600 "$rollback/schema.version"
  elif [[ ! -e "$SCHEMA_VERSION_FILE" && ! -L "$SCHEMA_VERSION_FILE" ]]; then
    : >"$rollback/schema.absent"
    chmod 600 "$rollback/schema.absent"
  else
    die "Canonical schema identity is unsafe; restore transaction preserved"
  fi
  # The complete rollback must reach durable storage before the prepared marker
  # can authorize any destructive write to the data bind mount.
  sync
  write_restore_marker prepared "$rollback_basename"
}

recover_interrupted_restore() {
  local state rollback orphan
  if [[ ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]]; then
    # A process can die between mktemp and writing the preparing marker. By
    # protocol, no data mutation is possible in that state.
    while IFS= read -r -d '' orphan; do
      [[ "$orphan" == "${RECOVERY_PATH}/${RESTORE_ROLLBACK_PREFIX}"* ]] \
        || die "Unexpected orphan restore path"
      warn "Removing pre-marker restore staging directory $orphan"
      rm -rf -- "$orphan"
    done < <(find "$RECOVERY_PATH" -mindepth 1 -maxdepth 1 -type d \
      -name "${RESTORE_ROLLBACK_PREFIX}*" -print0)
    durable_sync_path "$RECOVERY_PATH"
    return 0
  fi

  load_restore_marker
  state="$RESTORE_MARKER_STATE"
  rollback="$ACTIVE_RESTORE_ROLLBACK"
  if [[ "$state" == preparing ]]; then
    warn "Discarding an interrupted pre-mutation restore staging copy"
    remove_restore_transaction_state "$rollback"
    return 0
  fi
  path_is_safe_directory "$rollback" \
    || die "Prepared restore rollback is missing or unsafe; preserving marker"
  path_is_safe_directory "$rollback/data" \
    || die "Prepared restore data rollback is missing or unsafe; preserving marker"
  warn "Recovering original data after an interrupted restore transaction"
  if ! clear_data_contents || ! cp -a -- "$rollback/data/." "$DATA_PATH/"; then
    die "Interrupted restore recovery failed; rollback and marker were preserved"
  fi
  if path_is_safe_regular_file "$rollback/schema.version" && \
     [[ ! -e "$rollback/schema.absent" && ! -L "$rollback/schema.absent" ]]; then
    install_schema_identity_from "$rollback/schema.version"
  elif path_is_safe_regular_file "$rollback/schema.absent" && \
       [[ ! -s "$rollback/schema.absent" ]] && \
       [[ ! -e "$rollback/schema.version" && ! -L "$rollback/schema.version" ]]; then
    if [[ -e "$SCHEMA_VERSION_FILE" || -L "$SCHEMA_VERSION_FILE" ]]; then
      path_is_safe_regular_file "$SCHEMA_VERSION_FILE" \
        || die "Cannot remove unsafe canonical schema identity during rollback"
      rm -f -- "$SCHEMA_VERSION_FILE"
      durable_sync_path "$RECOVERY_PATH"
    fi
  else
    die "Restore rollback schema metadata is ambiguous; marker was preserved"
  fi
  sync
  remove_restore_transaction_state "$rollback"
  log "Interrupted restore transaction rolled back"
}

commit_restore_transaction() {
  local state rollback
  [[ -e "$RESTORE_MARKER" || -L "$RESTORE_MARKER" ]] || return 0
  load_restore_marker
  state="$RESTORE_MARKER_STATE"
  [[ "$state" == prepared ]] \
    || die "Cannot commit an unprepared restore transaction"
  rollback="$ACTIVE_RESTORE_ROLLBACK"
  path_is_safe_directory "$rollback" \
    || die "Cannot commit restore transaction without its rollback"
  remove_restore_transaction_state "$rollback"
  log "Restore transaction committed after schema compatibility validation"
}

import_payload() {
  local archive="$1"
  local compressed tar_file extracted max_compressed_bytes compressed_size
  local max_tar_bytes tar_size staged_state payload_sha
  compressed="$(mktemp "${INSTALL_PATH}/_restore.XXXXXX.tar.zst")"
  tar_file="$(mktemp "${INSTALL_PATH}/_restore.XXXXXX.tar")"
  extracted="$(mktemp -d "${INSTALL_PATH}/_restore.XXXXXX.dir")"
  cleanup_add_file "$compressed"; cleanup_add_file "$tar_file"
  cleanup_add_dir "$extracted"

  path_is_safe_regular_file "$archive" || die "Snapshot archive path is unsafe"
  [[ "$MANIFEST_ENCRYPTION" == gpg-aes256-v1 ]] \
    || die "Only the current encrypted snapshot format is supported"
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Encrypted snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
  mkdir -p "$SYNC_GNUPG_HOME"; chmod 700 "$SYNC_GNUPG_HOME"
  cleanup_add_dir "$SYNC_GNUPG_HOME"
  max_compressed_bytes=$((10#$SYNC_MAX_RESTORE_MB * 1000000))
  if ! gpg --homedir "$SYNC_GNUPG_HOME" --no-options \
      --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback \
      --passphrase-fd 3 --decrypt "$archive" \
      3<<<"$SYNC_ENCRYPTION_PASSPHRASE" | \
      head -c "$((max_compressed_bytes + 1))" >"$compressed"; then
    die "Snapshot decryption/authentication failed or exceeded the restore limit"
  fi
  compressed_size="$(stat -c '%s' "$compressed")"
  ((10#$compressed_size <= max_compressed_bytes)) \
    || die "Decrypted compressed payload exceeds SYNC_MAX_RESTORE_MB"

  payload_sha="$(sha256sum "$compressed" | awk '{print $1}')"
  [[ "$payload_sha" == "$MANIFEST_PAYLOAD_SHA" ]] \
    || die "Decrypted payload checksum mismatch"

  max_tar_bytes=$((10#$SYNC_MAX_EXTRACT_MB * 1000000 + 100000000))
  if ! zstd -q -dc -- "$compressed" | head -c "$((max_tar_bytes + 1))" >"$tar_file"; then
    die "Could not decompress snapshot within the configured size limit"
  fi
  tar_size="$(stat -c '%s' "$tar_file")"
  ((10#$tar_size <= max_tar_bytes)) || die "Snapshot decompression is too large"
  validate_tar_archive "$tar_file" || die "Snapshot archive validation failed"
  tar -C "$extracted" --no-same-owner --no-same-permissions -xf "$tar_file" \
    || die "Could not extract snapshot"

  validate_data_namespace "$extracted" snapshot
  set +e
  sqlite_schema_state "$extracted/$(basename "$DB_FILE")"
  staged_state=$?
  set -e
  [[ "$staged_state" -eq 0 ]] \
    || die "Snapshot does not contain a valid initialized SQLite schema"
  validate_snapshot_schema_identity "$extracted"
  begin_restore_transaction
  install_schema_identity_from "$extracted/$SNAPSHOT_SCHEMA_IDENTITY_NAME"
  rm -f -- "$extracted/$SNAPSHOT_SCHEMA_IDENTITY_NAME"
  chown -R "$(id -u "$SERVICE_USER"):$(id -g "$SERVICE_USER")" "$extracted"
  chmod -R u=rwX,go= "$extracted"
  if ! clear_data_contents || ! cp -a -- "$extracted/." "$DATA_PATH/"; then
    warn "Restore copy failed; invoking durable rollback"
    recover_interrupted_restore
    die "Restore failed; original data was restored"
  fi

  sync
  rm -rf -- "$extracted"
  rm -f -- "$compressed" "$tar_file"
  log "Snapshot copied inside the data bind mount; rollback retained until schema validation"
}

################################################################
# Chunking helpers
################################################################

ensure_remote_dir_safe() {
  local backups_dir="${WORK_DIR}/backups"
  [[ "$WORK_DIR" == /opt/hexvault/_gitmirror && \
     "$REMOTE_DIR" == "${WORK_DIR}/backups/${SYNC_HOST_ID}" ]] \
    || die "Refusing to use an unexpected sync staging path"
  [[ ! -L "$WORK_DIR" ]] || die "Sync work directory must not be a symlink"
  mkdir -p "$WORK_DIR"
  if [[ -e "$backups_dir" || -L "$backups_dir" ]]; then
    [[ -d "$backups_dir" && ! -L "$backups_dir" ]] \
      || die "Sync backups path is not a real directory"
  fi
  mkdir -p "$backups_dir"
  if [[ -e "$REMOTE_DIR" || -L "$REMOTE_DIR" ]]; then
    [[ -d "$REMOTE_DIR" && ! -L "$REMOTE_DIR" ]] \
      || die "Host sync path is not a real directory"
  fi
  mkdir -p "$REMOTE_DIR"
}

split_archive_into_remote() {
  local bs=$((10#$SYNC_CHUNK_SIZE_MB * 1000000)) archive_size chunk_count
  archive_size="$(stat -c '%s' "$ARCHIVE_PATH")"
  [[ "$archive_size" =~ ^[1-9][0-9]*$ && ${#archive_size} -le 16 ]] \
    || die "Encrypted snapshot size is invalid"
  chunk_count=$(((10#$archive_size + bs - 1) / bs))
  ((chunk_count >= 1 && chunk_count <= 10000)) \
    || die "Encrypted snapshot would require more than 10000 chunks"
  ensure_remote_dir_safe
  find "$REMOTE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  split -b "$bs" -d -a 5 -- "$ARCHIVE_PATH" \
    "${REMOTE_DIR}/${ARCHIVE_NAME}.part_" || die "Failed to split archive"
}

assemble_remote_archive() {
  local dest="$1" part size total=0
  local parts=( "${REMOTE_DIR}/${MANIFEST_ARCHIVE_NAME}.part_"* )
  ((${#parts[@]} == 10#$MANIFEST_CHUNK_COUNT)) \
    || die "Snapshot chunk count mismatch"
  rm -f -- "$dest"
  for part in "${parts[@]}"; do
    [[ -f "$part" && ! -L "$part" ]] || die "Invalid snapshot chunk: $part"
    size="$(stat -c '%s' "$part")"
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 ]] || die "Empty snapshot chunk: $part"
    total=$((total + size))
    ((total <= 10#$MANIFEST_ARCHIVE_SIZE)) \
      || die "Snapshot chunks exceed declared archive size"
    cat "$part" >>"$dest" || die "Failed to assemble snapshot"
  done
  ((total == 10#$MANIFEST_ARCHIVE_SIZE)) || die "Snapshot chunk sizes do not match manifest"
}

write_manifest() {
  local output="$1" timestamp="$2" size="$3" archive_sha="$4"
  local payload_sha="$5" archive_hmac="$6" encryption="$7"
  local snapshot_id="${8:-}" asset_prefix="${9:-}"
  local parts count unsigned canonical manifest_hmac
  parts=("${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*)
  count="${#parts[@]}"
  ((count > 0)) || die "No archive chunks were created"
  [[ "$PACK_SCHEMA_VERSION" == "$SCHEMA_VERSION" && \
     "$PACK_SCHEMA_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] \
    || die "Cannot write manifest without current schema identity"
  unsigned="$(mktemp)"; cleanup_add_file "$unsigned"
  jq -n \
    --argjson format_version 3 --arg service hexvault --arg host_id "$SYNC_HOST_ID" \
    --arg timestamp_utc "$timestamp" --arg archive_name "$ARCHIVE_NAME" \
    --argjson chunk_size_mb "$SYNC_CHUNK_SIZE_MB" --argjson chunk_count "$count" \
    --argjson archive_size_bytes "$size" --arg archive_sha256 "$archive_sha" \
    --arg payload_sha256 "$payload_sha" --arg archive_hmac_sha256 "$archive_hmac" \
    --argjson schema_version "$PACK_SCHEMA_VERSION" \
    --arg schema_fingerprint "$PACK_SCHEMA_FINGERPRINT" \
    --arg encryption "$encryption" --arg snapshot_id "$snapshot_id" \
    --arg asset_prefix "$asset_prefix" \
    '{format_version:$format_version,service:$service,host_id:$host_id,
      timestamp_utc:$timestamp_utc,archive_name:$archive_name,
      chunk_size_mb:$chunk_size_mb,chunk_count:$chunk_count,
      archive_size_bytes:$archive_size_bytes,archive_sha256:$archive_sha256,
      payload_sha256:$payload_sha256,archive_hmac_sha256:$archive_hmac_sha256,
      schema_version:$schema_version,schema_fingerprint:$schema_fingerprint,
      encryption:$encryption,snapshot_id:$snapshot_id,asset_prefix:$asset_prefix}' \
    >"$unsigned"
  canonical="$(jq -cS . "$unsigned")"
  manifest_hmac="$(printf '%s' "$canonical" | \
    python3 -c '
import hashlib,hmac,os,sys
secret=os.fdopen(3,"rb",closefd=False).read()
secret=secret[:-1] if secret.endswith(b"\n") else secret
key=hashlib.pbkdf2_hmac("sha256",secret,b"hexvault-sync-v3-hmac",600_000,32)
print(hmac.new(key,b"manifest|"+sys.stdin.buffer.read(),hashlib.sha256).hexdigest())' \
      3<<<"$SYNC_ENCRYPTION_PASSPHRASE")"
  jq --arg hmac "$manifest_hmac" '. + {manifest_hmac_sha256:$hmac}' \
    "$unsigned" >"$output"
}

validate_manifest() {
  local file="$1" canonical expected actual manifest_host manifest_service format_version
  local manifest_size
  path_is_safe_regular_file "$file" || die "Manifest path is missing or unsafe"
  manifest_size="$(stat -c '%s' "$file")"
  [[ "$manifest_size" =~ ^[1-9][0-9]{0,6}$ ]] && \
    ((10#$manifest_size <= 1048576)) \
    || die "Manifest exceeds the 1 MiB safety limit"
  jq -e 'type=="object" and .format_version==3 and
    .encryption=="gpg-aes256-v1" and
    (.chunk_size_mb|type=="number" and floor==.) and
    (.chunk_count|type=="number" and floor==.) and
    (.archive_size_bytes|type=="number" and floor==.) and
    (.schema_version|type=="number" and floor==.) and
    (.archive_name|type=="string") and (.archive_sha256|type=="string") and
    (.payload_sha256|type=="string") and (.archive_hmac_sha256|type=="string") and
    (.schema_fingerprint|type=="string") and
    (.manifest_hmac_sha256|type=="string") and
    (.snapshot_id|type=="string") and (.asset_prefix|type=="string")' \
    "$file" >/dev/null \
    || die "Only current encrypted authenticated manifest format v3 is supported"
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Encrypted snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
  expected="$(jq -r '.manifest_hmac_sha256' "$file")"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "Manifest authentication tag missing"
  canonical="$(jq -cS 'del(.manifest_hmac_sha256)' "$file")"
  actual="$(printf '%s' "$canonical" | \
    python3 -c '
import hashlib,hmac,os,sys
secret=os.fdopen(3,"rb",closefd=False).read()
secret=secret[:-1] if secret.endswith(b"\n") else secret
key=hashlib.pbkdf2_hmac("sha256",secret,b"hexvault-sync-v3-hmac",600_000,32)
print(hmac.new(key,b"manifest|"+sys.stdin.buffer.read(),hashlib.sha256).hexdigest())' \
      3<<<"$SYNC_ENCRYPTION_PASSPHRASE")"
  [[ "$actual" == "$expected" ]] \
    || die "Manifest authentication failed; refusing remote overwrite or fallback"

  MANIFEST_ARCHIVE_NAME="$(jq -r '.archive_name' "$file")"
  MANIFEST_ARCHIVE_SIZE="$(jq -r '.archive_size_bytes' "$file")"
  MANIFEST_ARCHIVE_SHA="$(jq -r '.archive_sha256' "$file")"
  MANIFEST_PAYLOAD_SHA="$(jq -r '.payload_sha256' "$file")"
  MANIFEST_CHUNK_SIZE_MB="$(jq -r '.chunk_size_mb' "$file")"
  MANIFEST_CHUNK_COUNT="$(jq -r '.chunk_count' "$file")"
  MANIFEST_ENCRYPTION="$(jq -r '.encryption' "$file")"
  MANIFEST_ASSET_PREFIX="$(jq -r '.asset_prefix' "$file")"
  MANIFEST_SNAPSHOT_ID="$(jq -r '.snapshot_id' "$file")"
  MANIFEST_SCHEMA_VERSION="$(jq -r '.schema_version' "$file")"
  MANIFEST_SCHEMA_FINGERPRINT="$(jq -r '.schema_fingerprint' "$file")"
  format_version="$(jq -r '.format_version' "$file")"
  manifest_host="$(jq -r '.host_id // empty' "$file")"
  manifest_service="$(jq -r '.service // empty' "$file")"
  [[ "$manifest_host" == "$SYNC_HOST_ID" ]] || die "Manifest belongs to another host"
  [[ "$manifest_service" == hexvault ]] || die "Manifest belongs to another service"
  [[ "$format_version" == 3 && "$MANIFEST_ENCRYPTION" == gpg-aes256-v1 ]] \
    || die "Unsupported snapshot format"
  [[ "$MANIFEST_ARCHIVE_NAME" == "$ARCHIVE_NAME" ]] \
    || die "Manifest archive name is not the current encrypted format"
  validate_uint_range manifest.chunk_size_mb "$MANIFEST_CHUNK_SIZE_MB" 1 49
  validate_uint_range manifest.chunk_count "$MANIFEST_CHUNK_COUNT" 1 10000
  validate_uint_range manifest.archive_size_bytes "$MANIFEST_ARCHIVE_SIZE" 1 \
    $((10#$SYNC_MAX_RESTORE_MB * 1000000))
  validate_uint_range manifest.schema_version "$MANIFEST_SCHEMA_VERSION" 1 2147483647
  ((10#$MANIFEST_SCHEMA_VERSION <= 10#$SCHEMA_VERSION)) \
    || die "Remote schema $MANIFEST_SCHEMA_VERSION is newer than image schema $SCHEMA_VERSION"
  [[ "$MANIFEST_ARCHIVE_SHA" =~ ^[0-9a-f]{64}$ && \
     "$MANIFEST_PAYLOAD_SHA" =~ ^[0-9a-f]{64}$ && \
     "$MANIFEST_SCHEMA_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] \
    || die "Manifest SHA-256 is invalid"
}

verify_archive() {
  local archive="$1" manifest="$2" size sha expected_hmac actual_hmac
  validate_manifest "$manifest"
  path_is_safe_regular_file "$archive" || die "Snapshot archive path is unsafe"
  size="$(stat -c '%s' "$archive")"
  [[ "$size" == "$MANIFEST_ARCHIVE_SIZE" ]] || die "Snapshot size mismatch"
  sha="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$sha" == "$MANIFEST_ARCHIVE_SHA" ]] || die "Snapshot checksum mismatch"
  if [[ "$MANIFEST_ENCRYPTION" == gpg-aes256-v1 ]]; then
    expected_hmac="$(jq -r '.archive_hmac_sha256 // empty' "$manifest")"
    [[ "$expected_hmac" =~ ^[0-9a-f]{64}$ ]] || die "Archive authentication tag missing"
    actual_hmac="$(compute_hmac_file "$archive" archive)"
    [[ "$actual_hmac" == "$expected_hmac" ]] || die "Archive authentication failed"
  fi
}

restore_from_remote() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" tmp archive
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "Manifest not found or unsafe: $manifest"
  validate_manifest "$manifest"
  tmp="$(mktemp -d "${INSTALL_PATH}/_restore_commit.XXXXXX")"
  cleanup_add_dir "$tmp"
  archive="$tmp/$MANIFEST_ARCHIVE_NAME"
  assemble_remote_archive "$archive"
  verify_archive "$archive" "$manifest"
  import_payload "$archive"
  rm -rf -- "$tmp"
  cleanup_remove_dir "$tmp"
}

commits_snapshot_is_valid() (
  set -Eeuo pipefail
  local manifest="$1" tmp archive
  tmp="$(mktemp -d "${INSTALL_PATH}/_verify_commit.XXXXXX")"
  trap 'rm -rf -- "$tmp"' EXIT
  validate_manifest "$manifest"
  archive="$tmp/$MANIFEST_ARCHIVE_NAME"
  assemble_remote_archive "$archive"
  verify_archive "$archive" "$manifest"
)

commits_namespace_contains_only_current_assets() {
  local manifest="$1" entry name index
  [[ -z "$MANIFEST_ASSET_PREFIX" && -z "$MANIFEST_SNAPSHOT_ID" ]] || return 1
  path_is_safe_regular_file "$manifest" || return 1
  while IFS= read -r -d '' entry; do
    path_is_safe_regular_file "$entry" || return 1
    name="$(basename "$entry")"
    [[ "$name" == "$MANIFEST_NAME" ]] && continue
    [[ "$name" =~ ^data\.tar\.zst\.gpg\.part_([0-9]{5})$ ]] || return 1
    index="${BASH_REMATCH[1]}"
    ((10#$index < 10#$MANIFEST_CHUNK_COUNT)) || return 1
  done < <(find "$REMOTE_DIR" -mindepth 1 -maxdepth 1 -print0)
}

################################################################
# Commits mode
################################################################

ensure_tools_commits() {
  local missing=() tool
  for tool in git ssh tar zstd jq sha256sum split openssl sqlite3 gpg python3 flock du sort; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || die "Missing tools: ${missing[*]}"
}

GH_MODE=""
GIT_CREDENTIAL_HELPER=""
COMMITS_REMOTE_COMMIT=""
COMMITS_ADVERTISED_OID=""
COMMITS_TREE_INDEX=""
COMMITS_TREE_HAS_SNAPSHOT=false
COMMITS_TREE_MANIFEST_OID=""
COMMITS_TREE_MANIFEST_TMP=""

gh_git_mode_detect() {
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for commits mode"

  if [[ "$GH_REMOTE" =~ ^https:// ]]; then
    if [[ "${SYNC_READ_ONLY,,}" == true || -z "$SYNC_AUTH_TOKEN" ]]; then
      GH_MODE="PULLONLY"
    else
      GH_MODE="SYNC"
    fi
  elif gh_remote_uses_ssh "$GH_REMOTE"; then
    [[ -n "$GH_SSH_PRIVATE_KEY" ]] \
      || die "SSH remote requires GH_SSH_PRIVATE_KEY"
    [[ "${SYNC_READ_ONLY,,}" == true ]] && GH_MODE="PULLONLY" || GH_MODE="SYNC"
  else
    die "Unsupported GH_REMOTE scheme (use https:// or ssh:// / git@)"
  fi

  if [[ "$GH_MODE" == SYNC && -z "$SYNC_ENCRYPTION_PASSPHRASE" ]]; then
    die "Write sync requires SYNC_ENCRYPTION_PASSPHRASE"
  fi
}

git_cmd() {
  if [[ -n "$GIT_CREDENTIAL_HELPER" ]]; then
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper \
    GIT_CONFIG_VALUE_0="!${GIT_CREDENTIAL_HELPER}" \
    GIT_TERMINAL_PROMPT=0 timeout --foreground --kill-after=15s \
      "$SYNC_NETWORK_TIMEOUT_SECONDS" git "$@"
  else
    GIT_TERMINAL_PROMPT=0 timeout --foreground --kill-after=15s \
      "$SYNC_NETWORK_TIMEOUT_SECONDS" git "$@"
  fi
}

gh_git_setup() {
  local key sync_ssh_dir git_auth_dir
  ensure_remote_dir_safe
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  export GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

  GIT_CREDENTIAL_HELPER=""
  if [[ -n "$SYNC_AUTH_TOKEN" && "$GH_REMOTE" =~ ^https:// ]]; then
    git_auth_dir="/run/hexvault-git-auth"
    rm -rf -- "$git_auth_dir"
    mkdir -m 700 "$git_auth_dir"
    cleanup_add_dir "$git_auth_dir"
    printf '%s' "$SYNC_AUTH_TOKEN" >"$git_auth_dir/token"
    chmod 600 "$git_auth_dir/token"
    GIT_CREDENTIAL_HELPER="$git_auth_dir/credential-helper"
    cat >"$GIT_CREDENTIAL_HELPER" <<'EOF'
#!/bin/sh
if [ "$1" = get ]; then
  printf 'username=x-access-token\npassword='
  cat /run/hexvault-git-auth/token
  printf '\n'
fi
EOF
    chmod 700 "$GIT_CREDENTIAL_HELPER"
  fi

  if gh_remote_uses_ssh "$GH_REMOTE"; then
    [[ -n "$GH_KNOWN_HOSTS" ]] \
      || die "SSH sync requires pinned GH_KNOWN_HOSTS"
    sync_ssh_dir="/run/hexvault-sync-ssh"
    rm -rf -- "$sync_ssh_dir"
    mkdir -m 700 "$sync_ssh_dir"
    cleanup_add_dir "$sync_ssh_dir"
    key="$sync_ssh_dir/id"
    printf '%s\n' "$GH_SSH_PRIVATE_KEY" >"$key"
    printf '%s\n' "$GH_KNOWN_HOSTS" >"$sync_ssh_dir/known_hosts"
    chmod 600 "$key" "$sync_ssh_dir/known_hosts"
    export GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o UserKnownHostsFile=$sync_ssh_dir/known_hosts -o StrictHostKeyChecking=yes"
  else
    unset GIT_SSH_COMMAND || true
  fi

}

gh_git_reinitialize_repository() {
  [[ "$INSTALL_PATH" == /opt/hexvault && \
     "$WORK_DIR" == /opt/hexvault/_gitmirror && \
     "$REMOTE_DIR" == "${WORK_DIR}/backups/${SYNC_HOST_ID}" ]] \
    || die "Refusing to recreate an unexpected commits worktree"
  [[ -d "$INSTALL_PATH" && ! -L "$INSTALL_PATH" && \
     "$(realpath -e -- "$INSTALL_PATH")" == "$INSTALL_PATH" ]] \
    || die "HexVault install path is missing, symlinked, or non-canonical"
  if [[ -e "$WORK_DIR" || -L "$WORK_DIR" ]]; then
    [[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] \
      || die "Commits worktree must be a real directory"
    rm -rf -- "$WORK_DIR"
  fi
  mkdir -m 700 -- "$WORK_DIR"
  git_cmd init --quiet --initial-branch="$GH_BRANCH" "$WORK_DIR"
  git_cmd -C "$WORK_DIR" remote add origin "$GH_REMOTE"
  git_cmd -C "$WORK_DIR" config user.name "$GH_COMMIT_NAME"
  git_cmd -C "$WORK_DIR" config user.email "$GH_COMMIT_EMAIL"
  git_cmd -C "$WORK_DIR" config protocol.version 2
  git_cmd -C "$WORK_DIR" config remote.origin.promisor true
  git_cmd -C "$WORK_DIR" config remote.origin.partialclonefilter blob:none
  git_cmd -C "$WORK_DIR" config fetch.recurseSubmodules false
  git_cmd -C "$WORK_DIR" config submodule.recurse false
  git_cmd -C "$WORK_DIR" config fetch.unpackLimit 1
  git_cmd -C "$WORK_DIR" config transfer.unpackLimit 1
  git_cmd -C "$WORK_DIR" config gc.auto 0
}

commits_remote_branch_exists() {
  local trace refs_file refs expected_ref="refs/heads/${GH_BRANCH}"
  local oid ref extra trace_size refs_size
  trace="$(mktemp /run/hexvault-git-capabilities.XXXXXX)"
  refs_file="$(mktemp /run/hexvault-git-refs.XXXXXX)"
  cleanup_add_file "$trace"
  cleanup_add_file "$refs_file"
  if ! (ulimit -f 2048 || exit 125; GIT_TRACE_PACKET="$trace" GIT_PROTOCOL=version=2 \
      git_cmd -C "$WORK_DIR" ls-remote --heads origin "$expected_ref") >"$refs_file"; then
    die "Could not query remote branch; refusing to treat a transport failure as an empty remote"
  fi
  trace_size="$(stat -c '%s' "$trace")"
  refs_size="$(stat -c '%s' "$refs_file")"
  [[ "$trace_size" =~ ^[0-9]+$ && "$refs_size" =~ ^[0-9]+$ ]] && \
    ((10#$trace_size <= 1048576 && 10#$refs_size <= 4096)) \
    || die "Remote Git capability/ref advertisement exceeded its safety bound"
  grep -Eq '< fetch=.*(^|[[:space:]])filter([[:space:]]|$)' "$trace" \
    || die "Remote Git server does not advertise protocol-v2 blob filtering; refusing an unbounded fetch"
  refs="$(<"$refs_file")"
  [[ "$refs" != *$'\n'* ]] \
    || die "Remote returned multiple records for the exact sync branch"
  COMMITS_ADVERTISED_OID=""
  [[ -n "$refs" ]] || return 1
  IFS=$'\t' read -r oid ref extra <<<"$refs"
  [[ -z "$extra" && "$ref" == "$expected_ref" && \
     ( "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ) ]] \
    || die "Remote returned an invalid exact branch record"
  COMMITS_ADVERTISED_OID="$oid"
  return 0
}

commits_tree_path_is_directory() {
  local commit="$1" path="$2" raw entry metadata actual_path mode type oid extra
  raw="$(mktemp /run/hexvault-git-tree-path.XXXXXX)"
  cleanup_add_file "$raw"
  git_cmd -C "$WORK_DIR" ls-tree -z "$commit" -- "$path" >"$raw" \
    || die "Could not inspect commits tree path '$path'"
  local -a entries=()
  mapfile -d '' -t entries <"$raw"
  ((${#entries[@]} <= 1)) || die "Commits tree contains an ambiguous path '$path'"
  ((${#entries[@]} == 1)) || return 1
  entry="${entries[0]}"
  metadata="${entry%%$'\t'*}"
  actual_path="${entry#*$'\t'}"
  read -r mode type oid extra <<<"$metadata"
  [[ -z "$extra" && "$actual_path" == "$path" && \
     "$mode" == 040000 && "$type" == tree ]] \
    || die "Commits path '$path' is not a real Git tree"
  return 0
}

commits_tree_preflight_names() {
  local commit="$1" scope="backups/${SYNC_HOST_ID}" raw entry metadata path
  local mode type oid extra name count=0 manifest_count=0 chunk_count=0
  COMMITS_TREE_HAS_SNAPSHOT=false
  COMMITS_TREE_MANIFEST_OID=""
  COMMITS_TREE_INDEX="$(mktemp /run/hexvault-git-tree-index.XXXXXX)"
  cleanup_add_file "$COMMITS_TREE_INDEX"
  : >"$COMMITS_TREE_INDEX"
  if ! commits_tree_path_is_directory "$commit" backups; then return 0; fi
  if ! commits_tree_path_is_directory "$commit" "$scope"; then return 0; fi

  raw="$(mktemp /run/hexvault-git-tree.XXXXXX)"
  cleanup_add_file "$raw"
  if ! (ulimit -f 4096 || exit 125; git_cmd -C "$WORK_DIR" ls-tree -r -z "$commit" -- "$scope") >"$raw"; then
    die "Commits namespace tree metadata exceeds its safety bound"
  fi
  while IFS= read -r -d '' entry; do
    ((count+=1)); ((count <= 10001)) \
      || die "Commits namespace contains too many entries"
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    read -r mode type oid extra <<<"$metadata"
    [[ -z "$extra" && "$type" == blob && \
       ( "$mode" == 100644 || "$mode" == 100755 ) && \
       ( "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ) ]] \
      || die "Commits namespace contains a symlink, gitlink, tree, or non-blob entry"
    [[ "$path" == "$scope/"* ]] || die "Commits tree entry escapes the target namespace"
    name="${path#"$scope/"}"
    [[ -n "$name" && "$name" != */* ]] \
      || die "Commits namespace contains a nested or empty path"
    case "$name" in
      "$MANIFEST_NAME") ((manifest_count+=1)); COMMITS_TREE_MANIFEST_OID="$oid" ;;
      data.tar.zst.gpg.part_[0-9][0-9][0-9][0-9][0-9]) ((chunk_count+=1)) ;;
      *) die "Commits namespace contains a non-current artifact: '$name'" ;;
    esac
    printf '%s\t%s\n' "$name" "$oid" >>"$COMMITS_TREE_INDEX"
  done <"$raw"
  ((manifest_count <= 1)) || die "Commits namespace contains duplicate manifests"
  ((count > 0)) || return 0
  ((manifest_count == 1)) \
    || die "Commits chunks exist without an authenticated current-v3 manifest"
  ((chunk_count >= 1 && chunk_count <= 10000)) \
    || die "Commits namespace has an invalid chunk count"
  COMMITS_TREE_HAS_SNAPSHOT=true
}

commits_fetch_manifest_bounded() {
  local output size
  [[ "$COMMITS_TREE_HAS_SNAPSHOT" == true && -n "$COMMITS_TREE_MANIFEST_OID" ]] \
    || die "Internal error: no commits manifest object was selected"
  output="$(mktemp /run/hexvault-commit-manifest.XXXXXX)"
  cleanup_add_file "$output"
  if ! (ulimit -f 4096 || exit 125; git_cmd -C "$WORK_DIR" cat-file blob \
      "$COMMITS_TREE_MANIFEST_OID") >"$output"; then
    die "Could not retrieve commits manifest within its hard size bound"
  fi
  size="$(stat -c '%s' "$output")"
  [[ "$size" =~ ^[1-9][0-9]{0,6}$ ]] && ((10#$size <= 1048576)) \
    || die "Commits manifest exceeds the 1 MiB safety limit"
  COMMITS_TREE_MANIFEST_TMP="$output"
}

commits_blob_size_bounded() {
  local oid="$1" max_bytes="$2" limit_kib size
  limit_kib=$(((10#$max_bytes + 4194304 + 1023) / 1024))
  if ! size="$( (ulimit -f "$limit_kib" || exit 125; git_cmd -C "$WORK_DIR" cat-file -s "$oid") )"; then
    return 1
  fi
  [[ "$size" =~ ^[1-9][0-9]{0,15}$ ]] || return 1
  printf '%s\n' "$size"
}

commits_fetch_declared_chunks_bounded() {
  local chunk_limit max_bytes total=0 count=0 name oid expected size
  local objects_before objects_now objects_limit
  chunk_limit=$((10#$MANIFEST_CHUNK_SIZE_MB * 1000000))
  max_bytes=$((10#$SYNC_MAX_RESTORE_MB * 1000000))
  objects_before="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
  [[ "$objects_before" =~ ^[0-9]+$ ]] || die "Could not measure Git object storage"
  objects_limit=$((10#$objects_before + 10#$MANIFEST_ARCHIVE_SIZE + 67108864))
  while IFS=$'\t' read -r name oid; do
    [[ "$name" == "$MANIFEST_NAME" ]] && continue
    printf -v expected '%s.part_%05d' "$MANIFEST_ARCHIVE_NAME" "$count"
    [[ "$name" == "$expected" ]] \
      || die "Commits tree chunks are not the exact declared current sequence"
    size="$(commits_blob_size_bounded "$oid" "$chunk_limit")" \
      || die "Chunk '$name' could not be size-checked within its hard bound"
    ((10#$size <= chunk_limit)) || die "Chunk '$name' exceeds manifest.chunk_size_mb"
    ((total += 10#$size, count += 1))
    ((total <= 10#$MANIFEST_ARCHIVE_SIZE && total <= max_bytes)) \
      || die "Commits chunks exceed the declared/allowed aggregate size"
    objects_now="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
    [[ "$objects_now" =~ ^[0-9]+$ ]] && ((10#$objects_now <= objects_limit)) \
      || die "Git object storage exceeded the bounded target-namespace allowance"
  done <"$COMMITS_TREE_INDEX"
  ((count == 10#$MANIFEST_CHUNK_COUNT)) \
    || die "Commits tree chunk count does not match the authenticated manifest"
  ((total == 10#$MANIFEST_ARCHIVE_SIZE)) \
    || die "Commits tree chunk sizes do not match the authenticated manifest"
}

commits_materialize_target_namespace() {
  local commit="${1:-}" scope="backups/${SYNC_HOST_ID}" unexpected
  local name oid output size limit_kib
  if [[ -n "$commit" ]]; then
    git_cmd -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" "$commit"
  fi
  git_cmd -C "$WORK_DIR" symbolic-ref HEAD "refs/heads/${GH_BRANCH}"
  ensure_remote_dir_safe
  if [[ "$COMMITS_TREE_HAS_SNAPSHOT" == true ]]; then
    while IFS=$'\t' read -r name oid; do
      output="${REMOTE_DIR}/${name}"
      size="$(GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" cat-file -s "$oid")"
      [[ "$size" =~ ^[1-9][0-9]{0,15}$ ]] \
        || die "Could not re-read preflighted object size for '$name'"
      limit_kib=$(((10#$size + 1048576 + 1023) / 1024))
      if ! (ulimit -f "$limit_kib" || exit 125; GIT_NO_LAZY_FETCH=1 \
          git_cmd -C "$WORK_DIR" cat-file blob "$oid") >"$output"; then
        die "Could not materialize preflighted commits object '$name'"
      fi
      [[ "$(stat -c '%s' "$output")" == "$size" ]] \
        || die "Materialized commits object size changed for '$name'"
      chmod 600 "$output"
    done <"$COMMITS_TREE_INDEX"
  fi
  unexpected="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 \
    ! -name .git ! -name backups -print -quit)"
  [[ -z "$unexpected" ]] || die "Exact commits materialization created a path outside backups/"
  unexpected="$(find "${WORK_DIR}/backups" -mindepth 1 -maxdepth 1 \
    ! -name "$SYNC_HOST_ID" -print -quit)"
  [[ -z "$unexpected" ]] || die "Exact commits materialization created another host namespace"
}

commits_empty_tree_oid() {
  GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" mktree </dev/null
}

commits_rewrite_tree_entry() (
  local parent_tree="$1" entry_name="$2" child_tree="$3"
  local raw filtered entry path result
  raw="$(mktemp /run/hexvault-parent-tree.XXXXXX)"
  filtered="$(mktemp /run/hexvault-rewritten-tree.XXXXXX)"
  trap 'rm -f -- "$raw" "$filtered"' EXIT
  if ! (ulimit -f 65536 || exit 125; GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" \
      ls-tree -z "$parent_tree") >"$raw"; then
    die "Parent Git tree exceeds the 64 MiB rewrite bound"
  fi
  if ! (
    ulimit -f 65536 || exit 125
    while IFS= read -r -d '' entry; do
      path="${entry#*$'\t'}"
      [[ "$path" == "$entry_name" ]] || printf '%s\0' "$entry"
    done <"$raw"
    printf '040000 tree %s\t%s\0' "$child_tree" "$entry_name"
  ) >"$filtered"; then
    die "Rewritten Git tree metadata exceeds its 64 MiB bound"
  fi
  result="$(GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" \
    mktree -z --missing <"$filtered")" \
    || die "Could not build scoped commits tree"
  rm -f -- "$raw" "$filtered"
  [[ "$result" =~ ^[0-9a-f]{40}$ || "$result" =~ ^[0-9a-f]{64}$ ]] \
    || die "Git returned an invalid rewritten tree object"
  printf '%s\n' "$result"
)

COMMITS_COMMIT_CREATED=false

commits_create_snapshot_commit() {
  local message="$1" target_input target_tree backups_tree root_tree
  local new_backups_tree new_root_tree old_root_tree new_commit oid name file index
  COMMITS_COMMIT_CREATED=false
  target_input="$(mktemp /run/hexvault-target-tree.XXXXXX)"
  cleanup_add_file "$target_input"
  : >"$target_input"
  file="${REMOTE_DIR}/${MANIFEST_NAME}"
  oid="$(GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" \
    hash-object -w --no-filters -- "$file")"
  [[ "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ]] \
    || die "Git returned an invalid manifest blob object"
  printf '100644 blob %s\t%s\0' "$oid" "$MANIFEST_NAME" >>"$target_input"
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    printf -v name '%s.part_%05d' "$MANIFEST_ARCHIVE_NAME" "$index"
    file="${REMOTE_DIR}/${name}"
    [[ -f "$file" && ! -L "$file" ]] || die "Refusing to publish unsafe chunk '$name'"
    oid="$(GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" \
      hash-object -w --no-filters -- "$file")"
    [[ "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid chunk blob object"
    printf '100644 blob %s\t%s\0' "$oid" "$name" >>"$target_input"
  done
  target_tree="$(GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" \
    mktree -z <"$target_input")" || die "Could not build target namespace tree"
  rm -f -- "$target_input"
  [[ "$target_tree" =~ ^[0-9a-f]{40}$ || "$target_tree" =~ ^[0-9a-f]{64}$ ]] \
    || die "Git returned an invalid target tree object"
  if [[ -n "$COMMITS_REMOTE_COMMIT" ]]; then
    root_tree="$(git_cmd -C "$WORK_DIR" rev-parse "${COMMITS_REMOTE_COMMIT}^{tree}")"
    old_root_tree="$root_tree"
    if commits_tree_path_is_directory "$COMMITS_REMOTE_COMMIT" backups; then
      backups_tree="$(git_cmd -C "$WORK_DIR" rev-parse "${COMMITS_REMOTE_COMMIT}:backups")"
    else
      backups_tree="$(commits_empty_tree_oid)"
    fi
  else
    root_tree="$(commits_empty_tree_oid)"
    old_root_tree="$root_tree"
    backups_tree="$(commits_empty_tree_oid)"
  fi
  [[ ( "$root_tree" =~ ^[0-9a-f]{40}$ || "$root_tree" =~ ^[0-9a-f]{64}$ ) && \
     ( "$backups_tree" =~ ^[0-9a-f]{40}$ || "$backups_tree" =~ ^[0-9a-f]{64}$ ) ]] \
    || die "Git returned an invalid parent tree object"
  new_backups_tree="$(commits_rewrite_tree_entry "$backups_tree" \
    "$SYNC_HOST_ID" "$target_tree")"
  new_root_tree="$(commits_rewrite_tree_entry "$root_tree" backups "$new_backups_tree")"
  [[ "$new_root_tree" != "$old_root_tree" ]] || return 0
  if [[ -n "$COMMITS_REMOTE_COMMIT" ]]; then
    new_commit="$(printf '%s\n' "$message" | GIT_NO_LAZY_FETCH=1 \
      git_cmd -C "$WORK_DIR" commit-tree "$new_root_tree" -p "$COMMITS_REMOTE_COMMIT")"
    [[ "$new_commit" =~ ^[0-9a-f]{40}$ || "$new_commit" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid commit object"
    git_cmd -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" \
      "$new_commit" "$COMMITS_REMOTE_COMMIT"
  else
    new_commit="$(printf '%s\n' "$message" | GIT_NO_LAZY_FETCH=1 \
      git_cmd -C "$WORK_DIR" commit-tree "$new_root_tree")"
    [[ "$new_commit" =~ ^[0-9a-f]{40}$ || "$new_commit" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid initial commit object"
    git_cmd -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" "$new_commit"
  fi
  COMMITS_REMOTE_COMMIT="$new_commit"
  COMMITS_COMMIT_CREATED=true
}

gh_git_pull_hard() {
  local object_bytes git_scan_status grep_scan_status
  local -a scan_statuses=()
  gh_git_reinitialize_repository
  COMMITS_REMOTE_COMMIT=""
  COMMITS_ADVERTISED_OID=""
  COMMITS_TREE_HAS_SNAPSHOT=false
  if commits_remote_branch_exists; then
    if ! (ulimit -f 65536 || exit 125; git_cmd -C "$WORK_DIR" fetch --no-tags --depth=1 \
        --filter=blob:none origin "$COMMITS_ADVERTISED_OID"); then
      die "Blobless commits fetch exceeded the 64 MiB metadata bound or failed"
    fi
    COMMITS_REMOTE_COMMIT="$(git_cmd -C "$WORK_DIR" rev-parse "FETCH_HEAD^{commit}")"
    [[ "$COMMITS_REMOTE_COMMIT" == "$COMMITS_ADVERTISED_OID" ]] \
      || die "Fetched commit does not match the exact advertised branch tip"
    git_cmd -C "$WORK_DIR" update-ref "refs/remotes/origin/${GH_BRANCH}" \
      "$COMMITS_REMOTE_COMMIT"
    object_bytes="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
    [[ "$object_bytes" =~ ^[0-9]+$ ]] && ((10#$object_bytes <= 67108864)) \
      || die "Blobless fetch exceeded the 64 MiB Git metadata allowance"
    set +e
    GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" cat-file --batch-check='%(objecttype)' \
      --batch-all-objects --unordered | grep -Fx blob >/dev/null
    scan_statuses=("${PIPESTATUS[@]}")
    set -e
    git_scan_status="${scan_statuses[0]}"
    grep_scan_status="${scan_statuses[1]}"
    [[ "$git_scan_status" -eq 0 && \
       ( "$grep_scan_status" -eq 0 || "$grep_scan_status" -eq 1 ) ]] \
      || die "Could not enumerate fetched Git object types safely"
    [[ "$grep_scan_status" -ne 0 ]] \
      || die "Remote ignored blob:none and sent branch blobs before namespace preflight"
    commits_tree_preflight_names "$COMMITS_REMOTE_COMMIT"
    if [[ "$COMMITS_TREE_HAS_SNAPSHOT" == true ]]; then
      commits_fetch_manifest_bounded
      validate_manifest "$COMMITS_TREE_MANIFEST_TMP"
      [[ -z "$MANIFEST_ASSET_PREFIX" && -z "$MANIFEST_SNAPSHOT_ID" ]] \
        || die "Commits manifest contains release-only generation metadata"
      commits_fetch_declared_chunks_bounded
    fi
    commits_materialize_target_namespace "$COMMITS_REMOTE_COMMIT"
  else
    COMMITS_TREE_INDEX="$(mktemp /run/hexvault-git-tree-index.XXXXXX)"
    cleanup_add_file "$COMMITS_TREE_INDEX"
    : >"$COMMITS_TREE_INDEX"
    commits_materialize_target_namespace
  fi
}

COMMITS_REMOTE_PRESENT=false
COMMITS_REMOTE_PAYLOAD=""
COMMITS_REMOTE_ENCRYPTION=""

commits_load_materialized_state() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" namespace_entry
  COMMITS_REMOTE_PRESENT=false
  COMMITS_REMOTE_PAYLOAD=""
  COMMITS_REMOTE_ENCRYPTION=""
  if path_is_safe_regular_file "$manifest"; then
    # Authentication/schema failures are never reclassified as replaceable
    # corruption. Only a fully authenticated current namespace may be mutated.
    validate_manifest "$manifest"
    commits_namespace_contains_only_current_assets "$manifest" \
      || die "Commits namespace contains unexpected/current-incompatible artifacts; refusing overwrite"
    if commits_snapshot_is_valid "$manifest"; then
      validate_manifest "$manifest"
      COMMITS_REMOTE_PRESENT=true
      COMMITS_REMOTE_PAYLOAD="$MANIFEST_PAYLOAD_SHA"
      COMMITS_REMOTE_ENCRYPTION="$MANIFEST_ENCRYPTION"
    elif [[ "$GH_MODE" == SYNC ]] && data_has_meaningful_content; then
      warn "Remote commits snapshot is incomplete/invalid; replacing it from valid local data"
    else
      die "Remote commits snapshot is incomplete/invalid and cannot be safely replaced"
    fi
  else
    namespace_entry="$(find "$REMOTE_DIR" -mindepth 1 -maxdepth 1 -print -quit)"
    [[ -z "$namespace_entry" ]] \
      || die "Commits namespace contains artifacts without a current authenticated manifest; refusing overwrite"
  fi
}

perform_commits_sync() {
  local phase="${1:-startup}"
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" need_push=true
  local attempt=1
  ensure_tools_commits
  gh_git_mode_detect
  gh_git_setup
  gh_git_pull_hard
  commits_load_materialized_state

  if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true && \
        "$COMMITS_REMOTE_PRESENT" != true ]]; then
    die "SYNC_FORCE_RESTORE requested, but no valid commits snapshot exists"
  fi

  if [[ "$phase" == startup && "$COMMITS_REMOTE_PRESENT" == true ]] && \
     { ! data_has_meaningful_content || [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; }; then
    log "Restoring filesystem snapshot from commits"
    restore_from_remote
  fi

  if [[ "$phase" == startup ]]; then
    [[ "$COMMITS_REMOTE_PRESENT" == true ]] && \
      log "Startup restore phase complete; publication deferred until schema validation" || \
      log "Startup restore phase found no usable remote snapshot"
    return 0
  fi

  [[ "$GH_MODE" == SYNC ]] || return 0
  if ! data_has_meaningful_content; then
    [[ "$phase" != publish ]] \
      || die "Publish-only sync refused: local HexVault data is missing"
    log "No meaningful local data to publish"
    return 0
  fi

  pack_payload
  while ((attempt <= 3)); do
    if ((attempt > 1)); then
      warn "Git push raced with another writer; bounded blobless refetch/retry $attempt of 3"
      gh_git_pull_hard
      manifest="${REMOTE_DIR}/${MANIFEST_NAME}"
      commits_load_materialized_state
    fi
    need_push=true
    if [[ "$COMMITS_REMOTE_PRESENT" == true && \
          "$COMMITS_REMOTE_PAYLOAD" == "$PACK_PAYLOAD_SHA" && \
          "$COMMITS_REMOTE_ENCRYPTION" == gpg-aes256-v1 ]]; then
      need_push=false
    fi
    [[ "$need_push" == true ]] \
      || { log "Local snapshot matches commits remote"; return 0; }
    split_archive_into_remote
    write_manifest "$manifest" "$(now_utc)" "$PACK_SIZE" "$PACK_SHA" \
      "$PACK_PAYLOAD_SHA" "$PACK_ARCHIVE_HMAC" "$PACK_ENCRYPTION"
    validate_manifest "$manifest"
    commits_namespace_contains_only_current_assets "$manifest" \
      || die "Refusing to publish an invalid current commits namespace"
    commits_create_snapshot_commit \
      "fs-backup(${SYNC_HOST_ID}): payload=${PACK_PAYLOAD_SHA}"
    if [[ "$COMMITS_COMMIT_CREATED" != true ]]; then
      log "Snapshot produced no scoped commit changes"
      return 0
    fi
    if GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" push origin \
        "HEAD:refs/heads/${GH_BRANCH}"; then
      log "Pushed filesystem snapshot commit"
      return 0
    fi
    ((attempt+=1))
  done
  die "Git push failed after 3 bounded blobless refetch/retries"
}

################################################################
# Releases mode
################################################################

ensure_tools_releases() {
  local missing=() tool
  for tool in curl tar zstd jq sha256sum split openssl sqlite3 gpg python3 flock head awk mkfifo; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || die "Missing tools: ${missing[*]}"
}

GH_OWNER=""
GH_REPO=""

urlencode() { jq -rn --arg value "$1" '$value|@uri'; }

validate_gh_remote_syntax() {
  local url="$1" tmp authority path userinfo="" owner repo
  local remote_host_port="" remote_host remote_port=""
  [[ -n "$url" && "$url" != *[[:space:][:cntrl:]]* && "$url" != *\\* ]] \
    || die "GH_REMOTE must not contain whitespace, control characters, or backslashes"

  if [[ "$url" == https://* ]]; then
    tmp="${url#https://}"
    [[ "$tmp" == */* ]] || die "HTTPS GH_REMOTE must include owner/repository"
    authority="${tmp%%/*}"
    path="${tmp#*/}"
    [[ -n "$authority" && "$authority" != *[@?#]* && "$path" != *[?#]* ]] \
      || die "HTTPS GH_REMOTE must not contain userinfo, a query, or a fragment"
    remote_host_port="$authority"
  elif [[ "$url" == ssh://* ]]; then
    tmp="${url#ssh://}"
    [[ "$tmp" == */* ]] || die "SSH GH_REMOTE must include owner/repository"
    authority="${tmp%%/*}"
    path="${tmp#*/}"
    [[ -n "$authority" && "$authority" != *[?#]* && "$path" != *[?#]* ]] \
      || die "SSH GH_REMOTE must not contain a query or a fragment"
    if [[ "$authority" == *@* ]]; then
      userinfo="${authority%@*}"
      [[ -n "$userinfo" && "$userinfo" != *:* && "${authority#*@}" != *@* ]] \
        || die "SSH GH_REMOTE userinfo must contain only a user name"
    fi
    remote_host_port="${authority##*@}"
  elif [[ "$url" =~ ^[^@/:]+@([^/:]+):(.+)$ ]]; then
    remote_host_port="${BASH_REMATCH[1]}"
    path="${BASH_REMATCH[2]}"
    [[ "$path" != *[?#]* ]] \
      || die "SCP-style GH_REMOTE must not contain a query or a fragment"
  else
    die "Unsupported GH_REMOTE scheme (use https://, ssh://, or user@host:)"
  fi

  if [[ "$remote_host_port" == *:* ]]; then
    remote_host="${remote_host_port%%:*}"
    remote_port="${remote_host_port#*:}"
    validate_uint_range GH_REMOTE.port "$remote_port" 1 65535
  else
    remote_host="$remote_host_port"
  fi
  [[ "$remote_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ && \
     "$remote_host" != *..* ]] \
    || die "GH_REMOTE host is not a safe DNS name or IPv4 address"

  path="${path%.git}"
  [[ "$path" =~ ^([^/]+)/([^/]+)$ ]] \
    || die "GH_REMOTE path must contain exactly owner/repository"
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
  [[ "$owner" =~ ^[A-Za-z0-9_.-]+$ && "$repo" =~ ^[A-Za-z0-9_.-]+$ && \
     "$owner" != . && "$owner" != .. && "$repo" != . && "$repo" != .. ]] \
    || die "GH_REMOTE owner/repository contains an unsafe path segment"
}

gh_remote_uses_ssh() {
  local url="$1"
  [[ "$url" == ssh://* || "$url" =~ ^[^@/:]+@[^/:]+: ]]
}

validate_github_endpoint() {
  local endpoint="$1" expected_host="$2" expected_port="$3" expected_path="$4"
  python3 - "$endpoint" "$expected_host" "$expected_port" "$expected_path" <<'PY'
import sys
import urllib.parse

raw, expected_host, expected_port_text, expected_path = sys.argv[1:]
if not raw or "\\" in raw or any(
    character.isspace() or ord(character) < 32 or ord(character) == 127
    for character in raw
):
    raise SystemExit(1)
parsed = urllib.parse.urlsplit(raw)
try:
    port = parsed.port
except ValueError:
    raise SystemExit(1)
expected_port = int(expected_port_text)
if not 1 <= expected_port <= 65535:
    raise SystemExit(1)
if (
    parsed.scheme.lower() != "https"
    or not parsed.netloc
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or parsed.path != expected_path
    or parsed.hostname.lower() != expected_host.lower()
    or (port if port is not None else 443) != expected_port
):
    raise SystemExit(1)
expected_authority = expected_host.lower()
if expected_port != 443:
    expected_authority += f":{expected_port}"
valid_authorities = {expected_authority}
if expected_port == 443:
    valid_authorities.add(f"{expected_authority}:443")
if parsed.netloc.lower() not in valid_authorities:
    raise SystemExit(1)
PY
}

parse_gh_remote() {
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for releases mode"
  validate_gh_remote_syntax "$GH_REMOTE"

  local url="$GH_REMOTE"
  local tmp host host_authority path transport
  local remote_port="" api_authority public_github=false api_port=443

  if [[ "$url" =~ ^https:// ]]; then
    transport=https
    tmp="${url#*://}"
    host="${tmp%%/*}"
    path="${tmp#*/}"
  elif [[ "$url" =~ ^ssh://([^/]+)/(.+)$ ]]; then
    transport=ssh
    host="${BASH_REMATCH[1]}"
    host="${host#*@}"
    path="${BASH_REMATCH[2]}"
  elif [[ "$url" =~ ^[^@]+@([^:]+):(.*)$ ]]; then
    transport=ssh
    host="${BASH_REMATCH[1]}"
    path="${BASH_REMATCH[2]}"
  else
    die "Unsupported GH_REMOTE: $GH_REMOTE"
  fi

  host_authority="$host"
  if [[ "$host_authority" == *:* ]]; then
    host="${host_authority%%:*}"
    remote_port="${host_authority#*:}"
    validate_uint_range GH_REMOTE.port "$remote_port" 1 65535
  fi
  host="${host,,}"
  [[ -n "$host" ]] || die "GH_REMOTE host is empty"
  if [[ "$host" == github.com ]]; then
    if [[ "$transport" == https && -n "$remote_port" && "$remote_port" != 443 ]]; then
      die "github.com HTTPS remotes must use the default port or explicit 443"
    fi
    public_github=true
  fi
  # An SSH transport port belongs to sshd, not to the HTTPS GitHub API.
  # Preserve an explicit port only when the remote itself uses HTTPS.
  api_authority="$host"
  if [[ "$public_github" == false && "$transport" == https && -n "$remote_port" ]]; then
    api_authority="${host}:${remote_port}"
    api_port="$remote_port"
  fi
  path="${path%.git}"
  [[ "$path" =~ ^([^/]+)/([^/]+)$ ]] \
    || die "GH_REMOTE path must contain exactly owner/repository"
  GH_OWNER="${BASH_REMATCH[1]}"
  GH_REPO="${BASH_REMATCH[2]}"
  [[ "$GH_OWNER" =~ ^[A-Za-z0-9_.-]+$ && "$GH_REPO" =~ ^[A-Za-z0-9_.-]+$ ]] \
    || die "Cannot safely parse owner/repo"
  [[ "$GH_OWNER" != . && "$GH_OWNER" != .. && \
     "$GH_REPO" != . && "$GH_REPO" != .. ]] \
    || die "Repository owner/name must not be a path segment"

  if [[ -z "$GH_API" ]]; then
    if [[ "$public_github" == true ]]; then
      GH_API="https://api.github.com"
    else
      GH_API="https://${api_authority}/api/v3"
    fi
  fi

  if [[ -z "$GH_UPLOAD" ]]; then
    if [[ "$public_github" == true ]]; then
      GH_UPLOAD="https://uploads.github.com"
    else
      GH_UPLOAD="https://${api_authority}/api/uploads"
    fi
  fi

  if [[ "$public_github" == true ]]; then
    validate_github_endpoint "$GH_API" api.github.com 443 "" \
      || die "GH_API must be exactly the HTTPS GitHub API base URL"
    validate_github_endpoint "$GH_UPLOAD" uploads.github.com 443 "" \
      || die "GH_UPLOAD must be exactly the HTTPS GitHub upload base URL"
  else
    validate_github_endpoint "$GH_API" "$host" "$api_port" /api/v3 \
      || die "GH_API must match the remote GitHub Enterprise HTTPS API base URL"
    validate_github_endpoint "$GH_UPLOAD" "$host" "$api_port" /api/uploads \
      || die "GH_UPLOAD must match the remote GitHub Enterprise HTTPS upload base URL"
  fi
}

AUTH_HEADER=()
AUTH_HEADER_FILE=""
HTTP_STATUS=""
HTTP_BODY_FILE=""
GH_ASSETS_JSON="[]"
CURL_BOUNDED_HTTP_STATUS="000"

gh_auth_header() {
  [[ -z "$AUTH_HEADER_FILE" || ! -f "$AUTH_HEADER_FILE" ]] || rm -f -- "$AUTH_HEADER_FILE"
  AUTH_HEADER_FILE="$(mktemp /run/hexvault-github-headers.XXXXXX)"
  cleanup_add_file "$AUTH_HEADER_FILE"
  chmod 600 "$AUTH_HEADER_FILE"
  printf 'X-GitHub-Api-Version: 2022-11-28\n' >"$AUTH_HEADER_FILE"
  if [[ -n "$SYNC_AUTH_TOKEN" ]]; then
    printf 'Authorization: Bearer %s\n' "$SYNC_AUTH_TOKEN" >>"$AUTH_HEADER_FILE"
  fi
  AUTH_HEADER=(-H "@${AUTH_HEADER_FILE}")
}

curl_stream_to_file_bounded() {
  local max_bytes="$1" output="$2" headers="$3"
  shift 3
  local status_file body_size header_size blocks wrapper_status
  local header_guard_dir header_pipe curl_status head_status header_status code
  local -a pipeline_status=()
  CURL_BOUNDED_HTTP_STATUS="000"
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ && ${#max_bytes} -le 16 ]] || return 2
  status_file="$(mktemp /run/hexvault-curl-status.XXXXXX)" || return 3
  cleanup_add_file "$status_file"
  header_guard_dir="$(mktemp -d /run/hexvault-curl-headers.XXXXXX)" || return 3
  cleanup_add_dir "$header_guard_dir"
  header_pipe="${header_guard_dir}/stream"
  mkfifo -m 600 "$header_pipe" || return 3
  rm -f -- "$output" "$headers"
  blocks=$(((10#$max_bytes + 1024 + 1023) / 1024))
  if ((blocks < (GH_HEADER_MAX_BYTES + 2048 + 1023) / 1024)); then
    blocks=$(((GH_HEADER_MAX_BYTES + 2048 + 1023) / 1024))
  fi

  if (
    set +e
    ulimit -f "$blocks" || exit 125
    head -c "$((GH_HEADER_MAX_BYTES + 1))" <"$header_pipe" >"$headers" &
    header_pid=$!
    # Keep one writer open so the bounded header reader cannot deadlock when
    # curl fails before opening --dump-header; curl itself must not inherit it.
    exec {header_guard_fd}>"$header_pipe" || exit 127
    curl "$@" --dump-header "$header_pipe" -o - {header_guard_fd}>&- \
      | head -c "$((10#$max_bytes + 1))" >"$output"
    pipeline_status=("${PIPESTATUS[@]}")
    exec {header_guard_fd}>&-
    wait "$header_pid"
    header_status=$?
    ((${#pipeline_status[@]} == 2)) || exit 126
    printf '%s %s %s\n' "${pipeline_status[0]}" "${pipeline_status[1]}" \
      "$header_status" >"$status_file"
  ); then wrapper_status=0; else wrapper_status=$?; fi
  rm -rf -- "$header_guard_dir"; cleanup_remove_dir "$header_guard_dir"
  [[ "$wrapper_status" -eq 0 ]] || return 3
  read -r curl_status head_status header_status <"$status_file" || return 3
  rm -f -- "$status_file"; cleanup_remove_file "$status_file"
  [[ "$curl_status" =~ ^[0-9]+$ && "$head_status" =~ ^[0-9]+$ && \
     "$header_status" =~ ^[0-9]+$ ]] || return 3
  body_size="$(stat -c '%s' "$output" 2>/dev/null)" || return 3
  header_size="$(stat -c '%s' "$headers" 2>/dev/null)" || return 3
  [[ "$body_size" =~ ^[0-9]+$ && "$header_size" =~ ^[0-9]+$ ]] || return 3
  ((10#$header_size <= GH_HEADER_MAX_BYTES)) || return 2
  code="$(awk '/^HTTP\/[0-9.]+ [0-9][0-9][0-9]([[:space:]]|$)/ {value=$2} END {print value}' \
    "$headers")" || return 3
  [[ "$code" =~ ^[0-9]{3}$ ]] || return 3
  CURL_BOUNDED_HTTP_STATUS="$code"
  ((10#$body_size <= 10#$max_bytes)) || return 2
  [[ "$curl_status" -ne 63 ]] || return 2
  [[ "$curl_status" -eq 0 && "$head_status" -eq 0 && \
     "$header_status" -eq 0 ]] || return 3
  return 0
}

http_json() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local ctype="${4:-application/json}" status body_size headers
  if [[ -n "${HTTP_BODY_FILE:-}" && -f "${HTTP_BODY_FILE:-}" ]]; then
    rm -f -- "$HTTP_BODY_FILE"
  fi
  local tmp
  tmp="$(mktemp)"; cleanup_add_file "$tmp"
  headers="$(mktemp /run/hexvault-api-headers.XXXXXX)"; cleanup_add_file "$headers"
  if [[ -n "$data" ]]; then
    if curl_stream_to_file_bounded "$GH_API_MAX_JSON_BYTES" "$tmp" "$headers" \
      -q --proto '=https' --proto-redir '=https' -sS \
      --connect-timeout 30 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$GH_API_MAX_JSON_BYTES" "${AUTH_HEADER[@]}" \
      -H 'Accept: application/vnd.github+json' -H "Content-Type: ${ctype}" \
      -X "$method" --data "$data" "$url"; then status=0; else status=$?; fi
  else
    if curl_stream_to_file_bounded "$GH_API_MAX_JSON_BYTES" "$tmp" "$headers" \
      -q --proto '=https' --proto-redir '=https' -sS \
      --connect-timeout 30 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$GH_API_MAX_JSON_BYTES" "${AUTH_HEADER[@]}" \
      -H 'Accept: application/vnd.github+json' -X "$method" \
      "$url"; then status=0; else status=$?; fi
  fi
  HTTP_STATUS="$CURL_BOUNDED_HTTP_STATUS"; HTTP_BODY_FILE="$tmp"
  rm -f -- "$headers"; cleanup_remove_file "$headers"
  [[ "$status" -eq 0 ]] || return 1
  body_size="$(stat -c '%s' "$tmp")" || return 1
  [[ "$body_size" =~ ^[0-9]+$ ]] && ((10#$body_size <= GH_API_MAX_JSON_BYTES)) \
    || { warn "GitHub API response exceeded the 20 MiB safety limit"; return 1; }
  return 0
}

gh_get_release_id_by_tag() {
  local encoded url
  encoded="$(urlencode "$GH_RELEASE_TAG")"
  url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encoded}"
  http_json GET "$url" || die "GET $url transport failed"

  case "$HTTP_STATUS" in
    200) jq -r '.id // empty' <"$HTTP_BODY_FILE" ;;
    404) echo "" ;;
    *)   die "GET $url failed (HTTP $HTTP_STATUS)" ;;
  esac
}

gh_create_release() {
  [[ -n "$SYNC_AUTH_TOKEN" ]] \
    || die "SYNC_AUTH_TOKEN is required to create release ${GH_RELEASE_TAG}"

  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases"

  local body
  body="$(jq -n \
    --arg tag  "$GH_RELEASE_TAG" \
    --arg name "$GH_RELEASE_NAME" \
    '{tag_name:$tag,name:$name,prerelease:true,draft:false}')"

  http_json "POST" "$url" "$body"

  [[ "$HTTP_STATUS" == "201" ]] \
    || die "POST $url failed (HTTP $HTTP_STATUS)"

  jq -r '.id' <"$HTTP_BODY_FILE"
}

GH_REL_ID=""

gh_ensure_release() {
  local phase="${1:-publish}" id
  id="$(gh_get_release_id_by_tag)"

  if [[ -z "$id" ]]; then
    if [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; then
      log "Release '${GH_RELEASE_TAG}' not found during forced restore"
      GH_REL_ID=""
      return 0
    elif sync_can_write && [[ "$phase" == publish ]]; then
      log "Release '${GH_RELEASE_TAG}' not found -> creating"
      id="$(gh_create_release)"
    else
      log "Release not found; creation is deferred until publish mode"
      GH_REL_ID=""
      return 0
    fi
  fi

  GH_REL_ID="$id"
  [[ "$GH_REL_ID" =~ ^[1-9][0-9]*$ ]] || die "Invalid GitHub release id"
  log "Using release id=$GH_REL_ID tag=${GH_RELEASE_TAG}"
}

gh_list_assets() {
  local page=1 count ndjson url
  ndjson="$(mktemp)"; cleanup_add_file "$ndjson"; : >"$ndjson"
  while :; do
    url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?per_page=100&page=${page}"
    if ! http_json GET "$url"; then
      warn "Could not list release assets"
      return 1
    fi
    if [[ "$HTTP_STATUS" != 200 ]]; then
      warn "Asset list failed (HTTP $HTTP_STATUS)"
      return 1
    fi
    if ! jq -e 'type=="array" and length<=100 and all(.[];
      type=="object" and (.name|type=="string") and
      (.id|type=="number" and floor==. and .>0) and
      (.size|type=="number" and floor==. and .>=0))' \
      "$HTTP_BODY_FILE" >/dev/null; then
      warn "Invalid assets response"
      return 1
    fi
    count="$(jq 'length' "$HTTP_BODY_FILE")" || return 1
    if ((page == 11)); then
      ((count == 0)) || {
        warn "Release asset listing exceeds the 1000-asset safety limit"
        return 1
      }
      break
    fi
    jq -c '.[]' "$HTTP_BODY_FILE" >>"$ndjson" || return 1
    ((count < 100)) && break
    ((page++))
    if ((page > 11)); then
      warn "Release asset listing exceeds the 1000-asset safety limit"
      return 1
    fi
  done
  jq -s '.' "$ndjson" || return 1
  rm -f -- "$ndjson" "$HTTP_BODY_FILE"
}

gh_refresh_assets() {
  local assets
  assets="$(gh_list_assets)" || die "Could not refresh release assets"
  GH_ASSETS_JSON="$assets"
}

gh_try_refresh_assets() {
  local assets
  assets="$(gh_list_assets)" || return 1
  GH_ASSETS_JSON="$assets"
}

gh_delete_asset_id() {
  local id="$1"
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || return 1
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"

  if ! http_json "DELETE" "$url"; then
    warn "DELETE asset $id transport failed"
    return 1
  fi
  if [[ ! "$HTTP_STATUS" =~ ^20[04]$ ]]; then
    warn "DELETE asset $id failed (HTTP $HTTP_STATUS)"
    return 1
  fi

  log "Deleted asset id=$id"
}

gh_upload_asset_as() {
  local file="$1" name="$2" encoded code status url body headers
  encoded="$(urlencode "$name")"
  url="${GH_UPLOAD}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?name=${encoded}"
  body="$(mktemp /run/hexvault-upload-body.XXXXXX)"; cleanup_add_file "$body"
  headers="$(mktemp /run/hexvault-upload-headers.XXXXXX)"; cleanup_add_file "$headers"
  if curl_stream_to_file_bounded "$GH_API_MAX_JSON_BYTES" "$body" "$headers" \
    -q --proto '=https' --proto-redir '=https' -sS \
    --connect-timeout 30 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
    --max-filesize "$GH_API_MAX_JSON_BYTES" "${AUTH_HEADER[@]}" \
    -H 'Content-Type: application/octet-stream' --data-binary @"$file" \
    "$url"; then status=0; else status=$?; fi
  code="$CURL_BOUNDED_HTTP_STATUS"
  rm -f -- "$body" "$headers"
  cleanup_remove_file "$body"; cleanup_remove_file "$headers"
  if [[ "$status" -ne 0 || ! "$code" =~ ^2[0-9][0-9]$ ]]; then
    warn "Upload $name failed (curl status $status, HTTP ${code:-000})"
    return 1
  fi
  log "Uploaded release asset $name"
}

validate_https_download_url() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse

raw = sys.argv[1]
if not raw or "\\" in raw or any(
    character.isspace() or ord(character) < 32 or ord(character) == 127
    for character in raw
):
    raise SystemExit(1)
parsed = urllib.parse.urlsplit(raw)
try:
    port = parsed.port
except ValueError:
    raise SystemExit(1)
if (
    parsed.scheme.lower() != "https"
    or not parsed.netloc
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.fragment
    or port == 0
):
    raise SystemExit(1)
print(raw)
PY
}

gh_download_asset_to() {
  local name="$1"
  local out="$2"

  [[ -n "$GH_REL_ID" ]] || return 3

  local id expected_size max_size count headers location download_url
  local -a locations=()
  read -r count id expected_size < <(jq -r --arg name "$name" '
    [.[]|select(.name==$name)] as $items |
    [($items|length),($items[0].id // 0),($items[0].size // 0)] | @tsv'
    <<<"$GH_ASSETS_JSON")
  [[ "$count" == 1 && "$id" =~ ^[1-9][0-9]*$ ]] || return 2
  max_size="${3:-$((10#$SYNC_MAX_RESTORE_MB * 1000000))}"
  [[ "$max_size" =~ ^[1-9][0-9]*$ ]] || return 2
  [[ "$expected_size" =~ ^[0-9]+$ ]] || return 2
  ((${#expected_size} <= ${#max_size})) || return 2
  ((10#$expected_size > 0 && 10#$expected_size <= 10#$max_size)) || return 2

  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"

  local code status
  headers="$(mktemp /run/hexvault-download-headers.XXXXXX)"
  cleanup_add_file "$headers"
  rm -f -- "$out"
  if curl_stream_to_file_bounded "$expected_size" "$out" "$headers" \
      -q --proto '=https' --proto-redir '=https' -sS \
      --connect-timeout 30 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      "${AUTH_HEADER[@]}" \
      -H "Accept: application/octet-stream" --max-filesize "$expected_size" \
      "$url"; then status=0; else status=$?; fi
  code="$CURL_BOUNDED_HTTP_STATUS"
  if [[ "$status" -ne 0 ]]; then
    rm -f -- "$out"
    rm -f -- "$headers"; cleanup_remove_file "$headers"
    [[ "$code" == 404 ]] && return 4
    [[ "$status" -eq 2 ]] && return 2
    return 3
  fi
  if [[ "$code" == 404 ]]; then
    rm -f -- "$out"
    rm -f -- "$headers"; cleanup_remove_file "$headers"
    return 4
  fi
  if [[ "$code" == 200 ]]; then
    rm -f -- "$headers"; cleanup_remove_file "$headers"
    [[ "$(stat -c '%s' "$out" 2>/dev/null || echo 0)" == "$expected_size" ]] \
      || { rm -f -- "$out"; return 2; }
    return 0
  fi
  [[ "$code" =~ ^30[12378]$ ]] || {
    rm -f -- "$out" "$headers"; cleanup_remove_file "$headers"; return 3;
  }
  while IFS= read -r location; do
    location="${location%$'\r'}"
    [[ "${location,,}" == location:* ]] || continue
    location="${location#*:}"
    location="$(sed 's/^[[:space:]]*//' <<<"$location")"
    locations+=("$location")
  done <"$headers"
  rm -f -- "$out" "$headers"
  ((${#locations[@]} == 1)) || return 3
  download_url="$(validate_https_download_url "${locations[0]}")" || return 3

  # Never forward the API Authorization header to redirected object storage.
  # Redirects from the already validated HTTPS storage URL remain anonymous.
  if curl_stream_to_file_bounded "$expected_size" "$out" "$headers" \
      -q --proto '=https' --proto-redir '=https' -L --max-redirs 5 -sS \
      --connect-timeout 30 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$expected_size" "$download_url"; then status=0; else status=$?; fi
  code="$CURL_BOUNDED_HTTP_STATUS"
  if [[ "$status" -ne 0 ]]; then
    rm -f -- "$out"
    rm -f -- "$headers"; cleanup_remove_file "$headers"
    [[ "$code" == 404 ]] && return 4
    [[ "$status" -eq 2 ]] && return 2
    return 3
  fi
  if [[ "$code" == 404 ]]; then
    rm -f -- "$out"
    rm -f -- "$headers"; cleanup_remove_file "$headers"
    return 4
  fi
  rm -f -- "$headers"; cleanup_remove_file "$headers"
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || { rm -f -- "$out"; return 3; }
  [[ "$(stat -c '%s' "$out" 2>/dev/null || echo 0)" == "$expected_size" ]] \
    || { rm -f -- "$out"; return 2; }
  return 0
}

release_asset_matches_file() (
  set -Eeuo pipefail
  local name="$1" file="$2" local_size downloaded
  [[ -f "$file" && ! -L "$file" ]] || return 1
  local_size="$(stat -c '%s' "$file")"
  [[ "$local_size" =~ ^[1-9][0-9]*$ ]] || return 1
  downloaded="$(mktemp /run/hexvault-release-verify.XXXXXX)"
  trap 'rm -f -- "$downloaded"' EXIT
  # The caller owns the registry refresh. This lookup/download is exact and
  # deliberately does not turn every chunk verification into 1-11 list calls.
  gh_download_asset_to "$name" "$downloaded" "$local_size" || return 1
  cmp -s -- "$file" "$downloaded"
)

release_cleanup_generation_assets_best_effort() {
  local version="$1"
  shift
  local asset_prefix manifest_asset name suffix count id
  local -A seen=()
  local -a ordered_names=()

  if [[ ! "$version" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}$ ]]; then
    warn "Refusing cleanup for an invalid release generation id"
    return 0
  fi
  asset_prefix="${RELEASE_NAMESPACE}snapshot--${version}--${ARCHIVE_NAME}.part_"
  manifest_asset="${RELEASE_NAMESPACE}snapshot--${version}--manifest.json"
  # Hide the commit point first even when callers recorded chunks before it.
  ordered_names=("$manifest_asset" "$@")

  if ! gh_try_refresh_assets; then
    warn "Could not list release assets for partial generation cleanup"
    return 0
  fi

  for name in "${ordered_names[@]}"; do
    [[ -n "$name" && -z "${seen[$name]:-}" ]] || continue
    seen["$name"]=1
    if [[ "$name" != "$manifest_asset" ]]; then
      [[ "$name" == "$asset_prefix"* ]] || {
        warn "Skipping cleanup of an asset outside generation $version"
        continue
      }
      suffix="${name#"$asset_prefix"}"
      [[ "$suffix" =~ ^[0-9]{5}$ ]] || {
        warn "Skipping cleanup of an invalid chunk name in generation $version"
        continue
      }
    fi

    if ! read -r count id < <(jq -r --arg name "$name" '
        [.[]|select(.name==$name)] as $items |
        [($items|length),($items[0].id // 0)] | @tsv' <<<"$GH_ASSETS_JSON"); then
      warn "Could not resolve partial release asset $name"
      continue
    fi
    [[ "$count" =~ ^[0-9]+$ ]] || {
      warn "Could not validate partial release asset $name"
      continue
    }
    ((10#$count == 0)) && continue
    if [[ "$count" != 1 || ! "$id" =~ ^[1-9][0-9]*$ ]] || \
       ! gh_delete_asset_id "$id"; then
      warn "Could not clean partial release asset $name"
    fi
  done
}

validate_release_namespace_assets() {
  jq -e --arg prefix "$RELEASE_NAMESPACE" '
    [.[] | select((.name|type=="string") and (.name|startswith($prefix)))] as $assets |
    (($assets|map(.name)|length) == ($assets|map(.name)|unique|length)) and
    all($assets[];
      ((.name|test("[[:space:][:cntrl:]]")|not) and
       (.name | .[($prefix|length):] |
         test("^snapshot--[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}--(manifest\\.json|data\\.tar\\.zst\\.gpg\\.part_[0-9]{5})$"))))
  ' <<<"$GH_ASSETS_JSON" >/dev/null \
    || die "Release contains a duplicate or unsupported asset in the current service/host namespace"
}

release_manifest_names() {
  jq -r --arg prefix "${RELEASE_NAMESPACE}snapshot--" '
    [.[]|select((.name|type=="string") and (.name|startswith($prefix)) and
      (.name|endswith("--manifest.json")))|.name]
    | sort | reverse | .[]' <<<"$GH_ASSETS_JSON"
}

gh_asset_metadata_exact() {
  local name="$1"
  jq -r --arg name "$name" '
    [.[]|select(.name==$name)] as $items |
    [($items|length),($items[0].id // 0),($items[0].size // -1)] | @tsv' \
    <<<"$GH_ASSETS_JSON"
}

SELECTED_RELEASE_MANIFEST=""
SELECTED_RELEASE_DIR=""
SELECTED_RELEASE_PAYLOAD=""
SELECTED_RELEASE_ENCRYPTION=""
RELEASE_CANDIDATE_COUNT=0
RELEASE_SELECTION_STATUS=1
declare -a RELEASE_FAILED_MANIFESTS=()
declare -a RELEASE_AUTHENTICATED_MANIFESTS=()
declare -a RELEASE_AUTHENTICATED_PATHS=()
declare -a RELEASE_AUTHENTICATED_PREFIXES=()
declare -a RELEASE_AUTHENTICATED_CHUNK_COUNTS=()
declare -a RELEASE_AUTHENTICATED_GENERATIONS=()
declare -a RELEASE_AUTHENTICATED_METADATA_COMPLETE=()

discard_selected_release_download() {
  [[ -n "$SELECTED_RELEASE_DIR" ]] || return 0
  [[ "$SELECTED_RELEASE_DIR" == "${INSTALL_PATH}/_release_candidate."* && \
     -d "$SELECTED_RELEASE_DIR" && ! -L "$SELECTED_RELEASE_DIR" ]] \
    || die "Refusing to discard an unsafe selected-release staging path"
  cleanup_remove_dir "$SELECTED_RELEASE_DIR"
  rm -rf -- "$SELECTED_RELEASE_DIR"
  SELECTED_RELEASE_DIR=""
  SELECTED_RELEASE_MANIFEST=""
  SELECTED_RELEASE_PAYLOAD=""
  SELECTED_RELEASE_ENCRYPTION=""
}

validate_release_manifest_identity() {
  local manifest_asset="$1" expected_manifest expected_prefix
  [[ "$MANIFEST_SNAPSHOT_ID" =~ \
     ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}$ ]] \
    || die "Release manifest snapshot_id is not a current writer generation"
  expected_manifest="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--manifest.json"
  expected_prefix="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--${ARCHIVE_NAME}.part_"
  [[ "$manifest_asset" == "$expected_manifest" ]] \
    || die "Release manifest filename does not match its authenticated generation"
  [[ "$MANIFEST_ASSET_PREFIX" == "$expected_prefix" ]] \
    || die "Release manifest asset_prefix does not match its authenticated generation"
}

select_verified_release_snapshot() {
  local scan_dir candidate cached_manifest candidate_dir generation_stem name
  local count id size download_status verify_status index part_index total chunk_bytes
  local metadata_complete candidate_output
  local -a candidates=()
  local -A declared_owner=() generation_allowed=()

  discard_selected_release_download
  SELECTED_RELEASE_MANIFEST=""
  SELECTED_RELEASE_DIR=""
  SELECTED_RELEASE_PAYLOAD=""
  SELECTED_RELEASE_ENCRYPTION=""
  RELEASE_SELECTION_STATUS=1
  RELEASE_FAILED_MANIFESTS=()
  RELEASE_AUTHENTICATED_MANIFESTS=()
  RELEASE_AUTHENTICATED_PATHS=()
  RELEASE_AUTHENTICATED_PREFIXES=()
  RELEASE_AUTHENTICATED_CHUNK_COUNTS=()
  RELEASE_AUTHENTICATED_GENERATIONS=()
  RELEASE_AUTHENTICATED_METADATA_COMPLETE=()
  validate_release_namespace_assets
  candidate_output="$(release_manifest_names)" \
    || die "Could not enumerate the bounded release manifest registry"
  [[ -z "$candidate_output" ]] || mapfile -t candidates <<<"$candidate_output"
  RELEASE_CANDIDATE_COUNT="${#candidates[@]}"
  ((RELEASE_CANDIDATE_COUNT <= 21)) \
    || die "Release contains more than 21 current snapshot manifests"
  scan_dir="$(mktemp -d "${INSTALL_PATH}/_release_manifest_scan.XXXXXX")"
  cleanup_add_dir "$scan_dir"

  # Authenticate every bounded service/host-qualified manifest before any
  # selection, publication, capacity reclamation, or retention mutation.
  for ((index=0; index<${#candidates[@]}; index++)); do
    candidate="${candidates[$index]}"
    read -r count id size < <(gh_asset_metadata_exact "$candidate")
    [[ "$count" == 1 && "$id" =~ ^[1-9][0-9]*$ && \
       "$size" =~ ^[1-9][0-9]*$ && 10#$size -le 1048576 ]] \
      || die "Release manifest asset is missing, duplicate, or unsafe: $candidate"
    cached_manifest="${scan_dir}/manifest-${index}.json"
    set +e
    gh_download_asset_to "$candidate" "$cached_manifest" 1048576
    download_status=$?
    set -e
    case "$download_status" in
      0) ;;
      2) die "Release manifest asset has invalid or oversized metadata: $candidate" ;;
      4) die "Release manifest disappeared during registry validation: $candidate" ;;
      *) die "Transport failed while downloading release manifest: $candidate" ;;
    esac
    validate_manifest "$cached_manifest"
    validate_release_manifest_identity "$candidate"
    [[ -z "${declared_owner[$candidate]:-}" ]] \
      || die "Two authenticated manifests claim the same manifest asset"
    declared_owner["$candidate"]="$candidate"
    generation_stem="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--"
    generation_allowed=(["$candidate"]=1)
    metadata_complete=true
    total=0
    chunk_bytes=$((10#$MANIFEST_CHUNK_SIZE_MB * 1000000))
    for ((part_index=0; part_index<10#$MANIFEST_CHUNK_COUNT; part_index++)); do
      name="${MANIFEST_ASSET_PREFIX}$(printf '%05d' "$part_index")"
      [[ -z "${declared_owner[$name]:-}" ]] \
        || die "Authenticated manifests declare a conflicting exact chunk name: $name"
      declared_owner["$name"]="$candidate"
      generation_allowed["$name"]=1
      read -r count id size < <(gh_asset_metadata_exact "$name")
      case "$count" in
        0) metadata_complete=false ;;
        1)
          [[ "$id" =~ ^[1-9][0-9]*$ && "$size" =~ ^[1-9][0-9]*$ ]] \
            || die "Authenticated generation has unsafe chunk metadata: $name"
          if ((part_index + 1 < 10#$MANIFEST_CHUNK_COUNT)); then
            ((10#$size == chunk_bytes)) || metadata_complete=false
          else
            ((10#$size <= chunk_bytes)) || metadata_complete=false
          fi
          ((total += 10#$size))
          ((total <= 10#$MANIFEST_ARCHIVE_SIZE)) || metadata_complete=false
          ;;
        *) die "Authenticated generation has a duplicate exact chunk asset: $name" ;;
      esac
    done
    ((total == 10#$MANIFEST_ARCHIVE_SIZE)) || metadata_complete=false
    while IFS= read -r name; do
      [[ -n "${generation_allowed[$name]:-}" ]] \
        || die "Authenticated generation contains an undeclared extra asset: $name"
    done < <(jq -r --arg stem "$generation_stem" \
      '.[]|select((.name|type=="string") and (.name|startswith($stem)))|.name' \
      <<<"$GH_ASSETS_JSON")

    RELEASE_AUTHENTICATED_MANIFESTS+=("$candidate")
    RELEASE_AUTHENTICATED_PATHS+=("$cached_manifest")
    RELEASE_AUTHENTICATED_PREFIXES+=("$MANIFEST_ASSET_PREFIX")
    RELEASE_AUTHENTICATED_CHUNK_COUNTS+=("$MANIFEST_CHUNK_COUNT")
    RELEASE_AUTHENTICATED_GENERATIONS+=("$MANIFEST_SNAPSHOT_ID")
    RELEASE_AUTHENTICATED_METADATA_COMPLETE+=("$metadata_complete")
  done

  # Payload verification is newest-to-oldest and stops at the first usable
  # complete snapshot; all small manifests above were already authenticated.
  for ((index=0; index<${#RELEASE_AUTHENTICATED_MANIFESTS[@]}; index++)); do
    candidate="${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"
    if [[ "${RELEASE_AUTHENTICATED_METADATA_COMPLETE[$index]}" != true ]]; then
      RELEASE_FAILED_MANIFESTS+=("$candidate")
      continue
    fi
    candidate_dir="$(mktemp -d "${INSTALL_PATH}/_release_candidate.XXXXXX")"
    cp -- "${RELEASE_AUTHENTICATED_PATHS[$index]}" "$candidate_dir/manifest.json" \
      || die "Could not stage authenticated release manifest"
    set +e
    ( set -Eeuo pipefail; download_release_snapshot "$candidate_dir" )
    verify_status=$?
    set -e
    case "$verify_status" in
      0)
        cleanup_add_dir "$candidate_dir"
        validate_manifest "$candidate_dir/manifest.json"
        validate_release_manifest_identity "$candidate"
        SELECTED_RELEASE_MANIFEST="$candidate"
        SELECTED_RELEASE_DIR="$candidate_dir"
        SELECTED_RELEASE_PAYLOAD="$MANIFEST_PAYLOAD_SHA"
        SELECTED_RELEASE_ENCRYPTION="$MANIFEST_ENCRYPTION"
        RELEASE_SELECTION_STATUS=0
        break
        ;;
      2)
        RELEASE_FAILED_MANIFESTS+=("$candidate")
        rm -rf -- "$candidate_dir"
        ;;
      *)
        rm -rf -- "$candidate_dir"
        die "Release payload download raced or failed during verified selection: $candidate"
        ;;
    esac
  done
}

release_snapshot_assets_are_complete() (
  set -Eeuo pipefail
  local manifest="$1" index name count id size total=0 expected_prefix chunk_bytes
  validate_manifest "$manifest"
  expected_prefix="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--${ARCHIVE_NAME}.part_"
  [[ "$MANIFEST_SNAPSHOT_ID" =~ \
     ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}$ && \
     "$MANIFEST_ASSET_PREFIX" == "$expected_prefix" ]] || return 1
  chunk_bytes=$((10#$MANIFEST_CHUNK_SIZE_MB * 1000000))
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    name="${MANIFEST_ASSET_PREFIX}$(printf '%05d' "$index")"
    read -r count id size < <(gh_asset_metadata_exact "$name")
    [[ "$count" == 1 && "$id" =~ ^[1-9][0-9]*$ && \
       "$size" =~ ^[1-9][0-9]*$ && \
       ${#size} -le ${#MANIFEST_ARCHIVE_SIZE} ]] || return 1
    if ((index + 1 < 10#$MANIFEST_CHUNK_COUNT)); then
      ((10#$size == chunk_bytes)) || return 1
    else
      ((10#$size <= chunk_bytes)) || return 1
    fi
    ((10#$size > 0 && 10#$size <= 10#$MANIFEST_ARCHIVE_SIZE - total)) || return 1
    total=$((total + 10#$size))
  done
  ((total == 10#$MANIFEST_ARCHIVE_SIZE))
)

download_release_snapshot() {
  local tmp="$1"
  local manifest="$tmp/manifest.json"
  local archive part_name part_path index assembled_size download_status verify_status
  path_is_safe_regular_file "$manifest" \
    || die "Downloaded release manifest is missing or unsafe"
  validate_manifest "$manifest"
  release_snapshot_assets_are_complete "$manifest" || return 2
  archive="$tmp/$MANIFEST_ARCHIVE_NAME"
  rm -f -- "$archive"
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    part_name="${MANIFEST_ASSET_PREFIX}$(printf '%05d' "$index")"
    part_path="$tmp/$part_name"
    set +e
    gh_download_asset_to "$part_name" "$part_path"
    download_status=$?
    set -e
    case "$download_status" in
      0) ;;
      2) return 2 ;;
      *) return 3 ;;
    esac
    cat "$part_path" >>"$archive" || return 3
    rm -f -- "$part_path"
    assembled_size="$(stat -c '%s' "$archive")"
    ((10#$assembled_size <= 10#$MANIFEST_ARCHIVE_SIZE)) || return 2
  done
  set +e
  ( set -Eeuo pipefail; validate_manifest "$manifest"; verify_archive "$archive" "$manifest" )
  verify_status=$?
  set -e
  [[ "$verify_status" -eq 0 ]] || return 2
  return 0
}

release_delete_authenticated_generation() {
  local index="$1" manifest prefix count generation name matches id manifest_id part_index
  local -a chunk_ids=()
  [[ "$index" =~ ^[0-9]+$ && 10#$index -lt ${#RELEASE_AUTHENTICATED_MANIFESTS[@]} ]] \
    || die "Invalid authenticated release registry index"
  manifest="${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"
  prefix="${RELEASE_AUTHENTICATED_PREFIXES[$index]}"
  count="${RELEASE_AUTHENTICATED_CHUNK_COUNTS[$index]}"
  generation="${RELEASE_AUTHENTICATED_GENERATIONS[$index]}"
  [[ "$generation" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}$ && \
     "$manifest" == "${RELEASE_NAMESPACE}snapshot--${generation}--manifest.json" && \
     "$prefix" == "${RELEASE_NAMESPACE}snapshot--${generation}--${ARCHIVE_NAME}.part_" ]] \
    || die "Refusing mutation for unsafe authenticated release metadata"
  read -r matches id _ < <(gh_asset_metadata_exact "$manifest")
  [[ "$matches" == 1 && "$id" =~ ^[1-9][0-9]*$ ]] \
    || die "Authenticated manifest became missing or ambiguous before mutation"
  manifest_id="$id"
  for ((part_index=0; part_index<10#$count; part_index++)); do
    name="${prefix}$(printf '%05d' "$part_index")"
    read -r matches id _ < <(gh_asset_metadata_exact "$name")
    case "$matches" in
      0) ;;
      1)
        [[ "$id" =~ ^[1-9][0-9]*$ ]] \
          || die "Authenticated generation has an unsafe chunk id"
        chunk_ids+=("$id")
        ;;
      *) die "Authenticated generation chunk became ambiguous before mutation: $name" ;;
    esac
  done

  # Manifest first hides the generation atomically; exact declared chunks only.
  gh_delete_asset_id "$manifest_id" || return 1
  for id in "${chunk_ids[@]}"; do
    gh_delete_asset_id "$id" \
      || warn "Could not delete hidden authenticated release chunk id=$id"
  done
}

ensure_release_asset_capacity() {
  local needed="$1" allow_pre_gc="${2:-true}"
  local count manifest_count target=-1 index pinned
  validate_uint_range release.new_asset_count "$needed" 2 1000
  while :; do
    count="$(jq 'length' <<<"$GH_ASSETS_JSON")"
    manifest_count="${#RELEASE_AUTHENTICATED_MANIFESTS[@]}"
    if ((10#$count + 10#$needed <= 1000 && manifest_count + 1 <= 21)); then
      return 0
    fi
    [[ "$allow_pre_gc" == true && -n "$SELECTED_RELEASE_MANIFEST" ]] \
      || die "Release capacity/registry bound requires GC, but no verified generation can be pinned"
    pinned="$SELECTED_RELEASE_MANIFEST"
    target=-1
    for ((index=${#RELEASE_AUTHENTICATED_MANIFESTS[@]}-1; index>=0; index--)); do
      [[ "${RELEASE_AUTHENTICATED_MANIFESTS[$index]}" == "$pinned" ]] && continue
      target="$index"
      break
    done
    ((target >= 0)) \
      || die "GitHub release capacity is exhausted while preserving the verified generation"
    release_delete_authenticated_generation "$target" \
      || die "Could not hide an authenticated generation for safe pre-publish capacity recovery"
    gh_refresh_assets
    select_verified_release_snapshot
    [[ "$RELEASE_SELECTION_STATUS" -eq 0 ]] \
      || die "Pre-publish GC lost the required verified release generation"
  done
}

pin_authenticated_release_generation() {
  local manifest="$1" index=-1 candidate_dir verify_status
  if [[ "$SELECTED_RELEASE_MANIFEST" == "$manifest" ]]; then
    return 0
  fi
  for ((verify_status=0; verify_status<${#RELEASE_AUTHENTICATED_MANIFESTS[@]}; verify_status++)); do
    if [[ "${RELEASE_AUTHENTICATED_MANIFESTS[$verify_status]}" == "$manifest" ]]; then
      index="$verify_status"
      break
    fi
  done
  ((index >= 0)) || die "Published release manifest is absent from the authenticated registry"
  candidate_dir="$(mktemp -d "${INSTALL_PATH}/_release_candidate.XXXXXX")"
  cp -- "${RELEASE_AUTHENTICATED_PATHS[$index]}" "$candidate_dir/manifest.json" \
    || die "Could not stage the published release manifest for full verification"
  set +e
  ( set -Eeuo pipefail; download_release_snapshot "$candidate_dir" )
  verify_status=$?
  set -e
  [[ "$verify_status" -eq 0 ]] || {
    rm -rf -- "$candidate_dir"
    die "Published release generation failed full archive verification"
  }
  discard_selected_release_download
  cleanup_add_dir "$candidate_dir"
  validate_manifest "$candidate_dir/manifest.json"
  validate_release_manifest_identity "$manifest"
  SELECTED_RELEASE_MANIFEST="$manifest"
  SELECTED_RELEASE_DIR="$candidate_dir"
  SELECTED_RELEASE_PAYLOAD="$MANIFEST_PAYLOAD_SHA"
  SELECTED_RELEASE_ENCRYPTION="$MANIFEST_ENCRYPTION"
  RELEASE_SELECTION_STATUS=0
}

publish_release_snapshot() {
  local allow_pre_gc="${1:-true}"
  local version asset_prefix manifest_asset local_manifest file suffix name candidate_output
  local post_asset_count post_manifest_count
  local -a parts attempted_assets=() chunk_assets=() post_manifest_names=()
  split_archive_into_remote
  parts=("${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*)
  # pack_payload may take time. Re-list and authenticate the entire bounded
  # manifest registry again before the first upload or GC mutation.
  gh_refresh_assets
  select_verified_release_snapshot
  if [[ "$RELEASE_SELECTION_STATUS" -eq 0 && \
        "$SELECTED_RELEASE_PAYLOAD" == "$PACK_PAYLOAD_SHA" && \
        "$SELECTED_RELEASE_ENCRYPTION" == gpg-aes256-v1 && \
        ${#RELEASE_FAILED_MANIFESTS[@]} -eq 0 ]]; then
    log "Local snapshot matches the revalidated release registry"
    return 0
  fi
  [[ "$RELEASE_SELECTION_STATUS" -eq 0 ]] || allow_pre_gc=false
  ensure_release_asset_capacity "$((${#parts[@]} + 1))" "$allow_pre_gc"
  version="$(date -u +'%Y%m%dT%H%M%SZ')-${PACK_PAYLOAD_SHA:0:16}-$(openssl rand -hex 16)"
  [[ "$version" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}-[0-9a-f]{32}$ ]] \
    || die "Could not generate a valid release generation id"
  asset_prefix="${RELEASE_NAMESPACE}snapshot--${version}--${ARCHIVE_NAME}.part_"
  manifest_asset="${RELEASE_NAMESPACE}snapshot--${version}--manifest.json"
  local_manifest="${REMOTE_DIR}/${MANIFEST_NAME}"
  write_manifest "$local_manifest" "$(now_utc)" "$PACK_SIZE" "$PACK_SHA" \
    "$PACK_PAYLOAD_SHA" "$PACK_ARCHIVE_HMAC" "$PACK_ENCRYPTION" \
    "$version" "$asset_prefix"

  for file in "${parts[@]}"; do
    suffix="${file##*.part_}"
    [[ "$suffix" =~ ^[0-9]{5}$ ]] || die "Snapshot split produced an invalid chunk name"
    chunk_assets+=("${asset_prefix}${suffix}")
  done

  # The generation nonce is unique, but still fail closed if any generated name
  # already exists. Cleanup below only ever receives these exact names.
  for name in "${chunk_assets[@]}" "$manifest_asset"; do
    [[ "$(jq -r --arg name "$name" '[.[]|select(.name==$name)]|length' \
      <<<"$GH_ASSETS_JSON")" == 0 ]] \
      || die "Release generation asset name already exists: $name"
  done

  for ((suffix=0; suffix<${#parts[@]}; suffix++)); do
    file="${parts[$suffix]}"
    name="${chunk_assets[$suffix]}"
    attempted_assets+=("$name")
    if gh_upload_asset_as "$file" "$name"; then
      :
    elif gh_try_refresh_assets && release_asset_matches_file "$name" "$file"; then
      log "Upload response for $name was lost, but the remote asset verifies"
    else
      release_cleanup_generation_assets_best_effort \
        "$version" "$manifest_asset" "${attempted_assets[@]}"
      die "Release chunk upload failed; partial generation cleanup was attempted"
    fi
  done

  # One consistent refresh authenticates the advertised registry and supplies
  # the exact id/size map used for every chunk verification below. It also
  # catches concurrent capacity/manifest changes before the manifest mutation.
  gh_refresh_assets
  select_verified_release_snapshot
  post_asset_count="$(jq 'length' <<<"$GH_ASSETS_JSON")"
  post_manifest_count="${#RELEASE_AUTHENTICATED_MANIFESTS[@]}"
  if ((10#$post_asset_count + 1 > 1000 || post_manifest_count + 1 > 21)); then
    release_cleanup_generation_assets_best_effort \
      "$version" "$manifest_asset" "${attempted_assets[@]}"
    die "Concurrent publication consumed reserved release capacity; partial generation cleanup was attempted"
  fi
  [[ "$(jq -r --arg name "$manifest_asset" \
      '[.[]|select(.name==$name)]|length' <<<"$GH_ASSETS_JSON")" == 0 ]] \
    || { release_cleanup_generation_assets_best_effort \
           "$version" "$manifest_asset" "${attempted_assets[@]}"; \
         die "Release manifest name appeared concurrently; partial generation cleanup was attempted"; }
  for ((suffix=0; suffix<${#parts[@]}; suffix++)); do
    if ! release_asset_matches_file "${chunk_assets[$suffix]}" "${parts[$suffix]}"; then
      release_cleanup_generation_assets_best_effort \
        "$version" "$manifest_asset" "${attempted_assets[@]}"
      die "Uploaded release chunks failed verification; partial generation cleanup was attempted"
    fi
  done

  # The versioned manifest is the commit point and is uploaded only after all chunks.
  attempted_assets+=("$manifest_asset")
  if gh_upload_asset_as "$local_manifest" "$manifest_asset"; then
    :
  elif gh_try_refresh_assets && \
       release_asset_matches_file "$manifest_asset" "$local_manifest"; then
    log "Manifest upload response was lost, but the remote manifest verifies"
  else
    release_cleanup_generation_assets_best_effort "$version" "${attempted_assets[@]}"
    die "Release manifest upload failed; partial generation cleanup was attempted"
  fi
  # The manifest is now visible. Authenticate the full bounded registry and
  # fully re-download/verify this exact generation before permitting retention.
  if ! gh_try_refresh_assets; then
    release_cleanup_generation_assets_best_effort "$version" "${attempted_assets[@]}"
    die "Could not refresh the registry after manifest publication; generation cleanup was attempted"
  fi
  candidate_output="$(release_manifest_names)" \
    || { release_cleanup_generation_assets_best_effort "$version" "${attempted_assets[@]}"; \
         die "Could not enumerate the post-publish manifest registry"; }
  [[ -z "$candidate_output" ]] || mapfile -t post_manifest_names <<<"$candidate_output"
  if ((${#post_manifest_names[@]} > 21)); then
    release_cleanup_generation_assets_best_effort "$version" "${attempted_assets[@]}"
    die "Concurrent publication exceeded the bounded manifest registry; current generation cleanup was attempted"
  fi
  if ! release_asset_matches_file "$manifest_asset" "$local_manifest"; then
    release_cleanup_generation_assets_best_effort "$version" "${attempted_assets[@]}"
    die "Uploaded release manifest failed verification; partial generation cleanup was attempted"
  fi
  select_verified_release_snapshot
  pin_authenticated_release_generation "$manifest_asset"
  log "Published complete release snapshot $version"
}

gc_release_snapshots() {
  local keep="${1:-$SYNC_RELEASE_KEEP}" index retained=0 manifest
  local -A keep_manifest=()
  validate_uint_range release_gc.keep "$keep" 1 20
  [[ "$RELEASE_SELECTION_STATUS" -eq 0 && -n "$SELECTED_RELEASE_MANIFEST" ]] \
    || die "Retention requires a fully verified generation to remain pinned"
  keep_manifest["$SELECTED_RELEASE_MANIFEST"]=1
  retained=1
  for manifest in "${RELEASE_AUTHENTICATED_MANIFESTS[@]}"; do
    [[ -n "${keep_manifest[$manifest]:-}" ]] && continue
    ((retained >= 10#$keep)) && break
    keep_manifest["$manifest"]=1
    ((retained+=1))
  done
  for ((index=${#RELEASE_AUTHENTICATED_MANIFESTS[@]}-1; index>=0; index--)); do
    manifest="${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"
    [[ -n "${keep_manifest[$manifest]:-}" ]] && continue
    if ! release_delete_authenticated_generation "$index"; then
      warn "Could not hide stale authenticated release generation $manifest"
    fi
  done
  gh_refresh_assets
  select_verified_release_snapshot
  [[ "$RELEASE_SELECTION_STATUS" -eq 0 ]] \
    || die "Retention verification lost the pinned complete release generation"
}

perform_releases_sync() {
  local phase="${1:-startup}"
  local remote_present=false remote_payload="" remote_encryption=""
  local allow_pre_gc=false release_needs_repair=false
  ensure_tools_releases
  [[ "$phase" == startup || "$phase" == publish ]] \
    || die "Unknown releases sync phase: $phase"
  parse_gh_remote
  { ! sync_can_write || [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]]; } \
    || die "Release write sync requires SYNC_ENCRYPTION_PASSPHRASE"
  gh_auth_header
  gh_ensure_release "$phase"
  if [[ -z "$GH_REL_ID" ]]; then
    if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true ]]; then
      die "SYNC_FORCE_RESTORE requested, but the release does not exist"
    fi
    return 0
  fi
  gh_refresh_assets
  select_verified_release_snapshot
  if [[ "$RELEASE_SELECTION_STATUS" -eq 0 ]]; then
    remote_present=true
    remote_payload="$SELECTED_RELEASE_PAYLOAD"
    remote_encryption="$SELECTED_RELEASE_ENCRYPTION"
    allow_pre_gc=true
    ((${#RELEASE_FAILED_MANIFESTS[@]} == 0)) || release_needs_repair=true
  elif ((RELEASE_CANDIDATE_COUNT > 0)); then
    if sync_can_write && data_has_meaningful_content; then
      warn "No authenticated release generation has a usable payload; preserving the registry before repair publish"
    else
      die "No complete authenticated Release generation is available"
    fi
  fi

  if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true && \
        "$remote_present" != true ]]; then
    die "SYNC_FORCE_RESTORE requested, but no valid release snapshot exists"
  fi

  if [[ "$phase" == startup && "$remote_present" == true ]] && \
     { ! data_has_meaningful_content || [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; }; then
    log "Restoring filesystem snapshot from release"
    validate_manifest "$SELECTED_RELEASE_DIR/manifest.json"
    import_payload "$SELECTED_RELEASE_DIR/$MANIFEST_ARCHIVE_NAME"
  fi

  if [[ "$phase" == startup ]]; then
    [[ "$remote_present" == true ]] && \
      log "Startup restore phase complete; publication deferred until schema validation" || \
      log "Startup restore phase found no usable release snapshot"
    return 0
  fi

  sync_can_write || return 0
  if ! data_has_meaningful_content; then
    [[ "$phase" != publish ]] \
      || die "Publish-only sync refused: local HexVault data is missing"
    log "No meaningful local data to publish"
    return 0
  fi
  pack_payload
  if [[ "$remote_present" == true && "$remote_payload" == "$PACK_PAYLOAD_SHA" && \
        "$remote_encryption" == gpg-aes256-v1 && "$release_needs_repair" == false ]]; then
    log "Local snapshot matches fully verified release remote"
    return 0
  fi
  publish_release_snapshot "$allow_pre_gc"
  gc_release_snapshots
}

################################################################
# Bootstrap & Launch
################################################################

sync_can_write() {
  [[ "${SYNC_ENABLED,,}" == true ]] || return 1
  [[ "${SYNC_READ_ONLY,,}" != true ]] || return 1
  case "${SYNC_METHOD,,}" in
    releases) [[ -n "$SYNC_AUTH_TOKEN" ]] ;;
    commits)
      if [[ "$GH_REMOTE" =~ ^https:// ]]; then
        [[ -n "$SYNC_AUTH_TOKEN" ]]
      else
        gh_remote_uses_ssh "$GH_REMOTE" && \
          [[ -n "$GH_SSH_PRIVATE_KEY" ]]
      fi ;;
  esac
}

perform_sync() {
  local phase="${1:-startup}"
  local lock_timeout="${2:-$SYNC_LOCK_TIMEOUT_SECONDS}" sync_lock_fd
  local HOME=/root USER=root LOGNAME=root
  export HOME USER LOGNAME
  [[ "${SYNC_ENABLED,,}" == true ]] || return 0
  exec {sync_lock_fd}>/run/hexvault-sync.lock
  flock -w "$lock_timeout" -x "$sync_lock_fd" \
    || die "Timed out waiting ${lock_timeout}s for the sync lock"
  case "${SYNC_METHOD,,}" in
    commits) perform_commits_sync "$phase" ;;
    releases) perform_releases_sync "$phase" ;;
  esac
  rm -f -- "$ARCHIVE_PATH"
  if [[ -n "$AUTH_HEADER_FILE" ]]; then
    rm -f -- "$AUTH_HEADER_FILE"
    AUTH_HEADER_FILE=""; AUTH_HEADER=()
  fi
  GIT_CREDENTIAL_HELPER=""
  unset GIT_SSH_COMMAND || true
  rm -rf -- /run/hexvault-sync-ssh /run/hexvault-git-auth "$SYNC_GNUPG_HOME"
  cleanup_remove_dir "$SYNC_GNUPG_HOME"
  flock -u "$sync_lock_fd"
  exec {sync_lock_fd}>&-
}

run_as_service() {
  local uid gid
  uid="$(id -u "$SERVICE_USER")"; gid="$(id -g "$SERVICE_USER")"
  setpriv --reuid "$uid" --regid "$gid" --init-groups \
    --inh-caps=-all --ambient-caps=-all \
    env -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
      -u GH_SSH_PRIVATE_KEY -u GIT_SSH_COMMAND \
      HOME=/var/lib/hexvault USER="$SERVICE_USER" LOGNAME="$SERVICE_USER" \
      XDG_DATA_HOME=/var/lib/hexvault/.local/share \
      XDG_CONFIG_HOME=/var/lib/hexvault/.config "$@"
}

tls_pair_is_valid() {
  local cert="$1" key="$2" check_seconds="${3:-0}" cert_pub key_pub
  local -a cert_name_check
  path_is_safe_regular_file "$cert" && path_is_safe_regular_file "$key" && \
    path_is_safe_regular_file "${CA_PATH}/CA.pem" || return 1
  [[ "$VAULT_HOST_KIND" == ip ]] && cert_name_check=(-checkip "$VAULT_HOST") \
    || cert_name_check=(-checkhost "$VAULT_HOST")
  openssl x509 -in "$cert" -noout -checkend "$check_seconds" >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -noout "${cert_name_check[@]}" >/dev/null 2>&1 || return 1
  openssl verify -CAfile "${CA_PATH}/CA.pem" "$cert" >/dev/null 2>&1 || return 1
  cert_pub="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | \
    openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" \
    || return 1
  key_pub="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | \
    sha256sum | awk '{print $1}')" || return 1
  [[ "$cert_pub" =~ ^[0-9a-f]{64}$ && "$cert_pub" == "$key_pub" ]]
}

remove_replaceable_file() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" || -L "$path" ]] || return 1
    rm -f -- "$path"
  fi
}

cleanup_tls_install_temps() {
  local unsafe
  [[ "$CONFIG_PATH" == /opt/hexvault/config ]] \
    || die "Unexpected config path during TLS temp cleanup"
  unsafe="$(find "$CONFIG_PATH" -mindepth 1 -maxdepth 1 \
    -name '.hexvault.tls.install.*' ! -type f ! -type l -print -quit)"
  [[ -z "$unsafe" ]] || die "Unsafe TLS install staging entry: $unsafe"
  find "$CONFIG_PATH" -mindepth 1 -maxdepth 1 \
    -name '.hexvault.tls.install.*' \( -type f -o -type l \) -delete
}

write_tls_rotation_marker() {
  local temporary
  temporary="$(mktemp "${RECOVERY_PATH}/.tls-rotation-in-progress.XXXXXX.tmp")"
  cleanup_add_file "$temporary"
  printf 'hexvault tls rotation in progress\n' >"$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary"
  mv -f -- "$temporary" "$TLS_ROTATION_MARKER"
  cleanup_remove_file "$temporary"
  durable_sync_path "$RECOVERY_PATH"
}

finish_tls_rotation_state() {
  rm -f -- "$TLS_ROTATION_MARKER"
  durable_sync_path "$RECOVERY_PATH"
  rm -rf -- "$TLS_PREVIOUS_DIR"
  remove_replaceable_file "$TLS_NEW_KEY" || die "Unsafe staged TLS key path"
  remove_replaceable_file "$TLS_NEW_CERT" || die "Unsafe staged TLS certificate path"
  remove_replaceable_file "$TLS_NEW_CSR" || die "Unsafe staged TLS CSR path"
  cleanup_tls_install_temps
  durable_sync_path "$RECOVERY_PATH"
  durable_sync_path "$CONFIG_PATH"
}

install_tls_pair_atomically() {
  local source_cert="$1" source_key="$2" temp_cert temp_key
  tls_pair_is_valid "$source_cert" "$source_key" 0 \
    || die "Refusing to install an invalid TLS pair"
  [[ ! -e "$TLS_CERT" && ! -L "$TLS_CERT" || -f "$TLS_CERT" || -L "$TLS_CERT" ]] \
    || die "TLS certificate target is not replaceable"
  [[ ! -e "$TLS_KEY" && ! -L "$TLS_KEY" || -f "$TLS_KEY" || -L "$TLS_KEY" ]] \
    || die "TLS key target is not replaceable"
  temp_cert="$(mktemp "${CONFIG_PATH}/.hexvault.tls.install.XXXXXX.crt")"
  temp_key="$(mktemp "${CONFIG_PATH}/.hexvault.tls.install.XXXXXX.key")"
  cleanup_add_file "$temp_cert"; cleanup_add_file "$temp_key"
  cp -- "$source_cert" "$temp_cert"
  cp -- "$source_key" "$temp_key"
  chown root:root "$temp_cert" "$temp_key"
  chmod 640 "$temp_cert" "$temp_key"
  durable_sync_path "$temp_cert"; durable_sync_path "$temp_key"
  mv -f -- "$temp_key" "$TLS_KEY"
  cleanup_remove_file "$temp_key"
  durable_sync_path "$CONFIG_PATH"
  mv -f -- "$temp_cert" "$TLS_CERT"
  cleanup_remove_file "$temp_cert"
  durable_sync_path "$CONFIG_PATH"
}

recover_interrupted_tls_rotation() {
  local no_previous="${TLS_PREVIOUS_DIR}/no-previous"
  if [[ ! -e "$TLS_ROTATION_MARKER" && ! -L "$TLS_ROTATION_MARKER" ]]; then
    # Without the durable marker, final paths were never touched.
    if [[ -e "$TLS_PREVIOUS_DIR" || -L "$TLS_PREVIOUS_DIR" ]]; then
      [[ "$TLS_PREVIOUS_DIR" == /opt/hexvault/recovery/tls-previous ]] \
        || die "Unexpected TLS recovery path"
      rm -rf -- "$TLS_PREVIOUS_DIR"
    fi
    remove_replaceable_file "$TLS_NEW_KEY" || die "Unsafe staged TLS key path"
    remove_replaceable_file "$TLS_NEW_CERT" || die "Unsafe staged TLS certificate path"
    remove_replaceable_file "$TLS_NEW_CSR" || die "Unsafe staged TLS CSR path"
    cleanup_tls_install_temps
    return 0
  fi
  path_is_safe_regular_file "$TLS_ROTATION_MARKER" \
    || die "Unsafe TLS rotation marker; inspect $RECOVERY_PATH manually"
  [[ "$(read_single_line_file "$TLS_ROTATION_MARKER")" == \
      "hexvault tls rotation in progress" ]] \
    || die "Unknown TLS rotation marker; inspect $RECOVERY_PATH manually"

  if tls_pair_is_valid "$TLS_CERT" "$TLS_KEY" 0; then
    log "Completed TLS pair was durable; finalizing interrupted rotation"
    finish_tls_rotation_state
    return 0
  fi
  if path_is_safe_directory "$TLS_PREVIOUS_DIR" && \
     tls_pair_is_valid "$TLS_PREVIOUS_DIR/hexvault.crt" \
       "$TLS_PREVIOUS_DIR/hexvault.key" 0; then
    warn "Restoring previous TLS pair after interrupted rotation"
    install_tls_pair_atomically "$TLS_PREVIOUS_DIR/hexvault.crt" \
      "$TLS_PREVIOUS_DIR/hexvault.key"
    finish_tls_rotation_state
    return 0
  fi
  if path_is_safe_directory "$TLS_PREVIOUS_DIR" && \
     path_is_safe_regular_file "$no_previous" && [[ ! -s "$no_previous" ]]; then
    warn "Discarding partial first-time TLS pair after interrupted rotation"
    remove_replaceable_file "$TLS_CERT" || die "Unsafe TLS certificate target"
    remove_replaceable_file "$TLS_KEY" || die "Unsafe TLS key target"
    finish_tls_rotation_state
    return 0
  fi
  die "Interrupted TLS rotation has no valid previous or completed pair; recovery state preserved"
}

ensure_tls_certificate() {
  local openssl_cfg san_entry no_previous="${TLS_PREVIOUS_DIR}/no-previous"
  recover_interrupted_tls_rotation
  if tls_pair_is_valid "$TLS_CERT" "$TLS_KEY" 2592000; then
    log "Using existing valid TLS certificate"
    return 0
  fi
  path_is_safe_regular_file "${CA_PATH}/CA.pem" && \
    path_is_safe_regular_file "$CA_KEY_FILE" \
    || die "Stock HexVault container requires regular CA.pem and root-only CA.key files"
  if [[ -e "$TLS_SERIAL" || -L "$TLS_SERIAL" ]]; then
    path_is_safe_regular_file "$TLS_SERIAL" \
      || die "CA serial path is unsafe"
  fi
  remove_replaceable_file "$TLS_NEW_KEY" || die "Unsafe staged TLS key path"
  remove_replaceable_file "$TLS_NEW_CERT" || die "Unsafe staged TLS certificate path"
  remove_replaceable_file "$TLS_NEW_CSR" || die "Unsafe staged TLS CSR path"
  openssl_cfg="$(mktemp /run/hexvault-openssl.XXXXXX.cnf)"; cleanup_add_file "$openssl_cfg"
  [[ "$VAULT_HOST_KIND" == ip ]] && san_entry="IP.1=${VAULT_HOST}" \
    || san_entry="DNS.1=${VAULT_HOST}"
  cat >"$openssl_cfg" <<EOF
[req]
distinguished_name=req_distinguished_name
[req_distinguished_name]
[v3_req]
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
${san_entry}
EOF
  umask 077
  openssl req -newkey rsa:3072 -nodes -keyout "$TLS_NEW_KEY" \
    -out "$TLS_NEW_CSR" -subj "/CN=HexVault" \
    -config "$openssl_cfg" -reqexts v3_req >/dev/null 2>&1 \
    || die "TLS CSR generation failed"
  openssl x509 -req -in "$TLS_NEW_CSR" \
    -CA "${CA_PATH}/CA.pem" -CAkey "$CA_KEY_FILE" \
    -CAserial "$TLS_SERIAL" -CAcreateserial \
    -out "$TLS_NEW_CERT" -days 365 -sha512 -extensions v3_req -extfile "$openssl_cfg" \
    >/dev/null 2>&1 || die "TLS certificate signing failed"
  tls_pair_is_valid "$TLS_NEW_CERT" "$TLS_NEW_KEY" 2592000 \
    || die "New TLS pair failed CA, SAN, expiry, or public-key validation"

  [[ ! -e "$TLS_PREVIOUS_DIR" && ! -L "$TLS_PREVIOUS_DIR" ]] \
    || die "Unexpected TLS previous-pair path before rotation"
  mkdir -m 700 "$TLS_PREVIOUS_DIR"
  if tls_pair_is_valid "$TLS_CERT" "$TLS_KEY" 0; then
    cp -- "$TLS_CERT" "$TLS_PREVIOUS_DIR/hexvault.crt"
    cp -- "$TLS_KEY" "$TLS_PREVIOUS_DIR/hexvault.key"
    chmod 600 "$TLS_PREVIOUS_DIR/hexvault.crt" "$TLS_PREVIOUS_DIR/hexvault.key"
  else
    : >"$no_previous"
    chmod 600 "$no_previous"
  fi
  sync
  write_tls_rotation_marker
  install_tls_pair_atomically "$TLS_NEW_CERT" "$TLS_NEW_KEY"
  tls_pair_is_valid "$TLS_CERT" "$TLS_KEY" 2592000 \
    || die "Installed TLS pair failed final validation; recovery marker preserved"
  finish_tls_rotation_state
  log "Generated and atomically rotated TLS certificate"
}

schema_fingerprint_for() {
  local database="$1"
  path_is_safe_regular_file "$database" \
    || die "Cannot fingerprint unsafe SQLite database path"
  sqlite3 -readonly -batch -noheader -init /dev/null \
    -cmd '.timeout 30000' "$database" \
    "SELECT 'meta|application_id|' || application_id FROM pragma_application_id;
     SELECT 'meta|user_version|' || user_version FROM pragma_user_version;
     SELECT 'schema|' || hex(CAST(type AS BLOB)) || '|' ||
            hex(CAST(name AS BLOB)) || '|' || hex(CAST(tbl_name AS BLOB)) || '|' ||
            hex(CAST(coalesce(sql,'') AS BLOB))
       FROM sqlite_schema
      ORDER BY type,name,tbl_name,coalesce(sql,'');" \
    | sha256sum | awk '{print $1}'
}

schema_fingerprint() { schema_fingerprint_for "$DB_FILE"; }

write_schema_version() {
  local temporary fingerprint
  if [[ -e "$SCHEMA_VERSION_FILE" || -L "$SCHEMA_VERSION_FILE" ]]; then
    path_is_safe_regular_file "$SCHEMA_VERSION_FILE" \
      || die "Canonical schema identity target is unsafe"
  fi
  fingerprint="$(schema_fingerprint)"
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || die "Could not fingerprint SQLite schema"
  temporary="$(mktemp "${RECOVERY_PATH}/.hexvault-schema.XXXXXX.tmp")"
  cleanup_add_file "$temporary"
  printf '%s %s\n' "$SCHEMA_VERSION" "$fingerprint" >"$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary"
  mv -f -- "$temporary" "$SCHEMA_VERSION_FILE"
  cleanup_remove_file "$temporary"
  durable_sync_path "$RECOVERY_PATH"
}

restore_schema_backup() {
  local backup="$1" temporary
  temporary="$(mktemp "${DATA_PATH}/.hexvault.rollback.XXXXXX.sqlite3")"
  cleanup_add_file "$temporary"
  cp -- "$backup" "$temporary" || return 1
  chown "$(id -u "$SERVICE_USER"):$(id -g "$SERVICE_USER")" "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary" || return 1
  [[ ! -e "$DB_FILE" && ! -L "$DB_FILE" || -f "$DB_FILE" || -L "$DB_FILE" ]] \
    || { rm -f -- "$temporary"; cleanup_remove_file "$temporary"; return 1; }
  rm -f -- "${DB_FILE}-wal" "${DB_FILE}-shm" "${DB_FILE}-journal"
  mv -f -- "$temporary" "$DB_FILE"
  cleanup_remove_file "$temporary"
  durable_sync_path "$DATA_PATH"
}

clear_schema_upgrade_transaction() {
  rm -f -- "$SCHEMA_UPGRADE_BACKUP"
  durable_sync_path "$RECOVERY_PATH"
  rm -f -- "$SCHEMA_UPGRADE_IDENTITY_BACKUP"
  durable_sync_path "$RECOVERY_PATH"
}

restore_schema_upgrade_transaction() {
  local expected_metadata restored_metadata
  [[ -f "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     -s "$SCHEMA_UPGRADE_BACKUP" ]] \
    || die "Schema upgrade recovery database is missing or unsafe"
  schema_identity_is_root_only "$SCHEMA_UPGRADE_IDENTITY_BACKUP" \
    || die "Schema upgrade recovery identity is missing or unsafe"
  expected_metadata="$(schema_identity_metadata_for_database \
    "$SCHEMA_UPGRADE_IDENTITY_BACKUP" "$SCHEMA_UPGRADE_BACKUP")" \
    || die "Schema upgrade recovery database and identity do not match"

  restore_schema_backup "$SCHEMA_UPGRADE_BACKUP" \
    || die "Could not recover the pre-upgrade SQLite database; backups preserved"
  install_schema_identity_from "$SCHEMA_UPGRADE_IDENTITY_BACKUP"
  restored_metadata="$(schema_identity_metadata_for_database \
    "$SCHEMA_VERSION_FILE" "$DB_FILE")" \
    || die "Recovered pre-upgrade database and identity failed validation"
  [[ "$restored_metadata" == "$expected_metadata" ]] \
    || die "Recovered schema identity differs from the trusted pre-upgrade identity"
}

recover_interrupted_schema_upgrade() {
  local database_backup_present=false identity_backup_present=false
  local backup_metadata current_metadata="" backup_version backup_fingerprint
  local current_version="" current_fingerprint

  [[ -e "$SCHEMA_UPGRADE_BACKUP" || -L "$SCHEMA_UPGRADE_BACKUP" ]] && \
    database_backup_present=true
  [[ -e "$SCHEMA_UPGRADE_IDENTITY_BACKUP" || \
     -L "$SCHEMA_UPGRADE_IDENTITY_BACKUP" ]] && identity_backup_present=true
  if [[ "$database_backup_present" == false && \
        "$identity_backup_present" == false ]]; then
    return 0
  fi

  if [[ "$database_backup_present" == false ]]; then
    schema_identity_is_root_only "$SCHEMA_UPGRADE_IDENTITY_BACKUP" \
      || die "Unsafe orphaned pre-upgrade schema identity"
    backup_metadata="$(read_schema_marker "$SCHEMA_UPGRADE_IDENTITY_BACKUP")" \
      || die "Invalid orphaned pre-upgrade schema identity"
    schema_identity_is_root_only "$SCHEMA_VERSION_FILE" \
      || die "Canonical schema identity is missing or unsafe"
    current_metadata="$(schema_identity_metadata_for_database \
      "$SCHEMA_VERSION_FILE" "$DB_FILE")" \
      || die "Canonical schema identity does not match the live database"
    read -r current_version current_fingerprint <<<"$current_metadata"
    ((10#$current_version <= 10#$SCHEMA_VERSION)) \
      || die "Live schema is newer than the image during upgrade recovery"
    if [[ "$current_version" == "$SCHEMA_VERSION" ]] || \
       cmp -s -- "$SCHEMA_VERSION_FILE" "$SCHEMA_UPGRADE_IDENTITY_BACKUP"; then
      log "Removing an orphaned pre-upgrade identity after a verified transaction boundary"
      rm -f -- "$SCHEMA_UPGRADE_IDENTITY_BACKUP"
      durable_sync_path "$RECOVERY_PATH"
      return 0
    fi
    die "Orphaned pre-upgrade identity does not match a completed or not-yet-started upgrade"
  fi
  [[ "$identity_backup_present" == true ]] \
    || die "Schema upgrade database backup exists without its trusted identity"
  [[ -f "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     -s "$SCHEMA_UPGRADE_BACKUP" ]] \
    || die "Interrupted-upgrade backup is empty or unsafe; preserving it"
  schema_identity_is_root_only "$SCHEMA_UPGRADE_IDENTITY_BACKUP" \
    || die "Interrupted-upgrade identity is unsafe; preserving the transaction"
  backup_metadata="$(schema_identity_metadata_for_database \
    "$SCHEMA_UPGRADE_IDENTITY_BACKUP" "$SCHEMA_UPGRADE_BACKUP")" \
    || die "Interrupted-upgrade backup does not match its trusted identity"
  read -r backup_version backup_fingerprint <<<"$backup_metadata"
  ((10#$backup_version < 10#$SCHEMA_VERSION)) \
    || die "Pre-upgrade identity is not older than image schema $SCHEMA_VERSION"

  if schema_identity_is_root_only "$SCHEMA_VERSION_FILE" && \
     current_metadata="$(schema_identity_metadata_for_database \
       "$SCHEMA_VERSION_FILE" "$DB_FILE")"; then
    read -r current_version current_fingerprint <<<"$current_metadata"
    ((10#$current_version <= 10#$SCHEMA_VERSION)) \
      || die "Live schema is newer than the image during upgrade recovery"
  fi
  if [[ "$current_version" == "$SCHEMA_VERSION" ]]; then
    log "Removing stale pre-upgrade backup after a verified completed upgrade"
    clear_schema_upgrade_transaction
    return 0
  fi

  warn "Recovering the pre-upgrade SQLite database and schema identity after an interrupted upgrade"
  restore_schema_upgrade_transaction
  clear_schema_upgrade_transaction
}

write_schema_recreate_marker() {
  local temporary
  temporary="$(mktemp "${RECOVERY_PATH}/.schema-recreate-in-progress.XXXXXX.tmp")"
  cleanup_add_file "$temporary"
  printf 'hexvault schema recreate in progress\n' >"$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  durable_sync_path "$temporary"
  mv -f -- "$temporary" "$SCHEMA_RECREATE_MARKER"
  cleanup_remove_file "$temporary"
  durable_sync_path "$RECOVERY_PATH"
}

recover_interrupted_schema_recreate() {
  [[ -e "$SCHEMA_RECREATE_MARKER" || -L "$SCHEMA_RECREATE_MARKER" ]] || return 0
  [[ -f "$SCHEMA_RECREATE_MARKER" && ! -L "$SCHEMA_RECREATE_MARKER" ]] \
    || die "Unsafe schema-recreate recovery marker; inspect $RECOVERY_PATH manually"
  [[ "$(read_single_line_file "$SCHEMA_RECREATE_MARKER")" == \
      "hexvault schema recreate in progress" ]] \
    || die "Unrecognized schema-recreate recovery marker; inspect $RECOVERY_PATH manually"
  warn "Removing an incomplete fresh schema recreation before startup sync"
  discard_failed_initial_schema
}

discard_failed_initial_schema() {
  [[ "$DB_FILE" == /opt/hexvault/data/hexvault.sqlite3 ]] \
    || die "Refusing to remove unexpected initial database path"
  if [[ -e "$SCHEMA_VERSION_FILE" || -L "$SCHEMA_VERSION_FILE" ]]; then
    path_is_safe_regular_file "$SCHEMA_VERSION_FILE" \
      || die "Unsafe canonical schema identity during failed initialization cleanup"
  fi
  rm -f -- "$DB_FILE" "${DB_FILE}-wal" "${DB_FILE}-shm" \
    "${DB_FILE}-journal"
  rm -f -- "$SCHEMA_VERSION_FILE"
  if [[ -d "$DATA_PATH/store" ]]; then
    find "$DATA_PATH/store" -mindepth 1 -maxdepth 1 ! -name '.gitignore' \
      -exec rm -rf -- {} +
  fi
  sync
  rm -f -- "$SCHEMA_RECREATE_MARKER"
  durable_sync_path "$RECOVERY_PATH"
}

upgrade_schema_if_needed() {
  local current marker_fingerprint metadata backup_tmp identity_tmp state
  schema_identity_is_root_only "$SCHEMA_VERSION_FILE" \
    || die "Existing database requires a root-only canonical schema identity; refusing startup"
  metadata="$(schema_identity_metadata_for_database "$SCHEMA_VERSION_FILE" "$DB_FILE")" \
    || die "Canonical schema identity does not match the existing SQLite schema"
  read -r current marker_fingerprint <<<"$metadata"
  ((10#$current <= 10#$SCHEMA_VERSION)) \
    || die "Database schema version $current is newer than image schema $SCHEMA_VERSION"
  if [[ "$current" == "$SCHEMA_VERSION" ]]; then
    return 0
  fi

  [[ ! -e "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     ! -e "$SCHEMA_UPGRADE_IDENTITY_BACKUP" && \
     ! -L "$SCHEMA_UPGRADE_IDENTITY_BACKUP" ]] \
    || die "Schema upgrade recovery transaction already exists"
  backup_tmp="$(mktemp "${RECOVERY_PATH}/.hexvault.preupgrade.XXXXXX.tmp")"
  identity_tmp="$(mktemp "${RECOVERY_PATH}/.hexvault-schema.preupgrade.XXXXXX.tmp")"
  cleanup_add_file "$backup_tmp"
  cleanup_add_file "$identity_tmp"
  rm -f -- "$backup_tmp"
  sqlite3 -readonly -cmd '.timeout 30000' "$DB_FILE" ".backup '$backup_tmp'" \
    || die "Could not back up SQLite before schema upgrade"
  sqlite_schema_state "$backup_tmp" || die "Pre-upgrade SQLite backup is invalid"
  cp -- "$SCHEMA_VERSION_FILE" "$identity_tmp" \
    || die "Could not back up canonical schema identity before upgrade"
  chown root:root "$backup_tmp" "$identity_tmp"
  chmod 600 "$backup_tmp" "$identity_tmp"
  durable_sync_path "$backup_tmp"
  durable_sync_path "$identity_tmp"
  [[ "$(schema_identity_metadata_for_database "$identity_tmp" "$backup_tmp")" == \
     "$metadata" ]] \
    || die "Pre-upgrade database and identity backup failed validation"
  mv -f -- "$identity_tmp" "$SCHEMA_UPGRADE_IDENTITY_BACKUP"
  cleanup_remove_file "$identity_tmp"
  durable_sync_path "$RECOVERY_PATH"
  mv -f -- "$backup_tmp" "$SCHEMA_UPGRADE_BACKUP"
  cleanup_remove_file "$backup_tmp"
  durable_sync_path "$RECOVERY_PATH"

  log "Upgrading HexVault schema to image schema version ${SCHEMA_VERSION}"
  set +e
  run_as_service "${INSTALL_PATH}/vault_server" \
    -f "$CONFIG_FILE" -d "$DATA_PATH" --upgrade-schema
  state=$?
  if [[ "$state" -eq 0 ]]; then
    sqlite_schema_state "$DB_FILE"
    state=$?
  fi
  set -e
  if [[ "$state" -ne 0 ]]; then
    warn "Schema upgrade failed validation; restoring the trusted pre-upgrade transaction"
    restore_schema_upgrade_transaction
    clear_schema_upgrade_transaction
    die "Schema upgrade failed; original SQLite database and identity were restored"
  fi
  write_schema_version
  clear_schema_upgrade_transaction
  log "Schema upgrade completed"
}

ensure_schema_and_admin() {
  local state user_state
  validate_data_namespace "$DATA_PATH" live
  set +e
  sqlite_schema_state "$DB_FILE"
  state=$?
  set -e
  case "$state" in
    0)
      upgrade_schema_if_needed
      log "Existing SQLite schema verified; recreate and admin reset skipped"
      ;;
    1)
      data_has_meaningful_content && \
        die "SQLite schema is empty but the data directory is not; refusing destructive initialization"
      [[ -n "$VAULT_PASSWORD" ]] \
        || die "VAULT_PASSWORD is required only for initial schema creation"
      write_schema_recreate_marker
      log "Recreating a fresh HexVault schema"
      if ! run_as_service "${INSTALL_PATH}/vault_server" \
          -f "$CONFIG_FILE" -d "$DATA_PATH" --recreate-schema; then
        discard_failed_initial_schema
        die "Schema recreation failed; partial fresh database was removed"
      fi
      if ! sqlite_schema_state "$DB_FILE"; then
        discard_failed_initial_schema
        die "Schema recreation did not create a valid users schema"
      fi
      set +e
      vault_user_exists "$DB_FILE" hexvault
      user_state=$?
      set -e
      case "$user_state" in
        0) ;;
        1)
          discard_failed_initial_schema
          die "Schema was recreated, but required user 'hexvault' does not exist; refusing --set-admin" ;;
        *)
          discard_failed_initial_schema
          die "Could not verify user 'hexvault' in the recreated users table" ;;
      esac
      # Deliberately adjacent to --recreate-schema: there is no independent admin lock.
      log "Promoting freshly created user 'hexvault' to admin"
      if ! run_as_service "${INSTALL_PATH}/vault_server" \
          --config-file "$CONFIG_FILE" --set-admin "hexvault:${VAULT_PASSWORD}"; then
        discard_failed_initial_schema
        die "Admin initialization failed; partial fresh database was removed"
      fi
      sync
      write_schema_version
      rm -f -- "$SCHEMA_RECREATE_MARKER"
      durable_sync_path "$RECOVERY_PATH"
      log "Initial admin account 'hexvault' configured"
      ;;
    2) die "Existing SQLite database is unreadable; refusing destructive recreation" ;;
  esac
  unset VAULT_PASSWORD
}

periodic_sync_loop() {
  trap - EXIT TERM INT
  while sleep "$SYNC_INTERVAL_SECONDS"; do
    log "Starting periodic consistent sync"
    set +e
    ( set -Eeuo pipefail; CLEANUP_FILES=(); CLEANUP_DIRS=(); \
      trap cleanup EXIT; perform_sync publish )
    local sync_status=$?
    set -e
    [[ "$sync_status" -eq 0 ]] && log "Periodic sync completed" || \
      warn "Periodic sync failed; server remains running"
  done
}

SYNC_WORKER_PID=""

launch_sync_worker() {
  local mode="$1"
  command -v setsid >/dev/null 2>&1 || die "setsid is required for isolated sync workers"
  [[ "$ENTRYPOINT_SCRIPT" == /entrypoint.sh && -x "$ENTRYPOINT_SCRIPT" ]] \
    || die "Unexpected entrypoint path for sync worker"
  SYNC_AUTH_TOKEN="$SYNC_AUTH_TOKEN" \
  SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
  GH_SSH_PRIVATE_KEY="$GH_SSH_PRIVATE_KEY" \
  GH_KNOWN_HOSTS="$GH_KNOWN_HOSTS" \
    setsid "$ENTRYPOINT_SCRIPT" "$mode" &
  SYNC_WORKER_PID=$!
}

terminate_sync_worker_group() {
  local worker_pid="$1" watchdog timeout_marker
  [[ "$worker_pid" =~ ^[1-9][0-9]*$ ]] || return 0
  timeout_marker="$(mktemp /run/hexvault-worker-stop.XXXXXX)"
  cleanup_add_file "$timeout_marker"
  rm -f -- "$timeout_marker"
  kill -TERM -- "-$worker_pid" 2>/dev/null || true
  (
    sleep 10
    printf 'timeout\n' >"$timeout_marker"
    kill -KILL -- "-$worker_pid" 2>/dev/null || true
  ) &
  watchdog=$!
  wait "$worker_pid" 2>/dev/null || true
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [[ -e "$timeout_marker" ]]; then
    warn "Sync worker did not stop within 10s and its process group was killed"
  fi
  rm -f -- "$timeout_marker"
  cleanup_remove_file "$timeout_marker"
}

wait_sync_worker_with_deadline() {
  local worker_pid="$1" deadline="$2" watchdog timeout_marker status
  timeout_marker="$(mktemp /run/hexvault-sync-timeout.XXXXXX)"
  cleanup_add_file "$timeout_marker"
  rm -f -- "$timeout_marker"
  (
    sleep "$deadline"
    printf 'timeout\n' >"$timeout_marker"
    kill -TERM -- "-$worker_pid" 2>/dev/null || exit 0
    sleep 10
    kill -KILL -- "-$worker_pid" 2>/dev/null || true
  ) &
  watchdog=$!
  set +e
  wait "$worker_pid"
  status=$?
  set -e
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [[ -e "$timeout_marker" ]]; then
    warn "Sync worker exceeded its ${deadline}s overall deadline"
    status=124
  fi
  rm -f -- "$timeout_marker"
  cleanup_remove_file "$timeout_marker"
  return "$status"
}

perform_startup_sync() {
  local state sync_status
  [[ "${SYNC_ENABLED,,}" == true ]] || return 0
  set +e
  sqlite_schema_state "$DB_FILE"
  state=$?
  set -e

  if [[ "$state" -eq 0 && "${SYNC_FORCE_RESTORE,,}" == false ]]; then
    set +e
    (
      set -Eeuo pipefail
      CLEANUP_FILES=()
      CLEANUP_DIRS=()
      trap cleanup EXIT
      perform_sync startup
    )
    sync_status=$?
    set -e
    if [[ "$sync_status" -ne 0 ]]; then
      warn "Startup sync failed, but the local SQLite schema is valid; starting and retrying later"
    fi
    return 0
  fi

  # Empty/invalid local state and explicit force-restore requests must resolve
  # the remote before schema initialization can proceed.
  perform_sync startup
}

perform_publish_best_effort() {
  local reason="$1" status
  set +e
  (
    set -Eeuo pipefail
    CLEANUP_FILES=()
    CLEANUP_DIRS=()
    trap cleanup EXIT
    perform_sync publish
  )
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    warn "$reason sync failed; it will be retried while the server remains available"
  else
    log "$reason sync completed"
  fi
  return 0
}

cleanup_stale_runtime_artifacts() {
  local unsafe
  [[ "$INSTALL_PATH" == /opt/hexvault && "$DATA_PATH" == /opt/hexvault/data && \
     "$CONFIG_PATH" == /opt/hexvault/config && \
     "$RECOVERY_PATH" == /opt/hexvault/recovery ]] \
    || die "Refusing stale-artifact cleanup for unexpected paths"
  find "$INSTALL_PATH" -mindepth 1 -maxdepth 1 \
    \( -name '_pack.*' -o -name '_payload.*' -o -name '_restore.*' \
       -o -name '_restore_commit.*' -o -name '_verify_commit.*' \
       -o -name '_release.*' -o -name '_db-before.*' -o -name '_db-after.*' \
       -o -name "$ARCHIVE_NAME" \) \
    -exec rm -rf -- {} +
  find "$DATA_PATH" -mindepth 1 -maxdepth 1 -type f \
    -name '.hexvault.rollback.*.sqlite3' -delete
  unsafe="$(find "$RECOVERY_PATH" -mindepth 1 -maxdepth 1 \
    \( -name '.hexvault-schema.*.tmp' \
       -o -name '.hexvault.preupgrade.*.tmp' \
       -o -name '.restore-in-progress.*.tmp' \
       -o -name '.tls-rotation-in-progress.*.tmp' \
       -o -name '.schema-recreate-in-progress.*.tmp' \) \
    ! -type f ! -type l -print -quit)"
  [[ -z "$unsafe" ]] || die "Unsafe recovery staging entry: $unsafe"
  find "$RECOVERY_PATH" -mindepth 1 -maxdepth 1 \
    \( -name '.hexvault-schema.*.tmp' \
       -o -name '.hexvault.preupgrade.*.tmp' \
       -o -name '.restore-in-progress.*.tmp' \
       -o -name '.tls-rotation-in-progress.*.tmp' \
       -o -name '.schema-recreate-in-progress.*.tmp' \) \
    \( -type f -o -type l \) -delete
  unsafe="$(find "$CONFIG_PATH" -mindepth 1 -maxdepth 1 \
    -name '.hexvault.conf.*.tmp' ! -type f ! -type l -print -quit)"
  [[ -z "$unsafe" ]] || die "Unsafe config staging entry: $unsafe"
  find "$CONFIG_PATH" -mindepth 1 -maxdepth 1 \
    -name '.hexvault.conf.*.tmp' \( -type f -o -type l \) -delete
  durable_sync_path "$INSTALL_PATH"
  durable_sync_path "$DATA_PATH"
  durable_sync_path "$RECOVERY_PATH"
  durable_sync_path "$CONFIG_PATH"
}

cleanup_stale_run_artifacts() {
  local unsafe stale
  local -a private_dirs=(
    /run/hexvault-sync-ssh
    /run/hexvault-git-auth
    "$SYNC_GNUPG_HOME"
  )
  [[ "$SYNC_GNUPG_HOME" == /run/hexvault-sync-gnupg ]] \
    || die "Refusing /run cleanup for unexpected GnuPG path"
  unsafe="$(find /run -xdev -mindepth 1 -maxdepth 1 \
    \( -name 'hexvault-github-headers.*' \
       -o -name 'hexvault-download-headers.*' \
       -o -name 'hexvault-api-headers.*' \
       -o -name 'hexvault-upload-headers.*' \
       -o -name 'hexvault-upload-body.*' \
       -o -name 'hexvault-curl-status.*' \
       -o -name 'hexvault-release-verify.*' \
       -o -name 'hexvault-openssl.*.cnf' \
       -o -name 'hexvault-sync-timeout.*' \
       -o -name 'hexvault-worker-stop.*' \
       -o -name 'hexvault-sync.lock' \) \
    ! -type f ! -type l -print -quit)"
  [[ -z "$unsafe" ]] || die "Unsafe stale HexVault /run entry: $unsafe"
  find /run -xdev -mindepth 1 -maxdepth 1 \
    \( -name 'hexvault-github-headers.*' \
       -o -name 'hexvault-download-headers.*' \
       -o -name 'hexvault-api-headers.*' \
       -o -name 'hexvault-upload-headers.*' \
       -o -name 'hexvault-upload-body.*' \
       -o -name 'hexvault-curl-status.*' \
       -o -name 'hexvault-release-verify.*' \
       -o -name 'hexvault-openssl.*.cnf' \
       -o -name 'hexvault-sync-timeout.*' \
       -o -name 'hexvault-worker-stop.*' \
       -o -name 'hexvault-sync.lock' \) \
    \( -type f -o -type l \) -delete
  unsafe="$(find /run -xdev -mindepth 1 -maxdepth 1 \
    -name 'hexvault-curl-headers.*' ! -type d ! -type l -print -quit)"
  [[ -z "$unsafe" ]] || die "Unsafe stale HexVault header-stream path: $unsafe"
  find /run -xdev -mindepth 1 -maxdepth 1 \
    -name 'hexvault-curl-headers.*' \( -type d -o -type l \) \
    -exec rm -rf -- {} +
  for stale in "${private_dirs[@]}"; do
    if [[ -e "$stale" || -L "$stale" ]]; then
      [[ -d "$stale" || -L "$stale" ]] \
        || die "Unsafe stale HexVault private path: $stale"
      rm -rf -- "$stale"
    fi
  done
  durable_sync_path /run
}

supervise_server() {
  local app_pid sync_pid="" final_pid="" status=0 stopping=false final_sync_status
  local -a command=(
    "${INSTALL_PATH}/vault_server" -f "$CONFIG_FILE" -p "$VAULT_PORT"
    -l /dev/stdout -c "${CONFIG_PATH}/hexvault.crt"
    -k "${CONFIG_PATH}/hexvault.key" -L "${INSTALL_PATH}/teams_server.hexlic"
    -d "$DATA_PATH"
  )
  (
    local uid gid
    uid="$(id -u "$SERVICE_USER")"; gid="$(id -g "$SERVICE_USER")"
    exec setpriv --reuid "$uid" --regid "$gid" --init-groups \
      --inh-caps=-all --ambient-caps=-all \
      env -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
        -u GH_SSH_PRIVATE_KEY -u GIT_SSH_COMMAND \
        HOME=/var/lib/hexvault USER="$SERVICE_USER" LOGNAME="$SERVICE_USER" \
        XDG_DATA_HOME=/var/lib/hexvault/.local/share \
        XDG_CONFIG_HOME=/var/lib/hexvault/.config "${command[@]}"
  ) &
  app_pid=$!
  log "Started vault_server as ${SERVICE_USER} (pid=$app_pid, port=$VAULT_PORT)"
  if sync_can_write && ((10#$SYNC_INTERVAL_SECONDS > 0)); then
    launch_sync_worker __periodic-sync
    sync_pid="$SYNC_WORKER_PID"
    log "Started periodic sync in isolated process group $sync_pid"
  fi
  request_stop() {
    stopping=true
    log "Forwarding shutdown signal to vault_server"
    kill -TERM "$app_pid" 2>/dev/null || true
  }
  trap request_stop TERM INT
  while :; do
    set +e
    wait "$app_pid"
    local wait_status=$?
    set -e
    if kill -0 "$app_pid" 2>/dev/null; then
      continue
    fi
    status="$wait_status"
    break
  done
  trap - TERM INT
  if [[ -n "$sync_pid" ]]; then
    terminate_sync_worker_group "$sync_pid"
  fi
  if sync_can_write && [[ "$stopping" == true ]]; then
    log "Creating bounded final snapshot after explicit graceful shutdown"
    launch_sync_worker __publish-once
    final_pid="$SYNC_WORKER_PID"
    set +e
    wait_sync_worker_with_deadline "$final_pid" "$SYNC_FINAL_TIMEOUT_SECONDS"
    final_sync_status=$?
    set -e
    [[ "$final_sync_status" -eq 0 ]] || warn "Final shutdown sync failed"
  elif sync_can_write; then
    warn "vault_server exited without an explicit graceful signal; final sync skipped"
  fi
  [[ "$stopping" == true ]] && return 0
  return "$status"
}

main() {
  local service_uid service_gid runtime_dir config_temporary
  validate_configuration
  id -u "$SERVICE_USER" >/dev/null 2>&1 || die "Service user $SERVICE_USER is missing"
  service_uid="$(id -u "$SERVICE_USER")"; service_gid="$(id -g "$SERVICE_USER")"
  [[ "$INSTALL_PATH" == /opt/hexvault ]] || die "Unexpected install path"
  for runtime_dir in "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH" \
      "$RECOVERY_PATH" "$KEYRING_PATH"; do
    ensure_runtime_directory "$runtime_dir"
  done

  # Harden parent directories before any root-owned temp/marker write. find does
  # not follow symlinks, so untrusted entries in bind mounts are never traversed.
  chown "root:$service_gid" "$CONFIG_PATH"
  chmod 750 "$CONFIG_PATH"
  find "$CONFIG_PATH" -xdev -type d -exec chown "root:$service_gid" -- {} + \
    -exec chmod 750 -- {} +
  find "$CONFIG_PATH" -xdev -type f -exec chown "root:$service_gid" -- {} +
  chown root:root "$RECOVERY_PATH"
  chmod 700 "$RECOVERY_PATH"
  chown -R --no-dereference "$service_uid:$service_gid" \
    "$LOGS_PATH" "$DATA_PATH" "$KEYRING_PATH"

  cleanup_stale_run_artifacts
  cleanup_stale_runtime_artifacts
  # Restore rollback owns both data and the canonical schema identity. It must
  # run before schema-upgrade/recreate recovery and before any remote access.
  recover_interrupted_restore
  recover_interrupted_schema_upgrade
  recover_interrupted_schema_recreate

  CONFIG_FILE="${CONFIG_PATH}/hexvault.conf"
  if [[ -e "$CONFIG_FILE" || -L "$CONFIG_FILE" ]]; then
    path_is_safe_regular_file "$CONFIG_FILE" \
      || die "HexVault config path must be a regular non-symlink file"
  else
    config_temporary="$(mktemp "${CONFIG_PATH}/.hexvault.conf.XXXXXX.tmp")"
    cleanup_add_file "$config_temporary"
    printf 'sqlite3;Data Source=%s;\n' "$DB_FILE" >"$config_temporary"
    chown "root:$service_gid" "$config_temporary"
    chmod 640 "$config_temporary"
    durable_sync_path "$config_temporary"
    mv -f -- "$config_temporary" "$CONFIG_FILE"
    cleanup_remove_file "$config_temporary"
    durable_sync_path "$CONFIG_PATH"
  fi
  [[ "$(read_single_line_file "$CONFIG_FILE")" == "sqlite3;Data Source=${DB_FILE};" ]] \
    || die "HexVault config must use the expected SQLite database: $DB_FILE"
  path_is_safe_regular_file "${CA_PATH}/CA.pem" && \
    path_is_safe_regular_file "$CA_KEY_FILE" \
    || die "Stock HexVault Compose requires regular CA/CA.pem and CA/CA.key files"

  log "Applying runtime patch"
  env -u VAULT_PASSWORD -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY python3 "${INSTALL_PATH}/license_patch.py" hexvault-940 \
    || die "Patch failed"
  path_is_safe_regular_file "${INSTALL_PATH}/vault_server" \
    || die "vault_server is missing or unsafe after patching"
  path_is_safe_regular_file "${INSTALL_PATH}/teams_server.hexlic" \
    || die "teams_server.hexlic is missing or unsafe"
  chown root:root "${INSTALL_PATH}/vault_server"
  chmod 755 "${INSTALL_PATH}/vault_server"
  ensure_tls_certificate
  chown "root:$service_gid" "$CONFIG_FILE" "$TLS_CERT" "$TLS_KEY" \
    "${INSTALL_PATH}/teams_server.hexlic"
  chmod 640 "$CONFIG_FILE" "$TLS_CERT" "$TLS_KEY" \
    "${INSTALL_PATH}/teams_server.hexlic"
  ensure_secret_service_bus
  perform_startup_sync
  # SYNC_FORCE_RESTORE is a one-shot startup override.
  SYNC_FORCE_RESTORE=false
  ensure_schema_and_admin
  commit_restore_transaction
  if sync_can_write; then
    perform_publish_best_effort "Post-schema"
  fi
  supervise_server
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    __periodic-sync) validate_configuration; periodic_sync_loop ;;
    __publish-once) validate_configuration; perform_sync publish ;;
    *) main "$@" ;;
  esac
fi
