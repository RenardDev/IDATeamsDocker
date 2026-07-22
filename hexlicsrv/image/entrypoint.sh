#!/bin/bash

set -Eeuo pipefail
shopt -s nullglob
umask 077

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

cleanup() {
  set +e
  local file dir
  for file in "${CLEANUP_FILES[@]:-}"; do
    [[ -n "$file" && -f "$file" ]] && rm -f -- "$file"
  done
  for dir in "${CLEANUP_DIRS[@]:-}"; do
    [[ -n "$dir" && -d "$dir" ]] && rm -rf -- "$dir"
  done
}
trap cleanup EXIT

now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] %s\n' "$(now_utc)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(now_utc)" "$*" >&2; }
die() { printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2; exit 1; }

LICENSE_HOST="${LICENSE_HOST:-localhost}"
LICENSE_PORT="${LICENSE_PORT:-65434}"
LICENSE_HOST_KIND=""

SYNC_ENABLED="${SYNC_ENABLED:-false}"
SYNC_READ_ONLY="${SYNC_READ_ONLY:-false}"
SYNC_METHOD="${SYNC_METHOD:-commits}"
SYNC_AUTH_TOKEN="${SYNC_AUTH_TOKEN:-}"
SYNC_ENCRYPTION_PASSPHRASE="${SYNC_ENCRYPTION_PASSPHRASE:-}"
SYNC_FORCE_RESTORE="${SYNC_FORCE_RESTORE:-false}"
SYNC_HOST_ID="${SYNC_HOST_ID:-hexlicsrv}"
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
GH_COMMIT_NAME="${GH_COMMIT_NAME:-HexLicSrv CI}"
GH_COMMIT_EMAIL="${GH_COMMIT_EMAIL:-hexlicsrv@example.com}"
GH_SSH_PRIVATE_KEY="${GH_SSH_PRIVATE_KEY:-}"
GH_KNOWN_HOSTS="${GH_KNOWN_HOSTS:-}"
GH_RELEASE_TAG="${GH_RELEASE_TAG:-hexlicsrv}"
GH_RELEASE_NAME="${GH_RELEASE_NAME:-HexLicSrv}"
GH_API="${GH_API:-}"
GH_UPLOAD="${GH_UPLOAD:-}"

# Keep sync credentials as shell-only state. Explicit sync workers receive the
# minimum required secret environment; unrelated root/vendor helpers do not.
export -n SYNC_AUTH_TOKEN SYNC_ENCRYPTION_PASSPHRASE GH_SSH_PRIVATE_KEY

INSTALL_PATH="/opt/hexlicsrv"
CA_PATH="${INSTALL_PATH}/CA"
CA_KEY_FILE="/run/hexlicsrv-ca-key/CA.key"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"
DB_FILE="${DATA_PATH}/hexlicsrv.sqlite3"
DB_CONNECTION="sqlite3;Data Source=${DB_FILE};"
SCHEMA_VERSION="940"
RECOVERY_PATH="${INSTALL_PATH}/recovery"
SCHEMA_MARKER="${RECOVERY_PATH}/schema-state.json"
SNAPSHOT_SCHEMA_MARKER_NAME=".hexlicsrv-schema-state.json"
ROLLBACK_SCHEMA_MARKER_NAME="original-schema-state.json"
SCHEMA_INIT_MARKER="${RECOVERY_PATH}/.schema-initializing"
SCHEMA_UPGRADE_BACKUP="${RECOVERY_PATH}/.preupgrade.sqlite3"
SCHEMA_UPGRADE_MARKER_BACKUP="${RECOVERY_PATH}/.preupgrade-schema-state.json"
KEYRING_PATH="/var/lib/hexlicsrv/.local/share/keyrings"
RESTORE_MARKER="${RECOVERY_PATH}/restore-in-progress.json"
SERVICE_USER="hexlicsrv"

WORK_DIR="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${WORK_DIR}/backups/${SYNC_HOST_ID}"
ARCHIVE_NAME="data.tar.zst.gpg"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"
RELEASE_NAMESPACE="hexlicsrv--${SYNC_HOST_ID}--"

PACK_SIZE=""
PACK_SHA=""
PACK_PAYLOAD_SHA=""
PACK_ENCRYPTION=""
PACK_ARCHIVE_HMAC=""
PACK_SCHEMA_FINGERPRINT=""

MANIFEST_ARCHIVE_NAME=""
MANIFEST_ARCHIVE_SIZE=""
MANIFEST_ARCHIVE_SHA=""
MANIFEST_PAYLOAD_SHA=""
MANIFEST_CHUNK_COUNT=""
MANIFEST_ENCRYPTION=""
MANIFEST_ASSET_PREFIX=""
MANIFEST_SNAPSHOT_ID=""
MANIFEST_SCHEMA_VERSION="0"
MANIFEST_SCHEMA_FINGERPRINT=""

LOADED_SCHEMA_VERSION=""
LOADED_SCHEMA_FINGERPRINT=""
RESTORE_TRANSACTION_ROLLBACK=""
RESTORE_TRANSACTION_ORIGINAL_STATE=""
RESTORE_TRANSACTION_ORIGINAL_MARKER_PRESENT=""

validate_bool() {
  local name="$1" value="${2,,}"
  [[ "$value" == "true" || "$value" == "false" ]] \
    || die "$name must be 'true' or 'false'"
}

validate_uint_range() {
  local name="$1" value="$2" min="$3" max="$4"
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die "$name must be an integer"
  ((10#$value >= min && 10#$value <= max)) \
    || die "$name must be between $min and $max"
}

gh_remote_is_ssh() {
  [[ "$GH_REMOTE" =~ ^ssh:// || \
     "$GH_REMOTE" =~ ^[^@[:space:]]+@[^:[:space:]]+:.+$ ]]
}

validate_sync_url_values() {
  python3 - "$GH_REMOTE" "$GH_API" "$GH_UPLOAD" <<'PY'
import re
import sys
import urllib.parse

remote, api, upload = sys.argv[1:]
for value in (remote, api, upload):
    if "\\" in value or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        raise SystemExit(1)

scp = re.fullmatch(r"([A-Za-z0-9_.-]+)@([^:\s]+):([^\s]+)", remote)
if scp is not None:
    remote_scheme = "ssh"
    remote_host = scp.group(2).lower()
    remote_path = scp.group(3)
    remote_port = None
    remote_api_port = 443
else:
    parsed = urllib.parse.urlsplit(remote)
    if parsed.scheme not in ("https", "ssh") or not parsed.hostname:
        raise SystemExit(1)
    if (
        parsed.password is not None
        or (parsed.scheme == "https" and parsed.username is not None)
        or (
            parsed.scheme == "ssh"
            and parsed.username is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+", parsed.username) is None
        )
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit(1)
    try:
        remote_port = parsed.port
        if remote_port == 0:
            raise SystemExit(1)
    except ValueError:
        raise SystemExit(1)
    remote_scheme = parsed.scheme
    remote_host = parsed.hostname.lower()
    remote_path = parsed.path.lstrip("/")
    remote_api_port = (remote_port or 443) if remote_scheme == "https" else 443

host_label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
if (
    len(remote_host) > 253
    or remote_host.endswith(".")
    or any(host_label.fullmatch(label) is None for label in remote_host.split("."))
):
    raise SystemExit(1)

if remote_path.endswith(".git"):
    remote_path = remote_path[:-4]
parts = remote_path.split("/")
safe_component = re.compile(r"[A-Za-z0-9_.-]+")
if (
    len(parts) != 2
    or any(safe_component.fullmatch(part) is None for part in parts)
    or any(part in (".", "..") for part in parts)
):
    raise SystemExit(1)
if remote_host == "github.com" and remote_scheme == "https" and remote_port not in (None, 443):
    raise SystemExit(1)

for endpoint, public_host, enterprise_path in (
    (api, "api.github.com", "/api/v3"),
    (upload, "uploads.github.com", "/api/uploads"),
):
    if not endpoint:
        continue
    parsed = urllib.parse.urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError:
        raise SystemExit(1)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise SystemExit(1)
    endpoint_host = parsed.hostname.lower()
    endpoint_port = port or 443
    if remote_host == "github.com":
        if (
            endpoint_host != public_host
            or endpoint_port != 443
            or parsed.path not in ("", "/")
        ):
            raise SystemExit(1)
    elif (
        endpoint_host != remote_host
        or endpoint_port != remote_api_port
        or parsed.path not in (enterprise_path, enterprise_path + "/")
    ):
        raise SystemExit(1)
PY
}

classify_license_host() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys

host = sys.argv[1]
if not host or len(host) > 253 or host.endswith(".") or "%" in host:
    raise SystemExit(1)

try:
    ipaddress.ip_address(host)
except ValueError:
    # A value that looks like a malformed numeric address must not silently
    # become a DNS SAN. IPv6 literals are accepted by ipaddress above.
    if re.fullmatch(r"[0-9.]+", host) or ":" in host:
        raise SystemExit(1)
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        raise SystemExit(1)
    label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    labels = host.split(".")
    if not labels or any(label.fullmatch(part) is None for part in labels):
        raise SystemExit(1)
    print("dns")
else:
    print("ip")
PY
}

validate_configuration() {
  validate_bool SYNC_ENABLED "$SYNC_ENABLED"
  validate_bool SYNC_READ_ONLY "$SYNC_READ_ONLY"
  validate_bool SYNC_FORCE_RESTORE "$SYNC_FORCE_RESTORE"
  if [[ "${SYNC_FORCE_RESTORE,,}" == true && "${SYNC_ENABLED,,}" == false ]]; then
    die "SYNC_FORCE_RESTORE=true requires SYNC_ENABLED=true"
  fi
  validate_uint_range LICENSE_PORT "$LICENSE_PORT" 1024 65535

  LICENSE_HOST_KIND="$(classify_license_host "$LICENSE_HOST")" \
    || die "LICENSE_HOST must be a valid DNS name or IP address"
  [[ "$LICENSE_HOST_KIND" == dns || "$LICENSE_HOST_KIND" == ip ]] \
    || die "Could not classify LICENSE_HOST"
  [[ "$SYNC_HOST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
    || die "SYNC_HOST_ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
  validate_uint_range SYNC_CHUNK_SIZE_MB "$SYNC_CHUNK_SIZE_MB" 1 49
  validate_uint_range SYNC_INTERVAL_SECONDS "$SYNC_INTERVAL_SECONDS" 0 2147483647
  if ((10#$SYNC_INTERVAL_SECONDS > 0 && 10#$SYNC_INTERVAL_SECONDS < 60)); then
    die "SYNC_INTERVAL_SECONDS must be 0 or at least 60"
  fi
  validate_uint_range SYNC_NETWORK_TIMEOUT_SECONDS "$SYNC_NETWORK_TIMEOUT_SECONDS" 10 3600
  validate_uint_range SYNC_LOCK_TIMEOUT_SECONDS "$SYNC_LOCK_TIMEOUT_SECONDS" 1 3600
  validate_uint_range SYNC_FINAL_TIMEOUT_SECONDS "$SYNC_FINAL_TIMEOUT_SECONDS" 30 540
  validate_uint_range SYNC_RELEASE_KEEP "$SYNC_RELEASE_KEEP" 1 20
  validate_uint_range SYNC_MAX_RESTORE_MB "$SYNC_MAX_RESTORE_MB" 1 1048576
  validate_uint_range SYNC_MAX_EXTRACT_MB "$SYNC_MAX_EXTRACT_MB" 1 1048576

  case "${SYNC_METHOD,,}" in
    commits|releases) ;;
    *) die "SYNC_METHOD must be 'commits' or 'releases'" ;;
  esac

  [[ "$GH_BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$ && \
     "$GH_BRANCH" != *..* && "$GH_BRANCH" != *//* && "$GH_BRANCH" != */ && \
     "$GH_BRANCH" != *.lock ]] || die "GH_BRANCH is not a safe branch name"
  [[ -n "$GH_RELEASE_TAG" && "$GH_RELEASE_TAG" != *$'\n'* && "$GH_RELEASE_TAG" != *$'\r'* ]] \
    || die "GH_RELEASE_TAG is invalid"
  [[ "$GH_COMMIT_NAME" != *$'\n'* && "$GH_COMMIT_NAME" != *$'\r'* && \
     "$GH_COMMIT_EMAIL" != *$'\n'* && "$GH_COMMIT_EMAIL" != *$'\r'* ]] \
    || die "Git commit identity must not contain line breaks"
  [[ "$SYNC_AUTH_TOKEN" != *[[:cntrl:]]* ]] \
    || die "SYNC_AUTH_TOKEN must not contain control characters"
  [[ "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\n'* && \
     "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\r'* ]] \
    || die "SYNC_ENCRYPTION_PASSPHRASE must not contain line breaks"
  if [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" && \
        ${#SYNC_ENCRYPTION_PASSPHRASE} -lt 20 ]]; then
    die "SYNC_ENCRYPTION_PASSPHRASE must contain at least 20 characters"
  fi
  [[ ! "$GH_REMOTE" =~ ^https?://[^/]*@ ]] \
    || die "GH_REMOTE must not contain URL credentials; use SYNC_AUTH_TOKEN"
  if [[ "${SYNC_ENABLED,,}" == true ]]; then
    [[ -n "$GH_REMOTE" ]] || die "SYNC_ENABLED=true requires GH_REMOTE"
    [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
      || die "SYNC_ENABLED=true requires SYNC_ENCRYPTION_PASSPHRASE"
    validate_sync_url_values \
      || die "GH_REMOTE/GH_API/GH_UPLOAD contain an invalid or unsafe URL"
    case "${SYNC_METHOD,,}" in
      releases)
        [[ "$GH_REMOTE" =~ ^https:// ]] || gh_remote_is_ssh \
          || die "Releases sync requires an HTTPS or SSH GitHub remote"
        if [[ "${SYNC_READ_ONLY,,}" == false ]]; then
          [[ -n "$SYNC_AUTH_TOKEN" ]] \
            || die "Writable releases sync requires SYNC_AUTH_TOKEN"
        fi
        ;;
      commits)
        if [[ "$GH_REMOTE" =~ ^https:// ]]; then
          if [[ "${SYNC_READ_ONLY,,}" == false ]]; then
            [[ -n "$SYNC_AUTH_TOKEN" ]] \
              || die "Writable HTTPS commits sync requires SYNC_AUTH_TOKEN"
          fi
        elif gh_remote_is_ssh; then
          [[ -n "$GH_SSH_PRIVATE_KEY" ]] \
            || die "SSH commits sync requires GH_SSH_PRIVATE_KEY"
          [[ -n "$GH_KNOWN_HOSTS" ]] \
            || die "SSH commits sync requires pinned GH_KNOWN_HOSTS"
        else
          die "Commits sync requires an HTTPS or SSH GitHub remote"
        fi
        ;;
    esac
  fi
}

ensure_secret_service_bus() {
  local machine_id_file="/etc/machine-id"
  local dbus_machine_id_file="/var/lib/dbus/machine-id"
  local service_uid service_gid default_bus_address bus_socket=""
  local health_id health_secret health_read
  local -a bus_info=()
  local -a service_identity_env=(
    "HOME=/var/lib/hexlicsrv"
    "USER=${SERVICE_USER}"
    "LOGNAME=${SERVICE_USER}"
    "XDG_DATA_HOME=/var/lib/hexlicsrv/.local/share"
    "XDG_CONFIG_HOME=/var/lib/hexlicsrv/.config"
  )

  service_uid="$(id -u "$SERVICE_USER")"
  service_gid="$(id -g "$SERVICE_USER")"
  default_bus_address="unix:path=/run/hexlicsrv-dbus/session-bus"
  unset DISPLAY WAYLAND_DISPLAY || true

  mkdir -p /var/lib/dbus /run/hexlicsrv-dbus "/run/user/${service_uid}" "$KEYRING_PATH"
  if [[ ! -s "$machine_id_file" ]]; then
    rm -f -- "$machine_id_file"
    dbus-uuidgen --ensure="$machine_id_file" \
      || die "Failed to generate D-Bus machine-id"
  fi
  [[ ! -d "$dbus_machine_id_file" || -L "$dbus_machine_id_file" ]] \
    || die "D-Bus machine-id path is an unexpected directory"
  ln -sfn "$machine_id_file" "$dbus_machine_id_file"

  export DBUS_SESSION_BUS_ADDRESS="$default_bus_address"
  export XDG_RUNTIME_DIR="/run/user/${service_uid}"
  chown "$service_uid:$service_gid" /run/hexlicsrv-dbus "$XDG_RUNTIME_DIR" "$KEYRING_PATH"
  chmod 700 /run/hexlicsrv-dbus "$XDG_RUNTIME_DIR" "$KEYRING_PATH"

  if ! timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
       -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
       "${service_identity_env[@]}" \
       DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
       XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
       dbus-send --bus="$DBUS_SESSION_BUS_ADDRESS" --type=method_call --print-reply \
       --dest=org.freedesktop.DBus /org/freedesktop/DBus \
       org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
    if [[ "$DBUS_SESSION_BUS_ADDRESS" == unix:path=/run/hexlicsrv-dbus/* ]]; then
      bus_socket="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
      bus_socket="${bus_socket%%,*}"
      rm -f -- "$bus_socket"
    fi

    mapfile -t bus_info < <(
      timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
        -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
        "${service_identity_env[@]}" \
        DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
        dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" \
          --fork --print-address=1 --print-pid=1
    )
    ((${#bus_info[@]} >= 2)) || die "Failed to start the D-Bus session bus"
    export DBUS_SESSION_BUS_ADDRESS="${bus_info[0]}"
    if [[ -n "$bus_socket" && -S "$bus_socket" ]]; then
      chown "$service_uid:$service_gid" "$bus_socket"
      chmod 600 "$bus_socket"
    fi
    log "Started D-Bus session bus (pid=${bus_info[1]})"
  fi

  printf '\n' | timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    gnome-keyring-daemon --unlock >/dev/null \
    || die "Failed to create/unlock the headless Secret Service keyring"

  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    gnome-keyring-daemon --start --components=secrets >/dev/null \
    || die "Failed to start the Secret Service"

  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    dbus-send --bus="$DBUS_SESSION_BUS_ADDRESS" --type=method_call --print-reply \
    --dest=org.freedesktop.secrets /org/freedesktop/secrets \
    org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1 \
    || die "Secret Service is not reachable through D-Bus"

  health_id="$(openssl rand -hex 12)"
  health_secret="$(openssl rand -hex 24)"
  printf '%s' "$health_secret" | timeout --kill-after=5s 20s \
    runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    secret-tool store --label='HexLicSrv secret-storage health check' \
      service hexlicsrv-health check "$health_id" >/dev/null \
    || die "Secret Service is reachable but not writable/unlocked"
  health_read="$(timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    secret-tool lookup service hexlicsrv-health check "$health_id")"
  [[ "$health_read" == "$health_secret" ]] \
    || die "Secret Service write/read health check failed"
  timeout --kill-after=5s 20s runuser -u "$SERVICE_USER" -- env \
    -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE -u GH_SSH_PRIVATE_KEY \
    "${service_identity_env[@]}" \
    DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
    XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
    secret-tool clear service hexlicsrv-health check "$health_id" >/dev/null \
    || warn "Could not remove Secret Service health-check item"
  log "Secret Service is writable as ${SERVICE_USER}"
}

data_has_meaningful_content() {
  local found
  found="$(find "$DATA_PATH" -mindepth 1 -type f -size +0c \
    ! -name '.gitignore' \
    ! -name "$SNAPSHOT_SCHEMA_MARKER_NAME" \
    ! -name '.hexlicsrv.restore.*' \
    ! -name '*.sqlite3-wal' \
    ! -name '*.sqlite3-shm' \
    ! -name '*.sqlite3-journal' \
    -print -quit 2>/dev/null || true)"
  [[ -n "$found" ]]
}

sqlite_schema_state() {
  local database="$1" count check
  if [[ -L "$database" || ( -e "$database" && ! -f "$database" ) ]]; then
    return 2
  fi
  if [[ ! -s "$database" ]]; then
    return 1
  fi
  if ! check="$(sqlite3 -readonly -cmd '.timeout 10000' "$database" \
      'PRAGMA quick_check;' 2>/dev/null)"; then
    return 2
  fi
  [[ "$check" == "ok" ]] || return 2
  if ! count="$(sqlite3 -readonly -cmd '.timeout 10000' "$database" \
      "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';" \
      2>/dev/null)"; then
    return 2
  fi
  [[ "$count" =~ ^[0-9]+$ ]] || return 2
  ((10#$count > 0)) && return 0
  # A non-empty SQLite file without application tables is not an empty target:
  # recreating it would be destructive and must require manual intervention.
  return 2
}

compute_schema_fingerprint() {
  local database="$1"
  [[ -f "$database" && ! -L "$database" && -s "$database" ]] || return 1
  python3 - "$database" <<'PY'
import hashlib
import json
import sqlite3
import sys
from urllib.parse import quote

path = sys.argv[1]
uri = "file:" + quote(path, safe="/") + "?mode=ro"
connection = sqlite3.connect(uri, uri=True, timeout=10)
try:
    connection.execute("PRAGMA query_only=ON")
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, COALESCE(sql, '')
          FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name, tbl_name, COALESCE(sql, '')
        """
    ).fetchall()
    document = {
        "application_id": connection.execute("PRAGMA application_id").fetchone()[0],
        "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
        "objects": [
            [kind, name, table, sql.replace("\r\n", "\n").rstrip()]
            for kind, name, table, sql in rows
        ],
    }
finally:
    connection.close()
canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
print(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
PY
}

load_schema_marker() {
  local marker="$1" marker_size
  [[ -f "$marker" && ! -L "$marker" ]] \
    || die "Schema marker is missing or unsafe: $marker"
  marker_size="$(stat -c '%s' "$marker")"
  [[ "$marker_size" =~ ^[0-9]+$ ]] && ((10#$marker_size > 0 && 10#$marker_size <= 4096)) \
    || die "Schema marker has an invalid size"
  jq -e 'type=="object" and (.format_version==1) and
    (.schema_version|type=="number" and floor==. and .>=1) and
    (.schema_fingerprint_sha256|type=="string" and test("^[0-9a-f]{64}$"))' \
    "$marker" >/dev/null || die "Schema marker is malformed"
  LOADED_SCHEMA_VERSION="$(jq -r '.schema_version' "$marker")"
  LOADED_SCHEMA_FINGERPRINT="$(jq -r '.schema_fingerprint_sha256' "$marker")"
  validate_uint_range schema_marker.schema_version "$LOADED_SCHEMA_VERSION" 1 2147483647
}

validate_schema_marker_against_database() {
  local marker="$1" database="$2" actual_fingerprint
  load_schema_marker "$marker"
  actual_fingerprint="$(compute_schema_fingerprint "$database")" \
    || die "Could not fingerprint SQLite schema"
  [[ "$actual_fingerprint" =~ ^[0-9a-f]{64}$ ]] \
    || die "SQLite schema fingerprint is malformed"
  [[ "$actual_fingerprint" == "$LOADED_SCHEMA_FINGERPRINT" ]] \
    || die "SQLite schema does not match its version marker"
}

compute_hmac_file() {
  local file="$1" context="$2"
  SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
  HEX_SYNC_HMAC_CONTEXT="$context" python3 - "$file" <<'PY'
import hashlib
import hmac
import os
import sys

secret = os.environ.get("SYNC_ENCRYPTION_PASSPHRASE", "").encode()
if not secret:
    raise SystemExit("missing sync passphrase")
context = os.environ["HEX_SYNC_HMAC_CONTEXT"].encode()
key = hashlib.pbkdf2_hmac("sha256", secret, b"hexlicsrv-sync-v3-hmac", 600_000, 32)
digest = hmac.new(key, context + b"|", hashlib.sha256)
with open(sys.argv[1], "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}

pack_payload() {
  local stage raw archive_hmac unsafe_entry database_state
  local staged_size max_extract_bytes max_restore_bytes chunk_count staged_marker
  set +e
  sqlite_schema_state "$DB_FILE"
  database_state=$?
  set -e
  [[ "$database_state" -eq 0 ]] \
    || die "Refusing to publish partial/invalid local state without a valid SQLite schema"
  validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
  [[ "$LOADED_SCHEMA_VERSION" == "$SCHEMA_VERSION" ]] \
    || die "Refusing to publish schema $LOADED_SCHEMA_VERSION from image schema $SCHEMA_VERSION"
  PACK_SCHEMA_FINGERPRINT="$LOADED_SCHEMA_FINGERPRINT"
  stage="$(mktemp -d "${INSTALL_PATH}/_pack.XXXXXX")"
  raw="$(mktemp "${INSTALL_PATH}/_payload.XXXXXX.tar.zst")"
  cleanup_add_dir "$stage"
  cleanup_add_file "$raw"

  if ! tar -C "$DATA_PATH" \
      --exclude='./.gitignore' \
      --exclude="./${SNAPSHOT_SCHEMA_MARKER_NAME}" \
      --exclude='./.hexlicsrv.restore.*' \
      --exclude="./$(basename "$DB_FILE")" \
      --exclude="./$(basename "$DB_FILE")-wal" \
      --exclude="./$(basename "$DB_FILE")-shm" \
      --exclude="./$(basename "$DB_FILE")-journal" \
      -cf - . | tar -C "$stage" --no-same-owner --no-same-permissions -xf -; then
    die "Could not stage filesystem data"
  fi

  rm -f -- "$stage/$(basename "$DB_FILE")"
  sqlite3 -readonly -cmd '.timeout 10000' "$DB_FILE" \
    ".backup '$stage/$(basename "$DB_FILE")'" \
    || die "Could not create a consistent SQLite backup"
  sqlite_schema_state "$stage/$(basename "$DB_FILE")" \
    || die "Consistent SQLite backup did not pass integrity/schema validation"
  staged_marker="$stage/$SNAPSHOT_SCHEMA_MARKER_NAME"
  cp -- "$SCHEMA_MARKER" "$staged_marker" \
    || die "Could not stage the trusted schema marker"
  chown root:root "$staged_marker"
  chmod 600 "$staged_marker"
  validate_schema_marker_against_database \
    "$staged_marker" "$stage/$(basename "$DB_FILE")"
  [[ "$LOADED_SCHEMA_VERSION" == "$SCHEMA_VERSION" && \
     "$LOADED_SCHEMA_FINGERPRINT" == "$PACK_SCHEMA_FINGERPRINT" ]] \
    || die "Consistent SQLite backup does not match the published schema identity"

  unsafe_entry="$(find "$stage" -mindepth 1 ! -type f ! -type d -print -quit)"
  [[ -z "$unsafe_entry" ]] \
    || die "Refusing to back up unsupported filesystem entry: $unsafe_entry"

  staged_size="$(du -sb --apparent-size --count-links "$stage" | awk '{print $1}')"
  [[ "$staged_size" =~ ^[0-9]+$ ]] || die "Could not determine staged snapshot size"
  max_extract_bytes=$((10#$SYNC_MAX_EXTRACT_MB * 1000000))
  ((10#$staged_size <= max_extract_bytes)) \
    || die "Local snapshot exceeds SYNC_MAX_EXTRACT_MB"

  log "Packing filesystem snapshot" >&2
  if ! tar -C "$stage" --sort=name --mtime=@0 --owner=0 --group=0 \
      --numeric-owner --hard-dereference -cf - . | zstd -q -T0 -19 -o "$raw"; then
    die "Failed to create the compressed payload"
  fi
  [[ -s "$raw" ]] || die "Compressed payload is empty"
  PACK_PAYLOAD_SHA="$(sha256sum "$raw" | awk '{print $1}')"

  rm -f -- "$ARCHIVE_PATH"
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Snapshot publication requires SYNC_ENCRYPTION_PASSPHRASE"
  gpg --no-options --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback \
    --passphrase-fd 3 --symmetric --cipher-algo AES256 --force-mdc \
    --s2k-digest-algo SHA512 --s2k-count 16777216 --compress-algo none \
    --output "$ARCHIVE_PATH" "$raw" 3<<<"$SYNC_ENCRYPTION_PASSPHRASE" \
    || die "Failed to encrypt the payload"
  PACK_ENCRYPTION="gpg-aes256-v1"

  PACK_SIZE="$(stat -c '%s' "$ARCHIVE_PATH")"
  max_restore_bytes=$((10#$SYNC_MAX_RESTORE_MB * 1000000))
  ((10#$PACK_SIZE <= max_restore_bytes)) \
    || die "Encrypted snapshot exceeds SYNC_MAX_RESTORE_MB"
  chunk_count=$(((10#$PACK_SIZE + 10#$SYNC_CHUNK_SIZE_MB * 1000000 - 1) / \
    (10#$SYNC_CHUNK_SIZE_MB * 1000000)))
  ((chunk_count >= 1 && chunk_count <= 10000)) \
    || die "Snapshot would require an unsupported number of chunks"
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

path = sys.argv[1]
limit = int(sys.argv[2]) * 1_000_000
total = 0
seen = set()
with tarfile.open(path, "r:") as archive:
    for entry_count, member in enumerate(archive, 1):
        if entry_count > 1_000_000:
            raise SystemExit("archive contains too many entries")
        name = member.name
        normalized = pathlib.PurePosixPath(name)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise SystemExit(f"unsafe archive path: {name!r}")
        canonical = normalized.as_posix()
        if canonical in seen:
            raise SystemExit(f"duplicate archive path: {name!r}")
        seen.add(canonical)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit(f"unsupported archive entry: {name!r}")
        total += max(member.size, 0)
        if total > limit:
            raise SystemExit("archive expands beyond SYNC_MAX_EXTRACT_MB")
PY
}

clear_data_contents() {
  [[ "$DATA_PATH" == "/opt/hexlicsrv/data" ]] || die "Refusing to clear unexpected DATA_PATH"
  find "$DATA_PATH" -mindepth 1 -maxdepth 1 ! -name '.gitignore' \
    -exec rm -rf -- {} +
}

write_restore_marker() {
  local rollback="$1" original_state="$2" original_marker_present="$3" tmp
  [[ "$original_marker_present" == true || "$original_marker_present" == false ]] \
    || die "Invalid original schema-marker state"
  [[ ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]] \
    || die "Restore transaction marker already exists"
  tmp="$(mktemp "${RECOVERY_PATH}/.restore-in-progress.XXXXXX")"
  cleanup_add_file "$tmp"
  jq -n --arg rollback "$(basename "$rollback")" \
    --argjson original_sqlite_state "$original_state" \
    --argjson original_schema_marker_present "$original_marker_present" \
    '{format_version:2,rollback:$rollback,
      original_sqlite_state:$original_sqlite_state,
      original_schema_marker_present:$original_schema_marker_present}' >"$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$RESTORE_MARKER"
  sync -f "$RESTORE_MARKER" "$RECOVERY_PATH" \
    || die "Could not durably record the restore transaction"
}

sqlite_state_matches() {
  local expected="$1" actual
  set +e
  sqlite_schema_state "$DB_FILE"
  actual=$?
  set -e
  [[ "$expected" -eq 2 || "$actual" -eq "$expected" ]]
}

load_restore_transaction() {
  local rollback_name marker_size rollback_marker marker_backup_size
  [[ -e "$RESTORE_MARKER" || -L "$RESTORE_MARKER" ]] || return 1
  [[ -f "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]] \
    || die "Unsafe restore transaction marker; manual recovery is required"
  marker_size="$(stat -c '%s' "$RESTORE_MARKER")"
  [[ "$marker_size" =~ ^[0-9]+$ ]] && ((10#$marker_size > 0 && 10#$marker_size <= 4096)) \
    || die "Invalid restore transaction marker size"
  jq -e 'type=="object" and (.format_version==2) and (.rollback|type=="string") and
    (.original_sqlite_state|type=="number" and floor==. and .>=0 and .<=2) and
    (.original_schema_marker_present|type=="boolean")' \
    "$RESTORE_MARKER" >/dev/null \
    || die "Invalid restore transaction marker; preserving recovery state"
  rollback_name="$(jq -r '.rollback' "$RESTORE_MARKER")"
  RESTORE_TRANSACTION_ORIGINAL_STATE="$(jq -r '.original_sqlite_state' "$RESTORE_MARKER")"
  RESTORE_TRANSACTION_ORIGINAL_MARKER_PRESENT="$(jq -r \
    '.original_schema_marker_present' "$RESTORE_MARKER")"
  [[ "$rollback_name" =~ ^rollback\.[A-Za-z0-9]+\.dir$ ]] \
    || die "Unsafe rollback directory in restore transaction marker"
  RESTORE_TRANSACTION_ROLLBACK="${RECOVERY_PATH}/${rollback_name}"
  [[ -d "$RESTORE_TRANSACTION_ROLLBACK" && ! -L "$RESTORE_TRANSACTION_ROLLBACK" ]] \
    || die "Restore rollback directory is missing; preserving the transaction marker"
  [[ -d "$RESTORE_TRANSACTION_ROLLBACK/data" && \
     ! -L "$RESTORE_TRANSACTION_ROLLBACK/data" ]] \
    || die "Restore rollback data directory is missing or unsafe"
  rollback_marker="${RESTORE_TRANSACTION_ROLLBACK}/${ROLLBACK_SCHEMA_MARKER_NAME}"
  if [[ "$RESTORE_TRANSACTION_ORIGINAL_MARKER_PRESENT" == true ]]; then
    [[ -f "$rollback_marker" && ! -L "$rollback_marker" ]] \
      || die "Restore rollback schema marker is missing or unsafe"
    marker_backup_size="$(stat -c '%s' "$rollback_marker")"
    [[ "$marker_backup_size" =~ ^[0-9]+$ ]] && \
      ((10#$marker_backup_size > 0 && 10#$marker_backup_size <= 4096)) \
      || die "Restore rollback schema marker has an invalid size"
  else
    [[ ! -e "$rollback_marker" && ! -L "$rollback_marker" ]] \
      || die "Restore rollback unexpectedly contains a schema marker"
  fi
  return 0
}

restore_schema_marker_from_rollback() {
  local rollback="$1" marker_present="$2" backup tmp
  backup="${rollback}/${ROLLBACK_SCHEMA_MARKER_NAME}"
  [[ ! -L "$SCHEMA_MARKER" && \
     ( ! -e "$SCHEMA_MARKER" || -f "$SCHEMA_MARKER" ) ]] || return 1
  if [[ "$marker_present" == true ]]; then
    [[ -f "$backup" && ! -L "$backup" ]] || return 1
    tmp="$(mktemp "${RECOVERY_PATH}/.schema-state.restore.XXXXXX")" || return 1
    cleanup_add_file "$tmp"
    cp -- "$backup" "$tmp" || return 1
    chown root:root "$tmp" || return 1
    chmod 600 "$tmp" || return 1
    mv -f -- "$tmp" "$SCHEMA_MARKER" || return 1
  elif [[ "$marker_present" == false ]]; then
    rm -f -- "$SCHEMA_MARKER" || return 1
  else
    return 1
  fi
  sync -f "$RECOVERY_PATH"
}

restore_original_data_transaction() {
  local rollback="$1" original_state="$2" original_marker_present="$3"
  clear_data_contents || return 1
  cp -a -- "$rollback/data/." "$DATA_PATH/" || return 1
  restore_schema_marker_from_rollback "$rollback" "$original_marker_present" \
    || return 1
  rm -f -- "$SCHEMA_INIT_MARKER" "$SCHEMA_UPGRADE_BACKUP" \
    "$SCHEMA_UPGRADE_MARKER_BACKUP" \
    || return 1
  sync -f "$DATA_PATH" "$RECOVERY_PATH" || return 1
  sqlite_state_matches "$original_state" || return 1
  if [[ "$original_state" -eq 0 ]]; then
    ( validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE" ) \
      >/dev/null 2>&1 || return 1
  elif [[ "$original_state" -eq 1 ]]; then
    [[ ! -e "$SCHEMA_MARKER" && ! -L "$SCHEMA_MARKER" ]] || return 1
  fi
}

cleanup_orphan_restore_rollbacks() {
  local rollback marker_tmp removed=false
  local -a rollbacks=("${RECOVERY_PATH}"/rollback.*.dir)
  local -a marker_temps=("${RECOVERY_PATH}"/.restore-in-progress.*)
  [[ "$RECOVERY_PATH" == /opt/hexlicsrv/recovery ]] \
    || die "Refusing rollback cleanup for an unexpected recovery path"
  [[ ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]] \
    || die "Refusing orphan rollback cleanup while a restore marker exists"
  for rollback in "${rollbacks[@]}"; do
    [[ "$(basename "$rollback")" =~ ^rollback\.[A-Za-z0-9]+\.dir$ ]] \
      || die "Refusing unsafe orphan rollback path"
    [[ -d "$rollback" && ! -L "$rollback" ]] \
      || die "Unsafe orphan rollback artifact: $rollback"
    rm -rf -- "$rollback"
    removed=true
  done
  for marker_tmp in "${marker_temps[@]}"; do
    [[ "$(basename "$marker_tmp")" =~ ^\.restore-in-progress\.[A-Za-z0-9]+$ ]] \
      || die "Refusing unsafe restore-marker temp path"
    [[ -f "$marker_tmp" || -L "$marker_tmp" ]] \
      || die "Unsafe orphan restore-marker artifact: $marker_tmp"
    rm -f -- "$marker_tmp"
    removed=true
  done
  if [[ "$removed" == true ]]; then
    sync -f "$RECOVERY_PATH" \
      || die "Could not durably remove orphan restore rollback directories"
    log "Removed orphan restore rollback state from before data mutation"
  fi
}

recover_interrupted_data_restore() {
  if [[ ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]]; then
    cleanup_orphan_restore_rollbacks
    return 0
  fi
  load_restore_transaction

  warn "Recovering local data after an interrupted snapshot restore"
  if ! restore_original_data_transaction \
      "$RESTORE_TRANSACTION_ROLLBACK" \
      "$RESTORE_TRANSACTION_ORIGINAL_STATE" \
      "$RESTORE_TRANSACTION_ORIGINAL_MARKER_PRESENT"; then
    die "Automatic interrupted-restore recovery failed; preserved copy: $RESTORE_TRANSACTION_ROLLBACK"
  fi
  rm -f -- "$RESTORE_MARKER"
  sync -f "$RECOVERY_PATH" || die "Could not durably clear the restore transaction marker"
  rm -rf -- "$RESTORE_TRANSACTION_ROLLBACK"
  sync -f "$RECOVERY_PATH" || die "Could not durably remove the restore rollback directory"
  log "Recovered the pre-restore local data"
}

commit_data_restore() {
  load_restore_transaction || return 0
  sqlite_schema_state "$DB_FILE" \
    || die "Refusing to commit a restore without a valid SQLite schema"
  validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
  [[ "$LOADED_SCHEMA_VERSION" == "$SCHEMA_VERSION" ]] \
    || die "Refusing to commit a restore before schema upgrade completes"
  [[ ! -e "$SCHEMA_INIT_MARKER" && ! -L "$SCHEMA_INIT_MARKER" && \
     ! -e "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     ! -e "$SCHEMA_UPGRADE_MARKER_BACKUP" && ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] \
    || die "Refusing to commit a restore while a schema transaction remains active"
  sync -f "$DATA_PATH" || die "Could not durably commit restored data"
  sync -f "$SCHEMA_MARKER" "$RECOVERY_PATH" \
    || die "Could not durably commit the restored schema marker"
  rm -f -- "$RESTORE_MARKER"
  sync -f "$RECOVERY_PATH" || die "Could not durably commit the restore marker removal"
  rm -rf -- "$RESTORE_TRANSACTION_ROLLBACK"
  sync -f "$RECOVERY_PATH" || die "Could not durably remove the committed rollback directory"
  log "Committed restored data after schema validation"
}

import_payload() {
  local archive="$1" encryption="$2"
  local compressed tar_file extracted rollback max_tar_bytes tar_size original_state
  local staged_marker staged_marker_install rollback_marker marker_size
  local original_marker_present=false
  compressed="$(mktemp "${INSTALL_PATH}/_restore.XXXXXX.tar.zst")"
  tar_file="$(mktemp "${INSTALL_PATH}/_restore.XXXXXX.tar")"
  extracted="$(mktemp -d "${INSTALL_PATH}/_restore.XXXXXX.dir")"
  rollback="$(mktemp -d "${RECOVERY_PATH}/rollback.XXXXXX.dir")"
  cleanup_add_file "$compressed"
  cleanup_add_file "$tar_file"
  cleanup_add_dir "$extracted"
  cleanup_add_dir "$rollback"

  case "$encryption" in
    gpg-aes256-v1)
      [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
        || die "Encrypted snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
      gpg --no-options --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback \
        --passphrase-fd 3 --output "$compressed" --decrypt "$archive" \
        3<<<"$SYNC_ENCRYPTION_PASSPHRASE" \
        || die "Snapshot decryption/authentication failed"
      ;;
    *) die "Unsupported snapshot encryption format: $encryption" ;;
  esac

  max_tar_bytes=$((10#$SYNC_MAX_EXTRACT_MB * 1000000 + 100000000))
  if ! zstd -q -dc -- "$compressed" | head -c "$((max_tar_bytes + 1))" >"$tar_file"; then
    die "Could not decompress snapshot within the configured size limit"
  fi
  tar_size="$(stat -c '%s' "$tar_file")"
  ((10#$tar_size <= max_tar_bytes)) \
    || die "Snapshot decompression exceeds SYNC_MAX_EXTRACT_MB"
  validate_tar_archive "$tar_file" || die "Snapshot archive validation failed"
  tar -C "$extracted" --no-same-owner --no-same-permissions -xf "$tar_file" \
    || die "Could not extract snapshot"

  set +e
  sqlite_schema_state "$extracted/$(basename "$DB_FILE")"
  local staged_state=$?
  set -e
  [[ "$staged_state" -eq 0 ]] \
    || die "Restored snapshot does not contain a valid initialized SQLite schema"
  staged_marker="$extracted/$SNAPSHOT_SCHEMA_MARKER_NAME"
  validate_schema_marker_against_database \
    "$staged_marker" "$extracted/$(basename "$DB_FILE")"
  ((10#$LOADED_SCHEMA_VERSION <= 10#$SCHEMA_VERSION)) \
    || die "Snapshot schema $LOADED_SCHEMA_VERSION is newer than image schema $SCHEMA_VERSION; refusing downgrade"
  [[ "$LOADED_SCHEMA_VERSION" == "$MANIFEST_SCHEMA_VERSION" ]] \
    || die "Snapshot manifest/schema marker version mismatch"
  [[ "$LOADED_SCHEMA_FINGERPRINT" == "$MANIFEST_SCHEMA_FINGERPRINT" ]] \
    || die "Snapshot manifest/schema fingerprint mismatch"
  staged_marker_install="$(mktemp "${RECOVERY_PATH}/.restored-schema-state.XXXXXX")"
  cleanup_add_file "$staged_marker_install"
  cp -- "$staged_marker" "$staged_marker_install" \
    || die "Could not stage the restored schema marker"
  chown root:root "$staged_marker_install"
  chmod 600 "$staged_marker_install"
  rm -f -- "$staged_marker"
  chown -R "$(id -u "$SERVICE_USER"):$(id -g "$SERVICE_USER")" "$extracted"
  chmod -R u=rwX,go= "$extracted"

  set +e
  sqlite_schema_state "$DB_FILE"
  original_state=$?
  set -e
  if [[ -L "$SCHEMA_MARKER" || \
        ( -e "$SCHEMA_MARKER" && ! -f "$SCHEMA_MARKER" ) ]]; then
    die "Local schema marker is unsafe; refusing snapshot restore"
  fi
  if [[ "$original_state" -eq 0 ]]; then
    validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
    original_marker_present=true
  elif [[ "$original_state" -eq 1 && \
          ( -e "$SCHEMA_MARKER" || -L "$SCHEMA_MARKER" ) ]]; then
    die "Empty local database has an unexpected schema marker"
  elif [[ -f "$SCHEMA_MARKER" ]]; then
    marker_size="$(stat -c '%s' "$SCHEMA_MARKER")"
    [[ "$marker_size" =~ ^[0-9]+$ ]] && \
      ((10#$marker_size > 0 && 10#$marker_size <= 4096)) \
      || die "Local schema marker has an invalid size"
    original_marker_present=true
  fi

  mkdir -m 700 -- "$rollback/data"
  cp -a -- "$DATA_PATH/." "$rollback/data/" \
    || die "Could not stage current data for rollback"
  if [[ "$original_marker_present" == true ]]; then
    rollback_marker="${rollback}/${ROLLBACK_SCHEMA_MARKER_NAME}"
    cp -- "$SCHEMA_MARKER" "$rollback_marker" \
      || die "Could not stage the current schema marker for rollback"
    chown root:root "$rollback_marker"
    chmod 600 "$rollback_marker"
  fi
  sync -f "$rollback/data" "$RECOVERY_PATH" \
    || die "Could not durably stage current data for rollback"
  # From this point onward the persistent rollback is transaction state, not a
  # disposable temp directory. Signals and the global EXIT trap must not erase it.
  cleanup_remove_dir "$rollback"
  write_restore_marker "$rollback" "$original_state" "$original_marker_present"

  if ! clear_data_contents || ! cp -a -- "$extracted/." "$DATA_PATH/" || \
     ! [[ ! -L "$SCHEMA_MARKER" && \
          ( ! -e "$SCHEMA_MARKER" || -f "$SCHEMA_MARKER" ) ]] || \
     ! mv -f -- "$staged_marker_install" "$SCHEMA_MARKER" || \
     ! sync -f "$SCHEMA_MARKER" "$RECOVERY_PATH" || \
     ! sqlite_schema_state "$DB_FILE" || \
     ! ( validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE" ); then
    warn "Restore failed; rolling back original data"
    if ! restore_original_data_transaction \
        "$rollback" "$original_state" "$original_marker_present"; then
      cleanup_remove_dir "$rollback"
      die "Restore and rollback both failed; recovery copy preserved at $rollback"
    fi
    rm -f -- "$RESTORE_MARKER"
    sync -f "$RECOVERY_PATH" || die "Could not durably clear the failed restore marker"
    rm -rf -- "$rollback"
    sync -f "$RECOVERY_PATH" || die "Could not durably remove the failed restore rollback"
    die "Restore failed; original data was restored"
  fi

  sync -f "$DATA_PATH" "$RECOVERY_PATH" \
    || die "Could not durably stage restored data and schema identity"
  rm -rf -- "$extracted"
  rm -f -- "$compressed" "$tar_file"
  log "Snapshot data and trusted schema marker staged; rollback remains active through schema validation"
}

write_manifest() {
  local output="$1" timestamp="$2" size="$3" archive_sha="$4"
  local payload_sha="$5" archive_hmac="$6" encryption="$7"
  local snapshot_id="${8:-}" asset_prefix="${9:-}"
  local parts count unsigned canonical manifest_hmac
  parts=("${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*)
  count="${#parts[@]}"
  ((count > 0)) || die "No archive chunks were created"
  [[ "$PACK_SCHEMA_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] \
    || die "Cannot write manifest without a validated schema fingerprint"

  unsigned="$(mktemp)"
  cleanup_add_file "$unsigned"
  jq -n \
    --argjson format_version 3 \
    --arg service hexlicsrv \
    --arg host_id "$SYNC_HOST_ID" \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg schema_fingerprint_sha256 "$PACK_SCHEMA_FINGERPRINT" \
    --arg timestamp_utc "$timestamp" \
    --arg archive_name "$ARCHIVE_NAME" \
    --argjson chunk_size_mb "$SYNC_CHUNK_SIZE_MB" \
    --argjson chunk_count "$count" \
    --argjson archive_size_bytes "$size" \
    --arg archive_sha256 "$archive_sha" \
    --arg payload_sha256 "$payload_sha" \
    --arg archive_hmac_sha256 "$archive_hmac" \
    --arg encryption "$encryption" \
    --arg snapshot_id "$snapshot_id" \
    --arg asset_prefix "$asset_prefix" \
    '{format_version:$format_version,service:$service,host_id:$host_id,
      schema_version:$schema_version,
      schema_fingerprint_sha256:$schema_fingerprint_sha256,
      timestamp_utc:$timestamp_utc,archive_name:$archive_name,
      chunk_size_mb:$chunk_size_mb,chunk_count:$chunk_count,
      archive_size_bytes:$archive_size_bytes,archive_sha256:$archive_sha256,
      payload_sha256:$payload_sha256,archive_hmac_sha256:$archive_hmac_sha256,
      encryption:$encryption,snapshot_id:$snapshot_id,asset_prefix:$asset_prefix}' \
    >"$unsigned"
  canonical="$(jq -cS . "$unsigned")"
  manifest_hmac="$(printf '%s' "$canonical" | \
    SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
    HEX_SYNC_HMAC_CONTEXT=manifest python3 -c '
import hashlib,hmac,os,sys
secret=os.environ["SYNC_ENCRYPTION_PASSPHRASE"].encode()
key=hashlib.pbkdf2_hmac("sha256",secret,b"hexlicsrv-sync-v3-hmac",600_000,32)
print(hmac.new(key,b"manifest|"+sys.stdin.buffer.read(),hashlib.sha256).hexdigest())')"
  jq --arg hmac "$manifest_hmac" '. + {manifest_hmac_sha256:$hmac}' \
    "$unsigned" >"$output"
}

manifest_file_is_safe() {
  local file="$1" size
  [[ -f "$file" && ! -L "$file" ]] || return 1
  size="$(stat -c '%s' "$file" 2>/dev/null)" || return 1
  [[ "$size" =~ ^[0-9]{1,7}$ ]] || return 1
  ((10#$size >= 1 && 10#$size <= 1048576))
}

manifest_hmac_authenticates() {
  local file="$1" expected canonical actual encryption
  manifest_file_is_safe "$file" || return 1
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] || return 1
  jq -e 'type=="object"' "$file" >/dev/null 2>&1 || return 1
  encryption="$(jq -r '.encryption // empty' "$file" 2>/dev/null)" || return 1
  [[ "$encryption" == gpg-aes256-v1 ]] || return 1
  expected="$(jq -r '.manifest_hmac_sha256 // empty' "$file" 2>/dev/null)" || return 1
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  canonical="$(jq -cS 'del(.manifest_hmac_sha256)' "$file" 2>/dev/null)" || return 1
  actual="$(printf '%s' "$canonical" | \
    SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
    HEX_SYNC_HMAC_CONTEXT=manifest python3 -c '
import hashlib,hmac,os,sys
secret=os.environ["SYNC_ENCRYPTION_PASSPHRASE"].encode()
key=hashlib.pbkdf2_hmac("sha256",secret,b"hexlicsrv-sync-v3-hmac",600_000,32)
print(hmac.new(key,b"manifest|"+sys.stdin.buffer.read(),hashlib.sha256).hexdigest())')" \
    || return 1
  [[ "$actual" == "$expected" ]]
}

validate_manifest() {
  local file="$1" manifest_host manifest_service
  manifest_file_is_safe "$file" || die "Snapshot manifest is missing, unsafe, or too large"
  jq -e 'type=="object" and
    (.format_version==3) and
    (.service|type=="string") and
    (.host_id|type=="string") and
    (.archive_name|type=="string") and
    (.chunk_count|type=="number" and floor==.) and
    (.archive_size_bytes|type=="number" and floor==.) and
    (.schema_version|type=="number" and floor == . and . >= 1) and
    (.schema_fingerprint_sha256|type=="string" and test("^[0-9a-f]{64}$")) and
    (.archive_sha256|type=="string") and
    (.payload_sha256|type=="string") and
    (.archive_hmac_sha256|type=="string") and
    (.manifest_hmac_sha256|type=="string") and
    (.encryption=="gpg-aes256-v1") and
    (.snapshot_id|type=="string") and
    (.asset_prefix|type=="string")' "$file" >/dev/null \
    || die "Invalid snapshot manifest structure"

  MANIFEST_ARCHIVE_NAME="$(jq -r '.archive_name' "$file")"
  MANIFEST_ARCHIVE_SIZE="$(jq -r '.archive_size_bytes' "$file")"
  MANIFEST_ARCHIVE_SHA="$(jq -r '.archive_sha256' "$file")"
  MANIFEST_PAYLOAD_SHA="$(jq -r '.payload_sha256' "$file")"
  MANIFEST_CHUNK_COUNT="$(jq -r '.chunk_count' "$file")"
  MANIFEST_ENCRYPTION="$(jq -r '.encryption' "$file")"
  MANIFEST_ASSET_PREFIX="$(jq -r '.asset_prefix' "$file")"
  MANIFEST_SNAPSHOT_ID="$(jq -r '.snapshot_id' "$file")"
  MANIFEST_SCHEMA_VERSION="$(jq -r '.schema_version' "$file")"
  MANIFEST_SCHEMA_FINGERPRINT="$(jq -r '.schema_fingerprint_sha256' "$file")"
  manifest_host="$(jq -r '.host_id' "$file")"
  manifest_service="$(jq -r '.service' "$file")"

  [[ "$manifest_host" == "$SYNC_HOST_ID" ]] \
    || die "Manifest belongs to a different SYNC_HOST_ID"
  [[ "$manifest_service" == "hexlicsrv" ]] \
    || die "Manifest belongs to a different service"
  [[ "$MANIFEST_ARCHIVE_NAME" == "$ARCHIVE_NAME" ]] \
    || die "Manifest archive_name is not the current encrypted format"
  validate_uint_range manifest.chunk_count "$MANIFEST_CHUNK_COUNT" 1 10000
  validate_uint_range manifest.archive_size_bytes "$MANIFEST_ARCHIVE_SIZE" 1 \
    $((10#$SYNC_MAX_RESTORE_MB * 1000000))
  validate_uint_range manifest.schema_version "$MANIFEST_SCHEMA_VERSION" 1 2147483647
  [[ "$MANIFEST_SCHEMA_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] \
    || die "Manifest schema fingerprint is invalid"
  [[ "$MANIFEST_ARCHIVE_SHA" =~ ^[0-9a-f]{64}$ ]] \
    || die "Manifest archive SHA-256 is invalid"
  [[ "$MANIFEST_PAYLOAD_SHA" =~ ^[0-9a-f]{64}$ ]] \
    || die "Manifest payload SHA-256 is invalid"
  [[ "$(jq -r '.archive_hmac_sha256' "$file")" =~ ^[0-9a-f]{64}$ ]] \
    || die "Manifest archive HMAC is invalid"
  [[ "$MANIFEST_ENCRYPTION" == "gpg-aes256-v1" ]] \
    || die "Only encrypted and authenticated snapshot manifests are supported"
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Encrypted snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
  manifest_hmac_authenticates "$file" || \
    die "Manifest authentication failed (wrong passphrase or corrupted manifest)"
}

validate_manifest_schema_compatibility() {
  ((10#$MANIFEST_SCHEMA_VERSION <= 10#$SCHEMA_VERSION)) \
    || die "Remote snapshot schema $MANIFEST_SCHEMA_VERSION is newer than image schema $SCHEMA_VERSION; refusing downgrade"
}

verify_archive() {
  local archive="$1" manifest="$2" size sha expected_hmac actual_hmac
  validate_manifest "$manifest"
  size="$(stat -c '%s' "$archive")"
  [[ "$size" == "$MANIFEST_ARCHIVE_SIZE" ]] \
    || die "Snapshot size mismatch"
  sha="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$sha" == "$MANIFEST_ARCHIVE_SHA" ]] \
    || die "Snapshot checksum mismatch"
  if [[ "$MANIFEST_ENCRYPTION" == "gpg-aes256-v1" ]]; then
    expected_hmac="$(jq -r '.archive_hmac_sha256 // empty' "$manifest")"
    [[ "$expected_hmac" =~ ^[0-9a-f]{64}$ ]] \
      || die "Encrypted archive has no valid authentication tag"
    actual_hmac="$(compute_hmac_file "$archive" archive)"
    [[ "$actual_hmac" == "$expected_hmac" ]] \
      || die "Archive authentication failed"
  fi
}

ensure_safe_work_dir() {
  if [[ -e "$WORK_DIR" || -L "$WORK_DIR" ]]; then
    [[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] \
      || die "Sync work path is not a safe directory"
  else
    mkdir -m 700 -- "$WORK_DIR"
  fi
}

ensure_safe_remote_dir() {
  local backups_dir="${WORK_DIR}/backups"
  ensure_safe_work_dir
  if [[ -e "$backups_dir" || -L "$backups_dir" ]]; then
    [[ -d "$backups_dir" && ! -L "$backups_dir" ]] \
      || die "Sync backups path is not a safe directory"
  else
    mkdir -- "$backups_dir"
  fi
  if [[ -e "$REMOTE_DIR" || -L "$REMOTE_DIR" ]]; then
    [[ -d "$REMOTE_DIR" && ! -L "$REMOTE_DIR" ]] \
      || die "Host sync path is not a safe directory"
  else
    mkdir -- "$REMOTE_DIR"
  fi
}

split_archive_into_remote() {
  local block_size=$((10#$SYNC_CHUNK_SIZE_MB * 1000000))
  ensure_safe_remote_dir
  rm -f -- \
    "${REMOTE_DIR}/data.tar.zst.gpg.part_"* \
    "${REMOTE_DIR}/${MANIFEST_NAME}"
  split -b "$block_size" -d -a 5 -- "$ARCHIVE_PATH" \
    "${REMOTE_DIR}/${ARCHIVE_NAME}.part_" \
    || die "Failed to split archive"
}

assemble_remote_archive() {
  local dest="$1"
  local index width=5 part size total_size=0 free_bytes
  local -a parts=()
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    printf -v part '%s/%s.part_%0*d' "$REMOTE_DIR" "$MANIFEST_ARCHIVE_NAME" "$width" "$index"
    [[ -f "$part" && ! -L "$part" ]] || die "Missing or unsafe snapshot chunk: $part"
    size="$(stat -c '%s' "$part")"
    [[ "$size" =~ ^[0-9]+$ ]] || die "Could not determine snapshot chunk size"
    ((total_size += 10#$size))
    ((total_size <= 10#$MANIFEST_ARCHIVE_SIZE)) \
      || die "Snapshot chunks exceed manifest archive size"
    parts+=("$part")
  done
  ((${#parts[@]} == 10#$MANIFEST_CHUNK_COUNT)) \
    || die "Snapshot chunk count mismatch"
  ((total_size == 10#$MANIFEST_ARCHIVE_SIZE)) \
    || die "Snapshot chunk sizes do not match manifest archive size"
  free_bytes="$(df -PB1 "$(dirname "$dest")" | awk 'NR==2 {print $4}')"
  [[ "$free_bytes" =~ ^[0-9]+$ ]] || die "Could not determine assembly disk capacity"
  ((10#$free_bytes > 10#$MANIFEST_ARCHIVE_SIZE)) \
    || die "Insufficient disk space to assemble snapshot"
  rm -f -- "$dest"
  cat "${parts[@]}" >"$dest" || die "Failed to assemble snapshot"
}

restore_from_commits_manifest() {
  local manifest="$1" tmp archive
  validate_manifest "$manifest"
  validate_manifest_schema_compatibility
  tmp="$(mktemp -d "${INSTALL_PATH}/_restore_commit.XXXXXX")"
  cleanup_add_dir "$tmp"
  archive="$tmp/$MANIFEST_ARCHIVE_NAME"
  assemble_remote_archive "$archive"
  verify_archive "$archive" "$manifest"
  import_payload "$archive" "$MANIFEST_ENCRYPTION"
  rm -rf -- "$tmp"
  cleanup_remove_dir "$tmp"
}

COMMITS_NAMESPACE_HAS_SNAPSHOT=false

validate_commits_namespace() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" entry name index
  local entry_count=0 chunk_count=0
  COMMITS_NAMESPACE_HAS_SNAPSHOT=false
  ensure_safe_remote_dir
  while IFS= read -r -d '' entry; do
    ((entry_count+=1))
    [[ -f "$entry" && ! -L "$entry" ]] \
      || die "Commits namespace contains a non-regular artifact"
    name="$(basename "$entry")"
    case "$name" in
      "$MANIFEST_NAME") ;;
      data.tar.zst.gpg.part_[0-9][0-9][0-9][0-9][0-9])
        ((chunk_count+=1))
        ;;
      *) die "Commits namespace contains a non-current artifact; refusing mutation" ;;
    esac
  done < <(find "$REMOTE_DIR" -mindepth 1 -maxdepth 1 -print0)

  if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
    ((entry_count == 0)) || \
      die "Commits namespace contains artifacts without an authenticated current-v3 manifest"
    return 0
  fi
  [[ -f "$manifest" && ! -L "$manifest" ]] \
    || die "Commits manifest is missing or unsafe"
  validate_manifest "$manifest"
  validate_manifest_schema_compatibility
  [[ -z "$MANIFEST_ASSET_PREFIX" && -z "$MANIFEST_SNAPSHOT_ID" ]] \
    || die "Commits manifest contains release-only generation metadata"
  ((chunk_count == 10#$MANIFEST_CHUNK_COUNT && \
     entry_count == 10#$MANIFEST_CHUNK_COUNT + 1)) \
    || die "Commits namespace does not contain exactly the declared snapshot chunks"
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    printf -v name '%s.part_%05d' "$MANIFEST_ARCHIVE_NAME" "$index"
    [[ -f "${REMOTE_DIR}/${name}" && ! -L "${REMOTE_DIR}/${name}" ]] \
      || die "Commits namespace is missing declared chunk: $name"
  done
  COMMITS_NAMESPACE_HAS_SNAPSHOT=true
  return 0
}

ensure_tools_commits() {
  local missing=() tool
  for tool in git ssh tar zstd jq sha256sum split openssl sqlite3 gpg python3 base64 flock du sort; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || die "Missing tools: ${missing[*]}"
}

GH_MODE=""
GIT_AUTH_B64=""
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
      GH_MODE="READONLY"
    else
      GH_MODE="SYNC"
    fi
  elif gh_remote_is_ssh; then
    [[ -n "$GH_SSH_PRIVATE_KEY" ]] || die "SSH remote requires GH_SSH_PRIVATE_KEY"
    if [[ "${SYNC_READ_ONLY,,}" == true ]]; then GH_MODE="READONLY"; else GH_MODE="SYNC"; fi
  else
    die "Unsupported GH_REMOTE scheme"
  fi
  if [[ "$GH_MODE" == "SYNC" && -z "$SYNC_ENCRYPTION_PASSPHRASE" ]]; then
    die "Write sync requires SYNC_ENCRYPTION_PASSPHRASE"
  fi
}

git_cmd() {
  if [[ -n "$GIT_AUTH_B64" ]]; then
    GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_0=http.extraHeader \
      GIT_CONFIG_VALUE_0="Authorization: Basic ${GIT_AUTH_B64}" \
      GIT_TERMINAL_PROMPT=0 \
      timeout --kill-after=30s "$SYNC_NETWORK_TIMEOUT_SECONDS" git "$@"
  else
    GIT_TERMINAL_PROMPT=0 \
      timeout --kill-after=30s "$SYNC_NETWORK_TIMEOUT_SECONDS" git "$@"
  fi
}

gh_git_setup() {
  local key sync_ssh_dir
  ensure_safe_work_dir
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  export GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

  GIT_AUTH_B64=""
  if [[ -n "$SYNC_AUTH_TOKEN" && "$GH_REMOTE" =~ ^https:// ]]; then
    GIT_AUTH_B64="$(printf 'x-access-token:%s' "$SYNC_AUTH_TOKEN" | base64 -w0)"
  fi

  if gh_remote_is_ssh; then
    [[ -n "$GH_KNOWN_HOSTS" ]] \
      || die "SSH sync requires pinned GH_KNOWN_HOSTS; insecure auto-accept is disabled"
    sync_ssh_dir="/run/hexlicsrv-sync-ssh"
    rm -rf -- "$sync_ssh_dir"
    mkdir -m 700 "$sync_ssh_dir"
    key="$sync_ssh_dir/id"
    printf '%s\n' "$GH_SSH_PRIVATE_KEY" >"$key"
    printf '%s\n' "$GH_KNOWN_HOSTS" >"$sync_ssh_dir/known_hosts"
    chmod 600 "$key" "$sync_ssh_dir/known_hosts"
    export GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o UserKnownHostsFile=$sync_ssh_dir/known_hosts -o StrictHostKeyChecking=yes"
  else
    unset GIT_SSH_COMMAND || true
  fi

}

gh_git_reinitialize_repository() {
  [[ "$INSTALL_PATH" == /opt/hexlicsrv && \
     "$WORK_DIR" == /opt/hexlicsrv/_gitmirror && \
     "$REMOTE_DIR" == "${WORK_DIR}/backups/${SYNC_HOST_ID}" ]] \
    || die "Refusing to recreate an unexpected commits worktree"
  [[ -d "$INSTALL_PATH" && ! -L "$INSTALL_PATH" && \
     "$(realpath -e -- "$INSTALL_PATH")" == "$INSTALL_PATH" ]] \
    || die "HexLicSrv install path is missing, symlinked, or non-canonical"
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
  trace="$(mktemp /run/hexlicsrv-git-capabilities.XXXXXX)"
  refs_file="$(mktemp /run/hexlicsrv-git-refs.XXXXXX)"
  cleanup_add_file "$trace"
  cleanup_add_file "$refs_file"
  if ! (ulimit -f 2048 || exit 125; GIT_TRACE_PACKET="$trace" GIT_PROTOCOL=version=2 \
      git_cmd -C "$WORK_DIR" ls-remote --heads origin "$expected_ref") >"$refs_file"; then
    die "Could not query remote branch ${GH_BRANCH}; refusing to treat a network/auth error as an empty remote"
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
  raw="$(mktemp /run/hexlicsrv-git-tree-path.XXXXXX)"
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
  COMMITS_TREE_INDEX="$(mktemp /run/hexlicsrv-git-tree-index.XXXXXX)"
  cleanup_add_file "$COMMITS_TREE_INDEX"
  : >"$COMMITS_TREE_INDEX"

  if ! commits_tree_path_is_directory "$commit" backups; then
    return 0
  fi
  if ! commits_tree_path_is_directory "$commit" "$scope"; then
    return 0
  fi

  raw="$(mktemp /run/hexlicsrv-git-tree.XXXXXX)"
  cleanup_add_file "$raw"
  if ! (ulimit -f 4096 || exit 125; git_cmd -C "$WORK_DIR" ls-tree -r -z "$commit" -- "$scope") >"$raw"; then
    die "Commits namespace tree metadata exceeds its safety bound"
  fi
  while IFS= read -r -d '' entry; do
    ((count+=1))
    ((count <= 10001)) || die "Commits namespace contains too many entries"
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    read -r mode type oid extra <<<"$metadata"
    [[ -z "$extra" && "$type" == blob && \
       ( "$mode" == 100644 || "$mode" == 100755 ) && \
       ( "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ) ]] \
      || die "Commits namespace contains a symlink, gitlink, tree, or non-blob entry"
    [[ "$path" == "$scope/"* ]] \
      || die "Commits tree entry escapes the target namespace"
    name="${path#"$scope/"}"
    [[ -n "$name" && "$name" != */* ]] \
      || die "Commits namespace contains a nested or empty path"
    case "$name" in
      "$MANIFEST_NAME")
        ((manifest_count+=1))
        COMMITS_TREE_MANIFEST_OID="$oid"
        ;;
      data.tar.zst.gpg.part_[0-9][0-9][0-9][0-9][0-9])
        ((chunk_count+=1))
        ;;
      *) die "Commits namespace contains a non-current artifact: '$name'" ;;
    esac
    printf '%s\t%s\n' "$name" "$oid" >>"$COMMITS_TREE_INDEX"
  done <"$raw"

  ((manifest_count <= 1)) || die "Commits namespace contains duplicate manifests"
  if ((count == 0)); then
    return 0
  fi
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
  output="$(mktemp /run/hexlicsrv-commit-manifest.XXXXXX)"
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
  if ! size="$( (ulimit -f "$limit_kib" || exit 125; \
      git_cmd -C "$WORK_DIR" cat-file -s "$oid") )"; then
    return 1
  fi
  [[ "$size" =~ ^[1-9][0-9]{0,15}$ ]] || return 1
  printf '%s\n' "$size"
}

commits_fetch_declared_chunks_bounded() {
  local manifest="$1" chunk_mb chunk_limit max_bytes total=0 count=0
  local name oid expected size objects_before objects_now objects_limit
  chunk_mb="$(jq -r '.chunk_size_mb // empty' "$manifest")"
  validate_uint_range manifest.chunk_size_mb "$chunk_mb" 1 49
  ((10#$MANIFEST_CHUNK_COUNT <= 10000)) || die "Manifest declares too many chunks"
  chunk_limit=$((10#$chunk_mb * 1000000))
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
  ensure_safe_remote_dir
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
  [[ -z "$unexpected" ]] \
    || die "Exact commits materialization created another host namespace"
}

commits_empty_tree_oid() {
  GIT_NO_LAZY_FETCH=1 git_cmd -C "$WORK_DIR" mktree </dev/null
}

commits_rewrite_tree_entry() (
  local parent_tree="$1" entry_name="$2" child_tree="$3"
  local raw filtered entry path result
  raw="$(mktemp /run/hexlicsrv-parent-tree.XXXXXX)"
  filtered="$(mktemp /run/hexlicsrv-rewritten-tree.XXXXXX)"
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
  target_input="$(mktemp /run/hexlicsrv-target-tree.XXXXXX)"
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
    if [[ "$grep_scan_status" -eq 0 ]]; then
      die "Remote ignored blob:none and sent branch blobs before namespace preflight"
    fi
    commits_tree_preflight_names "$COMMITS_REMOTE_COMMIT"
    if [[ "$COMMITS_TREE_HAS_SNAPSHOT" == true ]]; then
      commits_fetch_manifest_bounded
      validate_manifest "$COMMITS_TREE_MANIFEST_TMP"
      validate_manifest_schema_compatibility
      [[ -z "$MANIFEST_ASSET_PREFIX" && -z "$MANIFEST_SNAPSHOT_ID" ]] \
        || die "Commits manifest contains release-only generation metadata"
      commits_fetch_declared_chunks_bounded "$COMMITS_TREE_MANIFEST_TMP"
    fi
    commits_materialize_target_namespace "$COMMITS_REMOTE_COMMIT"
  else
    COMMITS_TREE_INDEX="$(mktemp /run/hexlicsrv-git-tree-index.XXXXXX)"
    cleanup_add_file "$COMMITS_TREE_INDEX"
    : >"$COMMITS_TREE_INDEX"
    commits_materialize_target_namespace
  fi
}

perform_commits_sync() {
  local phase="${1:-publish}"
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" remote_present=false
  local remote_payload="" remote_encryption="" need_push=true
  local attempt=1
  [[ "$phase" == startup || "$phase" == publish ]] \
    || die "Unknown commits sync phase: $phase"
  ensure_tools_commits
  gh_git_mode_detect
  gh_git_setup
  gh_git_pull_hard

  validate_commits_namespace
  if [[ "$COMMITS_NAMESPACE_HAS_SNAPSHOT" == true ]]; then
    remote_present=true
    remote_payload="$MANIFEST_PAYLOAD_SHA"
    remote_encryption="$MANIFEST_ENCRYPTION"
  fi

  if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true && \
        "$remote_present" == false ]]; then
    die "SYNC_FORCE_RESTORE=true was requested, but no commits snapshot exists"
  fi

  if [[ "$phase" == startup && "$remote_present" == true ]] && \
     { ! data_has_meaningful_content || [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; }; then
    log "Restoring filesystem snapshot from commits"
    restore_from_commits_manifest "$manifest"
  elif [[ "$GH_MODE" == "READONLY" ]]; then
    if [[ "$remote_present" == true ]]; then
      log "Read-only sync: preserving meaningful local data"
    else
      log "Read-only sync: no remote snapshot"
    fi
    return 0
  fi

  if [[ "$phase" == startup ]]; then
    log "Startup sync is restore-only; publication follows schema validation"
    return 0
  fi

  [[ "$GH_MODE" == "SYNC" ]] || return 0
  if ! data_has_meaningful_content; then
    [[ "$phase" == startup ]] && { log "No meaningful local data to publish before initialization"; return 0; }
    die "Local data disappeared or is empty; publish-only sync refuses to restore or upload it"
  fi

  pack_payload
  while ((attempt <= 3)); do
    if ((attempt > 1)); then
      warn "Git push raced with another writer; bounded blobless refetch/retry $attempt of 3"
      gh_git_pull_hard
      manifest="${REMOTE_DIR}/${MANIFEST_NAME}"
      remote_present=false
      remote_payload=""
      remote_encryption=""
      validate_commits_namespace
      if [[ "$COMMITS_NAMESPACE_HAS_SNAPSHOT" == true ]]; then
        remote_present=true
        remote_payload="$MANIFEST_PAYLOAD_SHA"
        remote_encryption="$MANIFEST_ENCRYPTION"
      fi
    fi

    need_push=true
    if [[ "$remote_present" == true && "$remote_payload" == "$PACK_PAYLOAD_SHA" && \
          "$remote_encryption" == "gpg-aes256-v1" ]]; then
      local verify_dir verify_archive_path
      verify_dir="$(mktemp -d "${INSTALL_PATH}/_verify_commit.XXXXXX")"
      cleanup_add_dir "$verify_dir"
      verify_archive_path="$verify_dir/$MANIFEST_ARCHIVE_NAME"
      if ( assemble_remote_archive "$verify_archive_path" && \
           verify_archive "$verify_archive_path" "$manifest" ); then
        need_push=false
      else
        warn "Matching commits manifest references an incomplete/corrupt snapshot; republishing"
      fi
      rm -rf -- "$verify_dir"
      cleanup_remove_dir "$verify_dir"
    fi
    [[ "$need_push" == true ]] \
      || { log "Local snapshot matches commits remote"; return 0; }

    split_archive_into_remote
    write_manifest "$manifest" "$(now_utc)" "$PACK_SIZE" "$PACK_SHA" \
      "$PACK_PAYLOAD_SHA" "$PACK_ARCHIVE_HMAC" "$PACK_ENCRYPTION"
    validate_commits_namespace
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

ensure_tools_releases() {
  local missing=() tool
  for tool in curl tar zstd jq sha256sum split openssl sqlite3 gpg python3 flock; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  ((${#missing[@]} == 0)) || die "Missing tools: ${missing[*]}"
}

GH_OWNER=""
GH_REPO=""
GH_REMOTE_HOST=""
GH_REL_ID=""
AUTH_HEADER=()
AUTH_HEADER_FILE=""
HTTP_STATUS=""
HTTP_BODY_FILE=""
GH_ASSETS_JSON="[]"
GH_API_MAX_JSON_BYTES=20000000

urlencode() { jq -rn --arg value "$1" '$value|@uri'; }

parse_gh_remote() {
  local url="$GH_REMOTE" tmp path endpoint host host_authority api_authority transport
  [[ -n "$url" ]] || die "GH_REMOTE is required for releases mode"
  if [[ "$url" =~ ^https:// ]]; then
    transport=https
    tmp="${url#*://}"; host_authority="${tmp%%/*}"; path="${tmp#*/}"
  elif [[ "$url" =~ ^ssh://([^/]+)/(.+)$ ]]; then
    transport=ssh
    host_authority="${BASH_REMATCH[1]}"; host_authority="${host_authority#*@}"; path="${BASH_REMATCH[2]}"
  elif [[ "$url" =~ ^[^@]+@([^:]+):(.+)$ ]]; then
    transport=ssh
    host_authority="${BASH_REMATCH[1]}"; path="${BASH_REMATCH[2]}"
  else
    die "Unsupported GH_REMOTE"
  fi
  host="${host_authority%%:*}"
  host="${host,,}"
  path="${path%.git}"
  [[ "$path" =~ ^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$ ]] \
    || die "Cannot safely parse owner/repo from GH_REMOTE"
  GH_OWNER="${BASH_REMATCH[1]}"
  GH_REPO="${BASH_REMATCH[2]}"
  [[ "$GH_OWNER" != . && "$GH_OWNER" != .. && \
     "$GH_REPO" != . && "$GH_REPO" != .. ]] \
    || die "Repository owner/name must not be a path segment"
  GH_REMOTE_HOST="$host"

  api_authority="$host"
  if [[ "$transport" == https && "$host" != github.com && "$host_authority" == *:* ]]; then
    api_authority="$host_authority"
  fi
  [[ -n "$GH_API" ]] || { [[ "$host" == github.com ]] && GH_API=https://api.github.com || GH_API="https://${api_authority}/api/v3"; }
  [[ -n "$GH_UPLOAD" ]] || { [[ "$host" == github.com ]] && GH_UPLOAD=https://uploads.github.com || GH_UPLOAD="https://${api_authority}/api/uploads"; }
  GH_API="${GH_API%/}"
  GH_UPLOAD="${GH_UPLOAD%/}"
  for endpoint in "$GH_API" "$GH_UPLOAD"; do
    [[ "$endpoint" =~ ^https://([^/]+) ]] || die "GitHub endpoints must use HTTPS"
    local endpoint_host="${BASH_REMATCH[1]}"
    endpoint_host="${endpoint_host%%:*}"
    endpoint_host="${endpoint_host,,}"
    if [[ "$host" == github.com ]]; then
      [[ "$endpoint_host" == api.github.com || "$endpoint_host" == uploads.github.com ]] \
        || die "Custom GitHub endpoint host is not allowed for github.com"
    else
      [[ "$endpoint_host" == "$host" ]] || die "GitHub Enterprise endpoint host mismatch"
    fi
  done
}

gh_auth_header() {
  if [[ -n "$AUTH_HEADER_FILE" && -f "$AUTH_HEADER_FILE" ]]; then
    rm -f -- "$AUTH_HEADER_FILE"
  fi
  AUTH_HEADER_FILE="$(mktemp /run/hexlicsrv-github-headers.XXXXXX)"
  cleanup_add_file "$AUTH_HEADER_FILE"
  chmod 600 "$AUTH_HEADER_FILE"
  printf 'X-GitHub-Api-Version: 2022-11-28\n' >"$AUTH_HEADER_FILE"
  if [[ -n "$SYNC_AUTH_TOKEN" ]]; then
    printf 'Authorization: Bearer %s\n' "$SYNC_AUTH_TOKEN" >>"$AUTH_HEADER_FILE"
  fi
  AUTH_HEADER=(-H "@${AUTH_HEADER_FILE}")
}

curl_with_hard_output_limit() {
  local max_bytes="$1" blocks
  shift
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || return 2
  blocks=$(((10#$max_bytes + 1023) / 1024))
  (
    ulimit -f "$blocks" || exit 2
    exec curl "$@"
  )
}

http_body_is_bounded() {
  local file="$1" size
  [[ -f "$file" && ! -L "$file" ]] || return 1
  size="$(stat -c '%s' "$file" 2>/dev/null)" || return 1
  [[ "$size" =~ ^[0-9]{1,8}$ ]] || return 1
  ((10#$size <= GH_API_MAX_JSON_BYTES))
}

http_json() {
  local method="$1" url="$2" data="${3:-}" tmp code status
  if [[ -n "${HTTP_BODY_FILE:-}" && -f "$HTTP_BODY_FILE" ]]; then
    rm -f -- "$HTTP_BODY_FILE"
  fi
  tmp="$(mktemp)"; cleanup_add_file "$tmp"
  if [[ -n "$data" ]]; then
    if code="$(curl_with_hard_output_limit "$GH_API_MAX_JSON_BYTES" \
      -q --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$GH_API_MAX_JSON_BYTES" --fail-with-body -sS -w '%{http_code}' \
      "${AUTH_HEADER[@]}" -H 'Accept: application/vnd.github+json' \
      -H 'Content-Type: application/json' -X "$method" --data "$data" \
      -o "$tmp" "$url")"; then status=0; else status=$?; fi
  else
    if code="$(curl_with_hard_output_limit "$GH_API_MAX_JSON_BYTES" \
      -q --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$GH_API_MAX_JSON_BYTES" --fail-with-body -sS -w '%{http_code}' \
      "${AUTH_HEADER[@]}" -H 'Accept: application/vnd.github+json' \
      -X "$method" -o "$tmp" "$url")"; then status=0; else status=$?; fi
  fi
  HTTP_STATUS="${code:-000}"; HTTP_BODY_FILE="$tmp"
  http_body_is_bounded "$tmp" \
    || die "$method $url returned an unsafe or oversized response body"
  if [[ "$status" -ne 0 ]]; then
    [[ -z "$data" ]] && return 1
    die "$method $url failed (HTTP $HTTP_STATUS)"
  fi
  jq -e . "$tmp" >/dev/null 2>&1 || {
    [[ -z "$data" ]] && return 1
    die "$method $url returned invalid JSON"
  }
  return 0
}

gh_get_release_id_by_tag() {
  local encoded url release_id
  encoded="$(urlencode "$GH_RELEASE_TAG")"
  url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encoded}"
  if ! http_json GET "$url"; then
    if [[ "$HTTP_STATUS" == 404 ]]; then
      rm -f -- "$HTTP_BODY_FILE"
      printf '\n'
      return 0
    fi
    die "GET release failed (HTTP $HTTP_STATUS)"
  fi
  [[ "$HTTP_STATUS" == 200 ]] || die "GET release failed (HTTP $HTTP_STATUS)"
  jq -e 'type=="object" and (.id|type=="number" and floor==. and .>0)' \
    "$HTTP_BODY_FILE" >/dev/null || die "GitHub release response has an invalid type or id"
  release_id="$(jq -r '.id // empty' "$HTTP_BODY_FILE")"
  rm -f -- "$HTTP_BODY_FILE"
  printf '%s\n' "$release_id"
}

gh_verify_repository_access() {
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}" repository_id
  if ! http_json GET "$url"; then
    die "Cannot access the configured GitHub repository (HTTP $HTTP_STATUS); refusing to treat it as an empty remote"
  fi
  [[ "$HTTP_STATUS" == 200 ]] \
    || die "Cannot access the configured GitHub repository (HTTP $HTTP_STATUS)"
  jq -e 'type=="object" and (.id|type=="number" and floor==. and .>0)' \
    "$HTTP_BODY_FILE" >/dev/null || die "GitHub repository response has an invalid type or id"
  repository_id="$(jq -r '.id // empty' "$HTTP_BODY_FILE")"
  [[ "$repository_id" =~ ^[1-9][0-9]*$ ]] \
    || die "GitHub repository metadata is invalid"
  rm -f -- "$HTTP_BODY_FILE"
  HTTP_BODY_FILE=""
}

gh_ensure_release() {
  local phase="${1:-publish}" body
  GH_REL_ID="$(gh_get_release_id_by_tag)"
  if [[ -z "$GH_REL_ID" ]]; then
    if [[ "$phase" == startup ]]; then
      log "Release not found during restore-only startup"
      return 0
    fi
    [[ -n "$SYNC_AUTH_TOKEN" && "${SYNC_READ_ONLY,,}" == false ]] \
      || { log "Release not found in read-only mode"; return 0; }
    body="$(jq -n --arg tag "$GH_RELEASE_TAG" --arg name "$GH_RELEASE_NAME" \
      '{tag_name:$tag,name:$name,prerelease:true,draft:false}')"
    http_json POST "${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases" "$body"
    [[ "$HTTP_STATUS" == 201 ]] || die "Create release failed (HTTP $HTTP_STATUS)"
    jq -e 'type=="object" and (.id|type=="number" and floor==. and .>0)' \
      "$HTTP_BODY_FILE" >/dev/null || die "Created release response has an invalid type or id"
    GH_REL_ID="$(jq -r '.id' "$HTTP_BODY_FILE")"
  fi
  [[ "$GH_REL_ID" =~ ^[1-9][0-9]*$ ]] || die "Invalid GitHub release id"
}

gh_list_assets() {
  local page=1 count ndjson url
  ndjson="$(mktemp)"; cleanup_add_file "$ndjson"; : >"$ndjson"
  while :; do
    url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?per_page=100&page=${page}"
    http_json GET "$url" || die "Could not list release assets"
    jq -e '
      type=="array" and length<=100 and
      all(.[];
        type=="object" and
        (.name|type=="string" and length>=1 and length<=1024) and
        (.id|type=="number" and floor==. and .>0 and .<=9007199254740991) and
        (.size|type=="number" and floor==. and .>=0 and .<=9007199254740991)
      )' "$HTTP_BODY_FILE" >/dev/null \
      || die "Invalid or oversized assets response page"
    count="$(jq 'length' "$HTTP_BODY_FILE")"
    if ((page == 11)); then
      ((count == 0)) \
        || die "Release asset count exceeds GitHub's 1000-asset limit"
      break
    fi
    # Retain only bounded fields used by registry validation/capacity checks;
    # never accumulate arbitrary API object payloads across ten pages.
    jq -c '.[] | {name,id,size}' "$HTTP_BODY_FILE" >>"$ndjson"
    ((count < 100)) && break
    ((page++))
    ((page <= 11)) || die "Release asset pagination exceeded its hard bound"
  done
  jq -s '.' "$ndjson"
  rm -f -- "$ndjson"
  rm -f -- "$HTTP_BODY_FILE"
}

gh_refresh_assets() { GH_ASSETS_JSON="$(gh_list_assets)"; }

gh_asset_id() {
  local name="$1"
  jq -r --arg name "$name" '[.[]|select(.name==$name)][0].id // empty' \
    <<<"$GH_ASSETS_JSON"
}

gh_asset_size_exact() {
  local name="$1" count size
  count="$(jq -r --arg name "$name" '[.[]|select(.name==$name)]|length' \
    <<<"$GH_ASSETS_JSON")"
  [[ "$count" == 1 ]] || return 1
  size="$(jq -r --arg name "$name" '[.[]|select(.name==$name)][0].size // empty' \
    <<<"$GH_ASSETS_JSON")"
  [[ "$size" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  printf '%s\n' "$size"
}

gh_upload_asset_as() {
  local file="$1" name="$2" encoded code url
  encoded="$(urlencode "$name")"
  url="${GH_UPLOAD}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?name=${encoded}"
  if ! code="$(curl -q --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
    --fail-with-body -sS -w '%{http_code}' "${AUTH_HEADER[@]}" \
    -H 'Content-Type: application/octet-stream' --data-binary @"$file" \
    -o /dev/null "$url")"; then
    warn "Upload $name failed (HTTP ${code:-000})"
    return 1
  fi
  if [[ ! "$code" =~ ^2[0-9][0-9]$ ]]; then
    warn "Upload $name failed (HTTP $code)"
    return 1
  fi
  log "Uploaded release asset $name"
}

validate_https_download_url() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse

raw = sys.argv[1]
if (
    not raw
    or "\\" in raw
    or any(character.isspace() or ord(character) < 32 or ord(character) == 127
           for character in raw)
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
  local name="$1" output="$2" max_size="${3:-1048576}"
  local id code url api_size actual_size headers redirect_url hard_limit
  id="$(gh_asset_id "$name")"
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || return 1
  api_size="$(gh_asset_size_exact "$name")" || return 1
  [[ "$max_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ((10#$api_size > 0 && 10#$api_size <= 10#$max_size)) || return 1
  hard_limit="$max_size"
  ((10#$hard_limit >= 1048576)) || hard_limit=1048576
  url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"
  headers="$(mktemp)"; cleanup_add_file "$headers"
  if ! code="$(curl_with_hard_output_limit "$hard_limit" \
    -q --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
    --max-filesize "$max_size" \
    --fail-with-body -sS -w '%{http_code}' --dump-header "$headers" \
    "${AUTH_HEADER[@]}" -H 'Accept: application/octet-stream' \
    -o "$output" "$url")"; then
    return 1
  fi
  if [[ "$code" =~ ^3[0-9][0-9]$ ]]; then
    redirect_url="$(python3 - "$headers" <<'PY'
import sys

locations = []
with open(sys.argv[1], "r", encoding="latin-1", newline=None) as stream:
    for line in stream:
        if line.lower().startswith("location:"):
            locations.append(line.split(":", 1)[1].strip())
if len(locations) != 1:
    raise SystemExit(1)
print(locations[0])
PY
    )" || return 1
    redirect_url="$(validate_https_download_url "$redirect_url")" || return 1
    # Never forward the API Authorization header to the object-storage host.
    # curl's redirect request is intentionally a separate unauthenticated call.
    if ! code="$(curl_with_hard_output_limit "$hard_limit" \
      -q --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
      --max-filesize "$max_size" --max-redirs 5 \
      --fail-with-body -L -sS -w '%{http_code}' \
      -o "$output" "$redirect_url")"; then
      return 1
    fi
  fi
  [[ "$code" =~ ^2[0-9][0-9]$ ]] || return 1
  actual_size="$(stat -c '%s' "$output")"
  [[ "$actual_size" == "$api_size" ]] && \
    ((10#$actual_size <= 10#$max_size))
}

gh_delete_asset_id() {
  local id="$1" code url
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || return 1
  url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"
  if ! code="$(curl -q --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
    --fail-with-body -sS -w '%{http_code}' "${AUTH_HEADER[@]}" \
    -X DELETE -o /dev/null "$url")"; then return 1; fi
  [[ "$code" =~ ^20[04]$ ]]
}

release_manifest_names() {
  jq -r --arg prefix "${RELEASE_NAMESPACE}snapshot--" '
    [.[] | select((.name|startswith($prefix)) and (.name|endswith("--manifest.json"))) | .name]
    | sort | reverse | .[]' <<<"$GH_ASSETS_JSON"
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
declare -a RELEASE_COMPLETED_MANIFESTS=()
declare -a RELEASE_COMPLETED_PREFIXES=()
declare -a RELEASE_COMPLETED_CHUNK_COUNTS=()
declare -a RELEASE_CURRENT_ASSET_NAMES=()
RELEASE_VERIFIED_PIN_MANIFEST=""

validate_release_asset_registry_shape() {
  local registry_file
  registry_file="$(mktemp "${INSTALL_PATH}/_release_registry.XXXXXX.json")"
  cleanup_add_file "$registry_file"
  printf '%s' "$GH_ASSETS_JSON" >"$registry_file"
  python3 - "$registry_file" "$RELEASE_NAMESPACE" <<'PY' \
    || die "Release contains duplicate, unsafe, or non-current assets in this service namespace"
import json
import re
import sys

assets = json.load(open(sys.argv[1], "r", encoding="utf-8"))
prefix = sys.argv[2]
if not isinstance(assets, list):
    raise SystemExit(1)
generation = r"[0-9]{8}T[0-9]{15}Z-[0-9a-f]{16}-[0-9a-f]{32}"
manifest = re.compile(rf"snapshot--{generation}--manifest\.json\Z")
chunk = re.compile(rf"snapshot--{generation}--data\.tar\.zst\.gpg\.part_[0-9]{{5}}\Z")
seen = set()
for asset in assets:
    if not isinstance(asset, dict):
        raise SystemExit(1)
    name = asset.get("name")
    if not isinstance(name, str) or not name.startswith(prefix):
        continue
    identifier = asset.get("id")
    size = asset.get("size")
    if (
        name in seen
        or not isinstance(identifier, int)
        or isinstance(identifier, bool)
        or identifier <= 0
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise SystemExit(1)
    seen.add(name)
    remainder = name[len(prefix):]
    if manifest.fullmatch(remainder) is None and chunk.fullmatch(remainder) is None:
        raise SystemExit(1)
PY
  mapfile -t RELEASE_CURRENT_ASSET_NAMES < <(jq -r --arg prefix "$RELEASE_NAMESPACE" \
    '.[]|select(.name|startswith($prefix))|.name' <<<"$GH_ASSETS_JSON")
}

validate_authenticated_release_asset_registry() {
  local index name remainder generation part_index manifest_name prefix count
  local -A authenticated_index=()
  for ((index=0; index<${#RELEASE_AUTHENTICATED_MANIFESTS[@]}; index++)); do
    authenticated_index["${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"]="$index"
  done
  for name in "${RELEASE_CURRENT_ASSET_NAMES[@]}"; do
    [[ "$name" == *'--manifest.json' ]] && continue
    remainder="${name#"$RELEASE_NAMESPACE"snapshot--}"
    generation="${remainder%%--data.tar.zst.gpg.part_*}"
    part_index="${name##*.part_}"
    manifest_name="${RELEASE_NAMESPACE}snapshot--${generation}--manifest.json"
    if [[ -z "${authenticated_index[$manifest_name]+present}" ]]; then
      # A strict writer-pattern chunk whose generation has no manifest is an
      # unpublished orphan. It is ignored and never included in GC.
      continue
    fi
    index="${authenticated_index[$manifest_name]}"
    prefix="${RELEASE_AUTHENTICATED_PREFIXES[$index]}"
    count="${RELEASE_AUTHENTICATED_CHUNK_COUNTS[$index]}"
    [[ "$name" == "$prefix"* && "$part_index" =~ ^[0-9]{5}$ ]] \
      || die "Release contains a chunk outside its authenticated declaration"
    ((10#$part_index < 10#$count)) \
      || die "Release contains an extra chunk inside an authenticated generation"
  done
}

validate_release_manifest_identity() {
  local manifest_asset="$1" expected_manifest expected_prefix
  [[ "$MANIFEST_SNAPSHOT_ID" =~ ^[0-9]{8}T[0-9]{15}Z-[0-9a-f]{16}-[0-9a-f]{32}$ ]] \
    || die "Release manifest snapshot_id does not match the current writer format"
  expected_manifest="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--manifest.json"
  expected_prefix="${RELEASE_NAMESPACE}snapshot--${MANIFEST_SNAPSHOT_ID}--${ARCHIVE_NAME}.part_"
  [[ "$manifest_asset" == "$expected_manifest" ]] \
    || die "Release manifest asset name does not match authenticated snapshot_id"
  [[ "$MANIFEST_ASSET_PREFIX" == "$expected_prefix" ]] \
    || die "Release manifest chunk prefix does not match authenticated snapshot_id"
}

select_verified_release_snapshot() {
  local candidate candidate_dir candidate_encryption scan_dir cached_manifest index
  local -a candidates=()
  SELECTED_RELEASE_MANIFEST=""
  SELECTED_RELEASE_DIR=""
  SELECTED_RELEASE_PAYLOAD=""
  SELECTED_RELEASE_ENCRYPTION=""
  RELEASE_CANDIDATE_COUNT=0
  RELEASE_SELECTION_STATUS=1
  RELEASE_FAILED_MANIFESTS=()
  RELEASE_AUTHENTICATED_MANIFESTS=()
  RELEASE_AUTHENTICATED_PATHS=()
  RELEASE_AUTHENTICATED_PREFIXES=()
  RELEASE_AUTHENTICATED_CHUNK_COUNTS=()
  RELEASE_COMPLETED_MANIFESTS=()
  RELEASE_COMPLETED_PREFIXES=()
  RELEASE_COMPLETED_CHUNK_COUNTS=()
  RELEASE_CURRENT_ASSET_NAMES=()
  RELEASE_VERIFIED_PIN_MANIFEST=""
  validate_release_asset_registry_shape
  mapfile -t candidates < <(release_manifest_names)
  RELEASE_CANDIDATE_COUNT="${#candidates[@]}"
  if ((RELEASE_CANDIDATE_COUNT > 21)); then
    warn "Release contains more than 21 current snapshot manifests; refusing an unbounded authentication scan"
    RELEASE_SELECTION_STATUS=4
    return 0
  fi
  scan_dir="$(mktemp -d "${INSTALL_PATH}/_release_manifest_scan.XXXXXX")"
  cleanup_add_dir "$scan_dir"

  # Authenticate and structurally validate every bounded current manifest before
  # selecting, publishing, or allowing GC. One bad completed manifest poisons the
  # namespace rather than being hidden behind a newer valid generation.
  for ((index=0; index<${#candidates[@]}; index++)); do
    candidate="${candidates[$index]}"
    [[ -n "$candidate" ]] || continue
    cached_manifest="${scan_dir}/manifest-${index}.json"
    if ! gh_download_asset_to "$candidate" "$cached_manifest" 1048576; then
      warn "Could not download release manifest $candidate; refusing stale fallback/publication"
      RELEASE_SELECTION_STATUS=3
      return 0
    fi
    candidate_encryption="$(jq -r '.encryption // empty' \
      "$cached_manifest" 2>/dev/null)" || candidate_encryption=invalid
    if [[ "$candidate_encryption" != gpg-aes256-v1 ]] || \
       ! manifest_hmac_authenticates "$cached_manifest"; then
      warn "Current release manifest $candidate is malformed or unauthenticated"
      RELEASE_SELECTION_STATUS=2
      return 0
    fi
    validate_manifest "$cached_manifest"
    validate_manifest_schema_compatibility
    validate_release_manifest_identity "$candidate"
    RELEASE_AUTHENTICATED_MANIFESTS+=("$candidate")
    RELEASE_AUTHENTICATED_PATHS+=("$cached_manifest")
    RELEASE_AUTHENTICATED_PREFIXES+=("$MANIFEST_ASSET_PREFIX")
    RELEASE_AUTHENTICATED_CHUNK_COUNTS+=("$MANIFEST_CHUNK_COUNT")
  done
  validate_authenticated_release_asset_registry

  # Authentication/namespace validation covered every manifest above. Payload
  # verification follows newest-to-oldest fallback and stops at the first usable
  # generation, avoiding up to 21 full snapshot downloads on each periodic sync.
  for ((index=0; index<${#RELEASE_AUTHENTICATED_MANIFESTS[@]}; index++)); do
    candidate="${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"
    cached_manifest="${RELEASE_AUTHENTICATED_PATHS[$index]}"
    candidate_dir="$(mktemp -d "${INSTALL_PATH}/_release_candidate.XXXXXX")"
    cp -- "$cached_manifest" "$candidate_dir/manifest.json" \
      || die "Could not stage authenticated release manifest for verification"
    if ( trap - EXIT; download_release_snapshot "$candidate" "$candidate_dir" false true ) \
        2>/dev/null; then
      RELEASE_COMPLETED_MANIFESTS+=("$candidate")
      RELEASE_COMPLETED_PREFIXES+=("${RELEASE_AUTHENTICATED_PREFIXES[$index]}")
      RELEASE_COMPLETED_CHUNK_COUNTS+=("${RELEASE_AUTHENTICATED_CHUNK_COUNTS[$index]}")
      cleanup_add_dir "$candidate_dir"
      validate_manifest "$candidate_dir/manifest.json"
      validate_release_manifest_identity "$candidate"
      SELECTED_RELEASE_MANIFEST="$candidate"
      SELECTED_RELEASE_DIR="$candidate_dir"
      SELECTED_RELEASE_PAYLOAD="$MANIFEST_PAYLOAD_SHA"
      SELECTED_RELEASE_ENCRYPTION="$MANIFEST_ENCRYPTION"
      RELEASE_VERIFIED_PIN_MANIFEST="$candidate"
      break
    else
      warn "Release snapshot $candidate failed complete integrity verification"
      RELEASE_FAILED_MANIFESTS+=("$candidate")
      rm -rf -- "$candidate_dir"
    fi
  done
  if [[ -n "$SELECTED_RELEASE_MANIFEST" ]]; then
    RELEASE_SELECTION_STATUS=0
  else
    RELEASE_SELECTION_STATUS=1
  fi
  return 0
}

download_release_snapshot() {
  local manifest_name="$1" tmp="$2" do_import="${3:-true}" reuse_manifest="${4:-false}"
  local manifest="$tmp/manifest.json"
  local archive part_name part_path index assembled_size part_size total_size=0 max_part_size=0 free_bytes
  local -a expected_parts=()
  if [[ "$reuse_manifest" != true ]]; then
    gh_download_asset_to "$manifest_name" "$manifest" 1048576 \
      || die "Could not download release manifest $manifest_name"
  else
    [[ -f "$manifest" && ! -L "$manifest" ]] \
      || die "Downloaded release manifest is missing or unsafe"
  fi
  validate_manifest "$manifest"
  [[ -n "$MANIFEST_ASSET_PREFIX" && \
     "$MANIFEST_ASSET_PREFIX" == "${RELEASE_NAMESPACE}snapshot--"* && \
     "$MANIFEST_ASSET_PREFIX" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "Release manifest asset_prefix is outside this host namespace"
  archive="$tmp/$MANIFEST_ARCHIVE_NAME"
  rm -f -- "$archive"
  for ((index=0; index<10#$MANIFEST_CHUNK_COUNT; index++)); do
    part_name="${MANIFEST_ASSET_PREFIX}$(printf '%05d' "$index")"
    part_size="$(gh_asset_size_exact "$part_name")" \
      || die "Release snapshot has a missing or duplicate asset: $part_name"
    ((total_size += 10#$part_size))
    ((10#$part_size > max_part_size)) && max_part_size=$((10#$part_size))
    ((total_size <= 10#$MANIFEST_ARCHIVE_SIZE)) \
      || die "Release chunk metadata exceeds manifest archive size"
    expected_parts+=("$part_name:$part_size")
  done
  ((total_size == 10#$MANIFEST_ARCHIVE_SIZE)) \
    || die "Release chunk sizes do not match manifest archive size"
  free_bytes="$(df -PB1 "$tmp" | awk 'NR==2 {print $4}')"
  [[ "$free_bytes" =~ ^[0-9]+$ ]] || die "Could not determine restore disk capacity"
  ((10#$free_bytes > 10#$MANIFEST_ARCHIVE_SIZE + max_part_size)) \
    || die "Insufficient disk space for the release snapshot"

  for ((index=0; index<${#expected_parts[@]}; index++)); do
    part_name="${expected_parts[$index]%%:*}"
    part_size="${expected_parts[$index]##*:}"
    part_path="$tmp/$part_name"
    gh_download_asset_to "$part_name" "$part_path" "$part_size" \
      || die "Missing release asset $part_name"
    cat "$part_path" >>"$archive"
    rm -f -- "$part_path"
    assembled_size="$(stat -c '%s' "$archive")"
    ((10#$assembled_size <= 10#$MANIFEST_ARCHIVE_SIZE)) \
      || die "Downloaded release chunks exceed manifest archive size"
  done
  verify_archive "$archive" "$manifest"
  if [[ "$do_import" == true ]]; then
    validate_manifest_schema_compatibility
    import_payload "$archive" "$MANIFEST_ENCRYPTION"
  fi
}

cleanup_release_assets_best_effort() {
  local generation_stem="$1" assets name id
  shift
  [[ "$generation_stem" == "${RELEASE_NAMESPACE}snapshot--"* && \
     "$generation_stem" =~ ^[A-Za-z0-9._-]+$ ]] || {
    warn "Refusing cleanup for an unsafe release generation stem"
    return 0
  }
  if ! assets="$(gh_list_assets)"; then
    warn "Could not list release assets while cleaning the partial current generation"
    return 0
  fi
  for name in "$@"; do
    if [[ "$name" != "$generation_stem"* || \
          ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
      warn "Refusing cleanup for an asset outside the current release generation"
      continue
    fi
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      if [[ ! "$id" =~ ^[1-9][0-9]*$ ]]; then
        warn "Could not safely identify partial release asset $name"
        continue
      fi
      gh_delete_asset_id "$id" \
        || warn "Could not remove partial current-generation asset $name (id=$id)"
    done < <(jq -r --arg name "$name" '.[]|select(.name==$name)|.id' <<<"$assets")
  done
}

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

publish_release_snapshot() {
  local allow_pre_gc="${1:-true}" version generation_stem asset_prefix
  local manifest_asset local_manifest manifest_verify verification_dir chunk_verify
  local file suffix name remote_size local_size
  local keep_old current_assets current_manifests new_assets projected_assets index
  local selection_status
  local -a part_files=() part_names=() generation_names=()
  split_archive_into_remote
  discard_selected_release_download
  gh_refresh_assets
  select_verified_release_snapshot
  selection_status="$RELEASE_SELECTION_STATUS"
  case "$selection_status" in
    0|1) ;;
    2) die "A current release manifest is malformed or unauthenticated; refusing publication and GC" ;;
    3) die "A current release manifest could not be downloaded; refusing publication and GC" ;;
    4) die "Release snapshot manifest count exceeds the bounded current-protocol limit" ;;
    *) die "Unexpected release selection status before publication" ;;
  esac
  if ((${#RELEASE_FAILED_MANIFESTS[@]} > 0)); then
    allow_pre_gc=false
  fi
  discard_selected_release_download
  if [[ "$allow_pre_gc" == true ]]; then
    keep_old=$((10#$SYNC_RELEASE_KEEP - 1))
    ((keep_old < 1)) && keep_old=1
    gc_release_snapshots "$keep_old"
    gh_refresh_assets
  fi
  current_assets="$(jq 'length' <<<"$GH_ASSETS_JSON")"
  current_manifests="$(jq -r --arg prefix "${RELEASE_NAMESPACE}snapshot--" \
    '[.[]|select((.name|startswith($prefix)) and (.name|endswith("--manifest.json")))]|length' \
    <<<"$GH_ASSETS_JSON")"
  ((10#$current_manifests + 1 <= 21)) \
    || die "Publishing another generation would exceed the 21-manifest authentication bound"
  new_assets=0
  for file in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do
    ((new_assets+=1))
  done
  ((new_assets+=1))
  projected_assets=$((10#$current_assets + new_assets))
  ((projected_assets <= 1000)) \
    || die "Release would contain $projected_assets assets; GitHub limit is 1000. Increase SYNC_CHUNK_SIZE_MB or reduce retention"
  version="$(date -u +'%Y%m%dT%H%M%S%NZ')-${PACK_PAYLOAD_SHA:0:16}-$(openssl rand -hex 16)"
  generation_stem="${RELEASE_NAMESPACE}snapshot--${version}--"
  asset_prefix="${generation_stem}${ARCHIVE_NAME}.part_"
  manifest_asset="${generation_stem}manifest.json"

  for file in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do
    suffix="${file##*.part_}"
    [[ "$suffix" =~ ^[0-9]{5}$ ]] || die "Unsafe local release chunk suffix"
    part_files+=("$file")
    part_names+=("${asset_prefix}${suffix}")
  done
  local_manifest="${REMOTE_DIR}/${MANIFEST_NAME}"
  write_manifest "$local_manifest" "$(now_utc)" "$PACK_SIZE" "$PACK_SHA" \
    "$PACK_PAYLOAD_SHA" "$PACK_ARCHIVE_HMAC" "$PACK_ENCRYPTION" \
    "$version" "$asset_prefix"
  generation_names=("$manifest_asset" "${part_names[@]}")
  for name in "${generation_names[@]}"; do
    [[ "$(jq -r --arg name "$name" '[.[]|select(.name==$name)]|length' \
      <<<"$GH_ASSETS_JSON")" == 0 ]] \
      || die "Release generation name collision: $name"
  done

  for ((index=0; index<${#part_files[@]}; index++)); do
    if ! gh_upload_asset_as "${part_files[$index]}" "${part_names[$index]}"; then
      cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
      die "Release chunk upload failed; partial current generation cleanup was attempted"
    fi
  done
  if ! gh_refresh_assets; then
    cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
    die "Could not verify uploaded release chunks; partial current generation cleanup was attempted"
  fi
  verification_dir="$(mktemp -d "${INSTALL_PATH}/_release_verify_upload.XXXXXX")"
  cleanup_add_dir "$verification_dir"
  for ((index=0; index<${#part_files[@]}; index++)); do
    local_size="$(stat -c '%s' "${part_files[$index]}")"
    remote_size="$(gh_asset_size_exact "${part_names[$index]}")" || {
      cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
      die "Uploaded release chunk is missing or ambiguous; partial current generation cleanup was attempted"
    }
    if [[ "$remote_size" != "$local_size" ]]; then
      cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
      die "Uploaded release chunk size mismatch; partial current generation cleanup was attempted"
    fi
    chunk_verify="${verification_dir}/chunk-${index}"
    if ! gh_download_asset_to "${part_names[$index]}" "$chunk_verify" "$local_size" || \
       ! cmp -s -- "${part_files[$index]}" "$chunk_verify"; then
      cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
      die "Uploaded release chunk failed re-download verification; partial current generation cleanup was attempted"
    fi
    rm -f -- "$chunk_verify"
  done

  if ! gh_upload_asset_as "$local_manifest" "$manifest_asset"; then
    cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
    die "Release manifest upload failed or was ambiguous; partial current generation cleanup was attempted"
  fi
  manifest_verify="${verification_dir}/manifest.json"
  if ! gh_refresh_assets || \
     ! gh_download_asset_to "$manifest_asset" "$manifest_verify" 1048576 || \
     ! cmp -s -- "$local_manifest" "$manifest_verify"; then
    cleanup_release_assets_best_effort "$generation_stem" "${generation_names[@]}"
    die "Uploaded release manifest failed re-download verification; partial current generation cleanup was attempted"
  fi
  log "Published complete release snapshot $version (manifest last)"
}

gc_release_snapshots() {
  local keep="${1:-$SYNC_RELEASE_KEEP}" index part_index manifest prefix count
  local name id chunk_id matches kept=1 pin_found=false
  local -a chunk_ids=()
  local -A preserve=()
  validate_uint_range release_gc.keep "$keep" 1 20
  [[ -n "$RELEASE_VERIFIED_PIN_MANIFEST" ]] || return 0
  preserve["$RELEASE_VERIFIED_PIN_MANIFEST"]=1
  for manifest in "${RELEASE_AUTHENTICATED_MANIFESTS[@]}"; do
    [[ "$manifest" == "$RELEASE_VERIFIED_PIN_MANIFEST" ]] && pin_found=true
  done
  [[ "$pin_found" == true ]] \
    || die "Fully verified release recovery point is absent from the authenticated registry"
  for manifest in "${RELEASE_AUTHENTICATED_MANIFESTS[@]}"; do
    ((kept >= 10#$keep)) && break
    [[ "$manifest" == "$RELEASE_VERIFIED_PIN_MANIFEST" ]] && continue
    preserve["$manifest"]=1
    ((kept+=1))
  done

  for ((index=0; index<${#RELEASE_AUTHENTICATED_MANIFESTS[@]}; index++)); do
    manifest="${RELEASE_AUTHENTICATED_MANIFESTS[$index]}"
    [[ -n "${preserve[$manifest]+present}" ]] && continue
    prefix="${RELEASE_AUTHENTICATED_PREFIXES[$index]}"
    count="${RELEASE_AUTHENTICATED_CHUNK_COUNTS[$index]}"
    [[ "$manifest" == "${RELEASE_NAMESPACE}snapshot--"*"--manifest.json" && \
       "$manifest" =~ ^[A-Za-z0-9._-]+$ && \
       "$prefix" == "${RELEASE_NAMESPACE}snapshot--"*"--${ARCHIVE_NAME}.part_" && \
       "$prefix" =~ ^[A-Za-z0-9._-]+$ ]] \
      || die "Refusing GC for unsafe authenticated release metadata"
    validate_uint_range release_gc.chunk_count "$count" 1 10000
    matches="$(jq -r --arg name "$manifest" '[.[]|select(.name==$name)]|length' \
      <<<"$GH_ASSETS_JSON")"
    id="$(gh_asset_id "$manifest")"
    [[ "$matches" == 1 && "$id" =~ ^[1-9][0-9]*$ ]] \
      || die "Authenticated completed generation manifest became ambiguous before GC"
    chunk_ids=()
    for ((part_index=0; part_index<10#$count; part_index++)); do
      name="${prefix}$(printf '%05d' "$part_index")"
      matches="$(jq -r --arg name "$name" '[.[]|select(.name==$name)]|length' \
        <<<"$GH_ASSETS_JSON")"
      [[ "$matches" == 1 ]] \
        || die "Authenticated completed generation chunk became ambiguous before GC: $name"
      chunk_id="$(gh_asset_id "$name")"
      [[ "$chunk_id" =~ ^[1-9][0-9]*$ ]] \
        || die "Authenticated completed generation has an unsafe chunk id"
      chunk_ids+=("$chunk_id")
    done

    # Hide the authenticated generation first so concurrent readers never see a
    # visible manifest whose declared chunks are being removed.
    if ! gh_delete_asset_id "$id"; then
      warn "Could not delete stale authenticated release manifest $manifest; preserving its chunks"
      continue
    fi
    for id in "${chunk_ids[@]}"; do
      gh_delete_asset_id "$id" \
        || warn "Could not delete a stale authenticated release chunk id=$id"
    done
  done
}

perform_releases_sync() {
  local phase="${1:-publish}"
  local remote_present=false remote_payload="" remote_encryption=""
  local allow_pre_gc=true release_needs_repair=false selection_status
  ensure_tools_releases
  [[ "$phase" == startup || "$phase" == publish ]] \
    || die "Unknown releases sync phase: $phase"
  parse_gh_remote
  [[ -z "$SYNC_AUTH_TOKEN" || "${SYNC_READ_ONLY,,}" == true || \
     -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Release write sync requires SYNC_ENCRYPTION_PASSPHRASE"
  gh_auth_header
  gh_verify_repository_access
  gh_ensure_release "$phase"
  if [[ -z "$GH_REL_ID" ]]; then
    if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true ]]; then
      die "SYNC_FORCE_RESTORE=true was requested, but the release does not exist"
    fi
    return 0
  fi
  gh_refresh_assets

  select_verified_release_snapshot
  selection_status="$RELEASE_SELECTION_STATUS"
  if [[ "$selection_status" -eq 0 ]]; then
    remote_present=true
    remote_payload="$SELECTED_RELEASE_PAYLOAD"
    remote_encryption="$SELECTED_RELEASE_ENCRYPTION"
    if ((${#RELEASE_FAILED_MANIFESTS[@]} > 0)); then
      release_needs_repair=true
      # A failed download may be transient. Preserve every completed
      # generation until a replacement manifest has been uploaded.
      allow_pre_gc=false
    fi
  elif [[ "$selection_status" -eq 2 ]]; then
    die "A current release manifest is malformed or unauthenticated; refusing publication and GC"
  elif [[ "$selection_status" -eq 3 ]]; then
    die "A release manifest could not be downloaded; refusing stale fallback/publication"
  elif [[ "$selection_status" -eq 4 ]]; then
    die "Release snapshot manifest count exceeds the safe current-protocol bound"
  elif ((RELEASE_CANDIDATE_COUNT > 0)); then
    if [[ "$phase" == startup ]] && \
       { ! data_has_meaningful_content || [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; }; then
      die "No retained release snapshot passed complete integrity verification"
    fi
    warn "No release snapshot passed verification; preserving valid local state and all remote generations"
    allow_pre_gc=false
  fi

  if [[ "$phase" == startup && "${SYNC_FORCE_RESTORE,,}" == true && \
        "$remote_present" == false ]]; then
    die "SYNC_FORCE_RESTORE=true was requested, but no release snapshot exists"
  fi

  if [[ "$phase" == startup && "$remote_present" == true ]] && \
     { ! data_has_meaningful_content || [[ "${SYNC_FORCE_RESTORE,,}" == true ]]; }; then
    log "Restoring filesystem snapshot from release"
    verify_archive "$SELECTED_RELEASE_DIR/$MANIFEST_ARCHIVE_NAME" \
      "$SELECTED_RELEASE_DIR/manifest.json"
    import_payload "$SELECTED_RELEASE_DIR/$MANIFEST_ARCHIVE_NAME" "$MANIFEST_ENCRYPTION"
  elif [[ -z "$SYNC_AUTH_TOKEN" || "${SYNC_READ_ONLY,,}" == true ]]; then
    if [[ "$remote_present" == true ]]; then
      log "Read-only sync: preserving meaningful local data"
    else
      log "Read-only sync: no remote snapshot"
    fi
    return 0
  fi


  if [[ "$phase" == startup ]]; then
    log "Startup sync is restore-only; publication follows schema validation"
    return 0
  fi

  [[ -n "$SYNC_AUTH_TOKEN" && "${SYNC_READ_ONLY,,}" == false ]] || return 0
  if ! data_has_meaningful_content; then
    [[ "$phase" == startup ]] && { log "No meaningful local data to publish before initialization"; return 0; }
    die "Local data disappeared or is empty; publish-only sync refuses to restore or upload it"
  fi
  pack_payload
  if [[ "$remote_present" == true && "$remote_payload" == "$PACK_PAYLOAD_SHA" && \
        "$remote_encryption" == "gpg-aes256-v1" && \
        "$release_needs_repair" == false ]]; then
    log "Local snapshot and verified release remote match"
    return 0
  fi

  publish_release_snapshot "$allow_pre_gc"
  gh_refresh_assets
  discard_selected_release_download
  select_verified_release_snapshot
  selection_status="$RELEASE_SELECTION_STATUS"
  [[ "$selection_status" -eq 0 ]] \
    || die "Post-publish release verification failed; refusing GC"
  discard_selected_release_download
  gc_release_snapshots
}

sync_can_write() {
  [[ "${SYNC_ENABLED,,}" == true ]] || return 1
  [[ "${SYNC_READ_ONLY,,}" == false ]] || return 1
  case "${SYNC_METHOD,,}" in
    releases) [[ -n "$SYNC_AUTH_TOKEN" ]] ;;
    commits)
      if [[ "$GH_REMOTE" =~ ^https:// ]]; then
        [[ -n "$SYNC_AUTH_TOKEN" ]]
      else
        gh_remote_is_ssh && \
          [[ -n "$GH_SSH_PRIVATE_KEY" ]]
      fi
      ;;
  esac
}

perform_sync() {
  local phase="${1:-publish}" sync_lock_fd
  [[ "${SYNC_ENABLED,,}" == true ]] || return 0
  exec {sync_lock_fd}>/run/hexlicsrv-sync.lock
  flock -w "$SYNC_LOCK_TIMEOUT_SECONDS" -x "$sync_lock_fd" \
    || die "Timed out waiting for the sync lock"
  case "${SYNC_METHOD,,}" in
    commits) perform_commits_sync "$phase" ;;
    releases) perform_releases_sync "$phase" ;;
  esac
  rm -f -- "$ARCHIVE_PATH"
  if [[ -n "$AUTH_HEADER_FILE" ]]; then
    rm -f -- "$AUTH_HEADER_FILE"
    AUTH_HEADER_FILE=""
    AUTH_HEADER=()
  fi
  flock -u "$sync_lock_fd"
  exec {sync_lock_fd}>&-
}

run_as_service() {
  local uid gid
  uid="$(id -u "$SERVICE_USER")"; gid="$(id -g "$SERVICE_USER")"
  setpriv --reuid "$uid" --regid "$gid" --init-groups \
    --inh-caps=-all --ambient-caps=-all \
    env -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
      -u GH_SSH_PRIVATE_KEY -u GIT_SSH_COMMAND \
      HOME=/var/lib/hexlicsrv USER="$SERVICE_USER" LOGNAME="$SERVICE_USER" \
      XDG_DATA_HOME=/var/lib/hexlicsrv/.local/share \
      XDG_CONFIG_HOME=/var/lib/hexlicsrv/.config "$@"
}

tls_pair_is_valid() {
  local cert="$1" key="$2" minimum_seconds="${3:-0}"
  local -a name_check
  if [[ "$LICENSE_HOST_KIND" == ip ]]; then
    name_check=(-checkip "$LICENSE_HOST")
  else
    name_check=(-checkhost "$LICENSE_HOST")
  fi
  [[ -s "$cert" && -s "$key" && ! -L "$cert" && ! -L "$key" ]] && \
    openssl x509 -in "$cert" -noout -checkend "$minimum_seconds" >/dev/null 2>&1 && \
    openssl x509 -in "$cert" -noout "${name_check[@]}" >/dev/null 2>&1 && \
    openssl verify -CAfile "${CA_PATH}/CA.pem" "$cert" >/dev/null 2>&1 && \
    openssl x509 -in "$cert" -noout -modulus 2>/dev/null | sha256sum | \
      cmp -s - <(openssl rsa -in "$key" -noout -modulus 2>/dev/null | sha256sum)
}

cleanup_stale_tls_artifacts() {
  local target removed=false
  local -a candidates=(
    "${CONFIG_PATH}"/.hexlicsrv.key.*
    "${CONFIG_PATH}"/.hexlicsrv.csr.*
    "${CONFIG_PATH}"/.hexlicsrv.crt.*
    "${CONFIG_PATH}"/.CA.srl.*
    "${CONFIG_PATH}"/.hexlicsrv.previous.crt.*
    "${CONFIG_PATH}"/.hexlicsrv.previous.key.*
    "${CONFIG_PATH}"/.hexlicsrv.recover.crt.*
    "${CONFIG_PATH}"/.hexlicsrv.recover.key.*
    "${CONFIG_PATH}"/.tls-renewal-in-progress.*
  )
  [[ "$CONFIG_PATH" == /opt/hexlicsrv/config ]] \
    || die "Refusing TLS cleanup for an unexpected configuration path"
  if [[ ! -e "${CONFIG_PATH}/.tls-renewal-in-progress" && \
        ! -L "${CONFIG_PATH}/.tls-renewal-in-progress" ]]; then
    for target in "${CONFIG_PATH}/.hexlicsrv.previous.crt" \
        "${CONFIG_PATH}/.hexlicsrv.previous.key"; do
      [[ ! -e "$target" && ! -L "$target" ]] || candidates+=("$target")
    done
  fi
  for target in "${candidates[@]}"; do
    [[ -f "$target" || -L "$target" ]] \
      || die "Refusing to remove non-file TLS artifact: $target"
    rm -f -- "$target"
    removed=true
  done
  if [[ "$removed" == true ]]; then
    sync -f "$CONFIG_PATH" || die "Could not durably remove stale TLS artifacts"
  fi
}

recover_interrupted_tls_renewal() {
  local cert="$1" key="$2" marker="$3" previous_cert="$4" previous_key="$5"
  local recover_cert recover_key service_gid
  [[ -e "$marker" ]] || return 0
  [[ -f "$marker" && ! -L "$marker" ]] \
    || die "Unsafe TLS renewal transaction marker"
  warn "Recovering an interrupted TLS certificate renewal"
  if tls_pair_is_valid "$cert" "$key" 0; then
    rm -f -- "$marker" "$previous_cert" "$previous_key"
    sync -f "$CONFIG_PATH" || die "Could not durably clear completed TLS recovery state"
    log "Completed TLS renewal pair was already valid"
    return 0
  fi
  if ! tls_pair_is_valid "$previous_cert" "$previous_key" 0; then
    warn "No valid previous TLS pair is available; generating a fresh pair"
    return 0
  fi

  recover_cert="$(mktemp "${CONFIG_PATH}/.hexlicsrv.recover.crt.XXXXXX")"
  recover_key="$(mktemp "${CONFIG_PATH}/.hexlicsrv.recover.key.XXXXXX")"
  cleanup_add_file "$recover_cert"; cleanup_add_file "$recover_key"
  cp -- "$previous_cert" "$recover_cert" && cp -- "$previous_key" "$recover_key" \
    || die "Could not stage the previous TLS pair for recovery"
  service_gid="$(id -g "$SERVICE_USER")"
  chown root:"$service_gid" "$recover_cert" "$recover_key"
  chmod 640 "$recover_cert" "$recover_key"
  mv -f -- "$recover_key" "$key"
  mv -f -- "$recover_cert" "$cert"
  sync -f "$CONFIG_PATH" || die "Could not durably restore the previous TLS pair"
  tls_pair_is_valid "$cert" "$key" 0 \
    || die "Previous TLS pair could not be restored; transaction state was preserved"
  rm -f -- "$marker" "$previous_cert" "$previous_key"
  sync -f "$CONFIG_PATH" || die "Could not durably commit TLS recovery"
  log "Restored the previous TLS certificate/key pair"
}

ensure_tls_certificate() {
  local cert="${CONFIG_PATH}/hexlicsrv.crt" key="${CONFIG_PATH}/hexlicsrv.key"
  local renew=true openssl_cfg san_entry
  local path tmp_key tmp_csr tmp_cert tmp_serial service_gid
  local marker="${CONFIG_PATH}/.tls-renewal-in-progress"
  local previous_cert="${CONFIG_PATH}/.hexlicsrv.previous.crt"
  local previous_key="${CONFIG_PATH}/.hexlicsrv.previous.key"
  local marker_tmp previous_cert_tmp previous_key_tmp commit_signal=""
  local -a cert_name_check
  for path in "$cert" "$key" "${CONFIG_PATH}/hexlicsrv.csr" \
      "${CONFIG_PATH}/CA.srl" "$marker" "$previous_cert" "$previous_key"; do
    [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] \
      || die "Refusing unsafe TLS path: $path"
  done
  if [[ "$LICENSE_HOST_KIND" == ip ]]; then
    cert_name_check=(-checkip "$LICENSE_HOST")
    san_entry="IP.1=${LICENSE_HOST}"
  else
    cert_name_check=(-checkhost "$LICENSE_HOST")
    san_entry="DNS.1=${LICENSE_HOST}"
  fi
  recover_interrupted_tls_renewal \
    "$cert" "$key" "$marker" "$previous_cert" "$previous_key"
  cleanup_stale_tls_artifacts
  if tls_pair_is_valid "$cert" "$key" 2592000; then
    renew=false
  fi
  [[ "$renew" == true ]] || { log "Using existing valid TLS certificate"; return 0; }
  [[ -s "${CA_PATH}/CA.pem" && -s "$CA_KEY_FILE" ]] \
    || die "Missing CA.pem or CA.key required for TLS certificate generation"
  openssl x509 -in "${CA_PATH}/CA.pem" -noout -pubkey 2>/dev/null | sha256sum | \
    cmp -s - <(openssl pkey -in "$CA_KEY_FILE" -pubout 2>/dev/null | sha256sum) \
    || die "CA.pem does not match the mounted CA.key"

  openssl_cfg="$(mktemp)"; cleanup_add_file "$openssl_cfg"
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
  tmp_key="$(mktemp "${CONFIG_PATH}/.hexlicsrv.key.XXXXXX")"
  tmp_csr="$(mktemp "${CONFIG_PATH}/.hexlicsrv.csr.XXXXXX")"
  tmp_cert="$(mktemp "${CONFIG_PATH}/.hexlicsrv.crt.XXXXXX")"
  tmp_serial="$(mktemp "${CONFIG_PATH}/.CA.srl.XXXXXX")"
  cleanup_add_file "$tmp_key"; cleanup_add_file "$tmp_csr"
  cleanup_add_file "$tmp_cert"; cleanup_add_file "$tmp_serial"
  rm -f -- "$tmp_serial"
  if [[ -s "${CONFIG_PATH}/CA.srl" ]]; then
    cp -- "${CONFIG_PATH}/CA.srl" "$tmp_serial" \
      || die "Could not stage the CA serial file"
  fi

  openssl req -newkey rsa:3072 -nodes -keyout "$tmp_key" \
    -out "$tmp_csr" -subj "/CN=${LICENSE_HOST}" \
    -config "$openssl_cfg" -reqexts v3_req >/dev/null 2>&1 \
    || die "TLS CSR generation failed"
  openssl x509 -req -in "$tmp_csr" \
    -CA "${CA_PATH}/CA.pem" -CAkey "$CA_KEY_FILE" \
    -CAserial "$tmp_serial" -CAcreateserial \
    -out "$tmp_cert" -days 365 -sha512 -extensions v3_req -extfile "$openssl_cfg" \
    >/dev/null 2>&1 || die "TLS certificate signing failed"

  openssl x509 -in "$tmp_cert" -noout -checkend 86400 >/dev/null 2>&1 && \
    openssl x509 -in "$tmp_cert" -noout "${cert_name_check[@]}" >/dev/null 2>&1 && \
    openssl verify -CAfile "${CA_PATH}/CA.pem" "$tmp_cert" >/dev/null 2>&1 && \
    openssl x509 -in "$tmp_cert" -noout -modulus 2>/dev/null | sha256sum | \
      cmp -s - <(openssl rsa -in "$tmp_key" -noout -modulus 2>/dev/null | sha256sum) \
    || die "Generated TLS certificate/key pair failed validation"

  service_gid="$(id -g "$SERVICE_USER")"
  chown root:"$service_gid" "$tmp_key" "$tmp_cert" "$tmp_serial"
  chmod 640 "$tmp_key" "$tmp_cert" "$tmp_serial"

  rm -f -- "$previous_cert" "$previous_key"
  if tls_pair_is_valid "$cert" "$key" 0; then
    previous_cert_tmp="$(mktemp "${CONFIG_PATH}/.hexlicsrv.previous.crt.XXXXXX")"
    previous_key_tmp="$(mktemp "${CONFIG_PATH}/.hexlicsrv.previous.key.XXXXXX")"
    cleanup_add_file "$previous_cert_tmp"; cleanup_add_file "$previous_key_tmp"
    cp -- "$cert" "$previous_cert_tmp" && cp -- "$key" "$previous_key_tmp" \
      || die "Could not stage the previous TLS pair"
    chown root:"$service_gid" "$previous_cert_tmp" "$previous_key_tmp"
    chmod 640 "$previous_cert_tmp" "$previous_key_tmp"
    mv -f -- "$previous_cert_tmp" "$previous_cert"
    mv -f -- "$previous_key_tmp" "$previous_key"
  fi
  marker_tmp="$(mktemp "${CONFIG_PATH}/.tls-renewal-in-progress.XXXXXX")"
  cleanup_add_file "$marker_tmp"
  printf '%s\n' 'tls-renewal-v1' >"$marker_tmp"
  chown root:"$service_gid" "$marker_tmp"
  chmod 640 "$marker_tmp"
  mv -f -- "$marker_tmp" "$marker"
  sync -f "$marker" "$CONFIG_PATH" \
    || die "Could not durably begin TLS renewal"

  # The marker and previous pair make the short rename commit recoverable after
  # SIGKILL. TERM/INT are remembered (not discarded) until the transaction is
  # fully validated and its marker has been durably cleared.
  trap 'commit_signal=TERM' TERM
  trap 'commit_signal=INT' INT
  mv -f -- "$tmp_serial" "${CONFIG_PATH}/CA.srl"
  mv -f -- "$tmp_key" "$key"
  mv -f -- "$tmp_cert" "$cert"
  sync -f "$CONFIG_PATH" || die "Could not durably install the new TLS pair"
  tls_pair_is_valid "$cert" "$key" 0 \
    || die "Installed TLS pair failed validation; recovery state was preserved"
  rm -f -- "$marker" "$previous_cert" "$previous_key"
  rm -f -- "$tmp_csr" "${CONFIG_PATH}/hexlicsrv.csr"
  sync -f "$CONFIG_PATH" || die "Could not durably commit TLS renewal"
  trap - TERM INT
  log "Generated a new TLS certificate"
  if [[ "$commit_signal" == TERM ]]; then
    warn "Stopping after completing the TLS renewal transaction"
    exit 143
  elif [[ "$commit_signal" == INT ]]; then
    warn "Interrupted after completing the TLS renewal transaction"
    exit 130
  fi
}

write_schema_marker() {
  local expected_fingerprint="${1:-}" tmp fingerprint
  sqlite_schema_state "$DB_FILE" \
    || die "Refusing to write a marker for an invalid SQLite schema"
  [[ ! -L "$SCHEMA_MARKER" ]] || die "Unsafe schema marker target"
  [[ ! -e "$SCHEMA_MARKER" || -f "$SCHEMA_MARKER" ]] \
    || die "Schema marker target is not a regular file"
  fingerprint="$(compute_schema_fingerprint "$DB_FILE")" \
    || die "Could not fingerprint the initialized SQLite schema"
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] \
    || die "Initialized SQLite schema fingerprint is malformed"
  if [[ -n "$expected_fingerprint" ]]; then
    [[ "$expected_fingerprint" =~ ^[0-9a-f]{64}$ && \
       "$fingerprint" == "$expected_fingerprint" ]] \
      || die "SQLite schema changed during exact-current marker adoption"
  fi
  tmp="$(mktemp "${RECOVERY_PATH}/.schema-state.XXXXXX")"
  cleanup_add_file "$tmp"
  jq -n --argjson schema_version "$SCHEMA_VERSION" \
    --arg schema_fingerprint_sha256 "$fingerprint" \
    '{format_version:1,schema_version:$schema_version,
      schema_fingerprint_sha256:$schema_fingerprint_sha256}' >"$tmp"
  chown root:root "$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$SCHEMA_MARKER"
  sync -f "$SCHEMA_MARKER" "$RECOVERY_PATH" \
    || die "Could not durably write the schema marker"
}

adopt_unmarked_current_schema() {
  local state reference_dir reference_db reference_config reference_connection
  local live_fingerprint reference_fingerprint service_uid service_gid
  set +e
  sqlite_schema_state "$DB_FILE"
  state=$?
  set -e
  [[ "$state" -eq 0 ]] || return 0

  if [[ -e "$SCHEMA_MARKER" || -L "$SCHEMA_MARKER" ]]; then
    validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
    ((10#$LOADED_SCHEMA_VERSION <= 10#$SCHEMA_VERSION)) \
      || die "Database schema marker $LOADED_SCHEMA_VERSION is newer than image schema $SCHEMA_VERSION; refusing downgrade"
    return 0
  fi

  # A data bind can survive while the separately-mounted recovery directory is
  # new. Never infer a version merely from a readable SQLite file: generate the
  # exact current schema in an isolated database and compare canonical DDL
  # fingerprints before creating the missing identity marker.
  [[ ! -e "$SCHEMA_INIT_MARKER" && ! -L "$SCHEMA_INIT_MARKER" && \
     ! -e "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     ! -e "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
     ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
     ! -e "$RESTORE_MARKER" && ! -L "$RESTORE_MARKER" ]] \
    || die "Cannot adopt an unmarked schema while a recovery transaction exists"

  reference_dir="$(mktemp -d /run/hexlicsrv-schema-reference.XXXXXX)"
  cleanup_add_dir "$reference_dir"
  service_uid="$(id -u "$SERVICE_USER")"
  service_gid="$(id -g "$SERVICE_USER")"
  chown "$service_uid:$service_gid" "$reference_dir"
  chmod 700 "$reference_dir"
  reference_db="${reference_dir}/hexlicsrv.sqlite3"
  reference_config="${reference_dir}/hexlicsrv.conf"
  reference_connection="sqlite3;Data Source=${reference_db};"
  printf '%s\n' "$reference_connection" >"$reference_config"
  chown "$service_uid:$service_gid" "$reference_config"
  chmod 600 "$reference_config"

  log "Verifying an existing unmarked SQLite schema against image version ${SCHEMA_VERSION}"
  if ! run_as_service "${INSTALL_PATH}/license_server" \
      -f "$reference_config" -C "$reference_connection" --recreate-schema; then
    die "Could not generate the isolated current-schema reference database"
  fi
  sqlite_schema_state "$reference_db" \
    || die "Isolated current-schema reference database failed validation"
  live_fingerprint="$(compute_schema_fingerprint "$DB_FILE")" \
    || die "Could not fingerprint the existing unmarked SQLite schema"
  reference_fingerprint="$(compute_schema_fingerprint "$reference_db")" \
    || die "Could not fingerprint the isolated current-schema reference"
  [[ "$live_fingerprint" =~ ^[0-9a-f]{64}$ && \
     "$reference_fingerprint" =~ ^[0-9a-f]{64}$ ]] \
    || die "Current-schema comparison produced a malformed fingerprint"
  [[ "$live_fingerprint" == "$reference_fingerprint" ]] \
    || die "Existing unmarked SQLite schema is not the exact current image schema; refusing automatic adoption"

  write_schema_marker "$reference_fingerprint"
  rm -rf -- "$reference_dir"
  cleanup_remove_dir "$reference_dir"
  log "Adopted an exact current SQLite schema and created its missing marker"
}

write_schema_init_marker() {
  local tmp
  [[ ! -e "$SCHEMA_INIT_MARKER" && ! -L "$SCHEMA_INIT_MARKER" ]] \
    || die "Schema initialization marker already exists or is unsafe"
  tmp="$(mktemp "${RECOVERY_PATH}/.schema-initializing.XXXXXX")"
  cleanup_add_file "$tmp"
  printf '%s\n' 'schema-initializing-v1' >"$tmp"
  chown root:root "$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$SCHEMA_INIT_MARKER"
  sync -f "$SCHEMA_INIT_MARKER" "$RECOVERY_PATH" \
    || die "Could not durably begin schema initialization"
}

clear_schema_upgrade_transaction() {
  rm -f -- "$SCHEMA_UPGRADE_BACKUP"
  sync -f "$RECOVERY_PATH" \
    || die "Could not durably clear the schema upgrade database backup"
  rm -f -- "$SCHEMA_UPGRADE_MARKER_BACKUP"
  sync -f "$RECOVERY_PATH" \
    || die "Could not durably clear the schema upgrade marker backup"
}

restore_schema_upgrade_backup() {
  local restored restored_marker
  [[ -f "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     -s "$SCHEMA_UPGRADE_BACKUP" ]] \
    || die "Schema upgrade recovery database is missing or unsafe"
  [[ -f "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
     ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
     -s "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] \
    || die "Schema upgrade recovery marker is missing or unsafe"
  sqlite_schema_state "$SCHEMA_UPGRADE_BACKUP" \
    || die "Schema upgrade recovery backup is invalid; preserving it for manual recovery"
  validate_schema_marker_against_database \
    "$SCHEMA_UPGRADE_MARKER_BACKUP" "$SCHEMA_UPGRADE_BACKUP"
  restored="$(mktemp "${DATA_PATH}/.hexlicsrv.restore.XXXXXX.sqlite3")"
  restored_marker="$(mktemp "${RECOVERY_PATH}/.schema-state.restore.XXXXXX")"
  cleanup_add_file "$restored"
  cleanup_add_file "$restored_marker"
  cp -- "$SCHEMA_UPGRADE_BACKUP" "$restored" \
    || die "Could not copy the schema upgrade recovery database"
  cp -- "$SCHEMA_UPGRADE_MARKER_BACKUP" "$restored_marker" \
    || die "Could not copy the schema upgrade recovery marker"
  chown "$(id -u "$SERVICE_USER"):$(id -g "$SERVICE_USER")" "$restored"
  chown root:root "$restored_marker"
  chmod 600 "$restored"
  chmod 600 "$restored_marker"
  [[ ! -L "$DB_FILE" && ( ! -e "$DB_FILE" || -f "$DB_FILE" ) && \
     ! -L "$SCHEMA_MARKER" && \
     ( ! -e "$SCHEMA_MARKER" || -f "$SCHEMA_MARKER" ) ]] \
    || die "Unsafe SQLite/schema marker target during upgrade recovery"
  rm -f -- "${DB_FILE}-wal" "${DB_FILE}-shm" "${DB_FILE}-journal"
  mv -f -- "$restored" "$DB_FILE"
  mv -f -- "$restored_marker" "$SCHEMA_MARKER"
  sync -f "$DATA_PATH" "$RECOVERY_PATH" \
    || die "Could not durably restore the pre-upgrade schema"
  sqlite_schema_state "$DB_FILE" \
    || die "Recovered pre-upgrade SQLite database failed validation"
  validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
}

recover_interrupted_schema_upgrade() {
  local current_state marker_status=1
  local db_backup_present=false marker_backup_present=false
  [[ -e "$SCHEMA_UPGRADE_BACKUP" || -L "$SCHEMA_UPGRADE_BACKUP" ]] && \
    db_backup_present=true
  [[ -e "$SCHEMA_UPGRADE_MARKER_BACKUP" || \
     -L "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] && marker_backup_present=true
  if [[ "$db_backup_present" == false && "$marker_backup_present" == false ]]; then
    return 0
  fi
  if [[ "$db_backup_present" == false && "$marker_backup_present" == true ]]; then
    [[ -f "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
       ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] \
      || die "Unsafe orphaned schema marker backup"
    validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
    if [[ "$LOADED_SCHEMA_VERSION" != "$SCHEMA_VERSION" ]] && \
       ! cmp -s -- "$SCHEMA_MARKER" "$SCHEMA_UPGRADE_MARKER_BACKUP"; then
      die "Orphaned schema marker backup does not match a completed or not-yet-started upgrade"
    fi
    rm -f -- "$SCHEMA_UPGRADE_MARKER_BACKUP"
    sync -f "$RECOVERY_PATH" || die "Could not clear orphaned schema marker backup"
    return 0
  fi
  [[ "$db_backup_present" == true && "$marker_backup_present" == true ]] \
    || die "Incomplete schema upgrade recovery transaction"
  [[ -f "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
     -f "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
     ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] \
    || die "Unsafe schema upgrade recovery transaction"
  sqlite_schema_state "$SCHEMA_UPGRADE_BACKUP" \
    || die "Interrupted-upgrade backup is invalid; preserving $SCHEMA_UPGRADE_BACKUP"
  set +e
  sqlite_schema_state "$DB_FILE"
  current_state=$?
  if [[ "$current_state" -eq 0 ]]; then
    ( validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE" ) \
      >/dev/null 2>&1
    marker_status=$?
  fi
  set -e
  if [[ "$current_state" -eq 0 && "$marker_status" -eq 0 ]]; then
    validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
  fi
  if [[ "$current_state" -eq 0 && "$marker_status" -eq 0 && \
        "$LOADED_SCHEMA_VERSION" == "$SCHEMA_VERSION" ]]; then
    log "Removing stale pre-upgrade backup after a verified completed upgrade"
    clear_schema_upgrade_transaction
    return 0
  fi
  warn "Recovering the pre-upgrade SQLite database after an interrupted schema upgrade"
  restore_schema_upgrade_backup
  ((10#$LOADED_SCHEMA_VERSION < 10#$SCHEMA_VERSION)) \
    || die "Recovered schema marker is not older than the image schema"
  clear_schema_upgrade_transaction
}

discard_partial_schema_initialization() {
  rm -f -- "$DB_FILE" "${DB_FILE}-wal" "${DB_FILE}-shm" \
    "${DB_FILE}-journal" "$SCHEMA_MARKER"
  sync -f "$DATA_PATH" "$RECOVERY_PATH" \
    || die "Could not durably discard partial schema initialization"
}

recover_interrupted_schema_initialization() {
  [[ -e "$SCHEMA_INIT_MARKER" || -L "$SCHEMA_INIT_MARKER" ]] || return 0
  [[ -f "$SCHEMA_INIT_MARKER" && ! -L "$SCHEMA_INIT_MARKER" ]] \
    || die "Unsafe schema-initialization marker; refusing automatic recovery"
  warn "Discarding a partial SQLite database left by interrupted schema initialization"
  discard_partial_schema_initialization
  rm -f -- "$SCHEMA_INIT_MARKER"
  sync -f "$RECOVERY_PATH" || die "Could not durably clear partial schema initialization"
}

ensure_schema() {
  local state backup_tmp="" marker_backup_tmp=""
  recover_interrupted_schema_upgrade
  set +e
  sqlite_schema_state "$DB_FILE"
  state=$?
  set -e
  case "$state" in
    0)
      validate_schema_marker_against_database "$SCHEMA_MARKER" "$DB_FILE"
      ((10#$LOADED_SCHEMA_VERSION <= 10#$SCHEMA_VERSION)) \
        || die "Database schema marker $LOADED_SCHEMA_VERSION is newer than image schema $SCHEMA_VERSION; refusing downgrade"
      if [[ "$LOADED_SCHEMA_VERSION" == "$SCHEMA_VERSION" ]]; then
        chown root:root "$SCHEMA_MARKER"
        chmod 600 "$SCHEMA_MARKER"
        log "Existing SQLite schema version ${SCHEMA_VERSION} verified"
        return 0
      fi

      [[ ! -e "$SCHEMA_UPGRADE_BACKUP" && ! -L "$SCHEMA_UPGRADE_BACKUP" && \
         ! -e "$SCHEMA_UPGRADE_MARKER_BACKUP" && \
         ! -L "$SCHEMA_UPGRADE_MARKER_BACKUP" ]] \
        || die "Schema upgrade transaction targets already exist"
      backup_tmp="$(mktemp "${RECOVERY_PATH}/.preupgrade.XXXXXX.tmp")"
      marker_backup_tmp="$(mktemp "${RECOVERY_PATH}/.preupgrade-schema-state.XXXXXX.tmp")"
      cleanup_add_file "$backup_tmp"
      cleanup_add_file "$marker_backup_tmp"
      sqlite3 -readonly -cmd '.timeout 10000' "$DB_FILE" ".backup '$backup_tmp'" \
        || die "Could not back up SQLite before schema upgrade"
      sqlite_schema_state "$backup_tmp" \
        || die "Pre-upgrade SQLite backup failed validation"
      cp -- "$SCHEMA_MARKER" "$marker_backup_tmp" \
        || die "Could not back up the schema marker before upgrade"
      validate_schema_marker_against_database "$marker_backup_tmp" "$backup_tmp"
      chown root:root "$backup_tmp" "$marker_backup_tmp"
      chmod 600 "$backup_tmp" "$marker_backup_tmp"
      mv -f -- "$marker_backup_tmp" "$SCHEMA_UPGRADE_MARKER_BACKUP"
      sync -f "$SCHEMA_UPGRADE_MARKER_BACKUP" "$RECOVERY_PATH" \
        || die "Could not durably stage the pre-upgrade schema marker"
      mv -f -- "$backup_tmp" "$SCHEMA_UPGRADE_BACKUP"
      sync -f "$SCHEMA_UPGRADE_BACKUP" "$RECOVERY_PATH" \
        || die "Could not durably stage the pre-upgrade database"
      log "Upgrading existing SQLite schema to image version ${SCHEMA_VERSION}"
      if ! run_as_service "${INSTALL_PATH}/license_server" \
          -f "$CONFIG_FILE" -C "$DB_CONNECTION" \
          -c "${CONFIG_PATH}/hexlicsrv.crt" \
          -k "${CONFIG_PATH}/hexlicsrv.key" \
          -L "${INSTALL_PATH}/license_server.hexlic" --upgrade-schema; then
        restore_schema_upgrade_backup
        clear_schema_upgrade_transaction
        die "Schema upgrade failed; the pre-upgrade database was restored"
      fi
      if ! sqlite_schema_state "$DB_FILE"; then
        restore_schema_upgrade_backup
        clear_schema_upgrade_transaction
        die "Upgraded schema failed validation; the pre-upgrade database was restored"
      fi
      write_schema_marker
      clear_schema_upgrade_transaction
      ;;
    1)
      [[ ! -L "$DB_FILE" ]] || die "Refusing symlinked SQLite database target"
      [[ ! -e "$SCHEMA_MARKER" && ! -L "$SCHEMA_MARKER" ]] \
        || die "Empty database has an unexpected schema marker; refusing recreation"
      log "Initializing schema in an empty SQLite database"
      write_schema_init_marker
      if ! run_as_service "${INSTALL_PATH}/license_server" \
          -f "$CONFIG_FILE" -C "$DB_CONNECTION" --recreate-schema; then
        discard_partial_schema_initialization
        rm -f -- "$SCHEMA_INIT_MARKER"
        sync -f "$RECOVERY_PATH" || die "Could not durably abort schema initialization"
        die "Schema initialization failed; the partial SQLite database was removed"
      fi
      if ! sqlite_schema_state "$DB_FILE"; then
        discard_partial_schema_initialization
        rm -f -- "$SCHEMA_INIT_MARKER"
        sync -f "$RECOVERY_PATH" || die "Could not durably abort invalid schema initialization"
        die "Schema initialization produced an invalid database; it was removed"
      fi
      write_schema_marker
      rm -f -- "$SCHEMA_INIT_MARKER"
      sync -f "$RECOVERY_PATH" || die "Could not durably commit schema initialization"
      ;;
    2)
      die "Existing SQLite database is unreadable; refusing destructive schema recreation"
      ;;
  esac
}

periodic_sync_loop() {
  local active_pid="" sleep_pid="" sync_status=0 stop_requested=false
  trap - EXIT
  request_periodic_stop() {
    stop_requested=true
    [[ -z "$sleep_pid" ]] || kill -TERM "$sleep_pid" 2>/dev/null || true
    [[ -z "$active_pid" ]] || kill -TERM -- "-$active_pid" 2>/dev/null || true
  }
  trap request_periodic_stop TERM INT

  while :; do
    sleep "$SYNC_INTERVAL_SECONDS" &
    sleep_pid=$!
    wait "$sleep_pid" 2>/dev/null || true
    sleep_pid=""
    [[ "$stop_requested" == false ]] || break

    log "Starting periodic sync"
    [[ "$stop_requested" == false ]] || break
    set +e
    SYNC_AUTH_TOKEN="$SYNC_AUTH_TOKEN" \
      SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
      GH_SSH_PRIVATE_KEY="$GH_SSH_PRIVATE_KEY" \
      setsid /entrypoint.sh __hexlicsrv_sync_publish &
    active_pid=$!
    if [[ "$stop_requested" == true ]]; then
      kill -TERM -- "-$active_pid" 2>/dev/null || true
    fi
    wait "$active_pid"
    sync_status=$?
    set -e
    if [[ "$stop_requested" == true ]]; then
      for _ in {1..100}; do
        kill -0 -- "-$active_pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 -- "-$active_pid" 2>/dev/null; then
        warn "Periodic sync did not stop promptly; killing its process group"
        kill -KILL -- "-$active_pid" 2>/dev/null || true
      fi
      wait "$active_pid" 2>/dev/null || true
      active_pid=""
      break
    fi
    active_pid=""
    if [[ "$sync_status" -eq 0 ]]; then
      log "Periodic sync completed"
    else
      warn "Periodic sync failed; the server remains running"
    fi
  done
}

terminate_sync_process_group() {
  local pgid="$1" description="$2"
  local attempt
  [[ "$pgid" =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM -- "-$pgid" 2>/dev/null || true
  for attempt in {1..100}; do
    kill -0 -- "-$pgid" 2>/dev/null || return 0
    sleep 0.1
  done
  if kill -0 -- "-$pgid" 2>/dev/null; then
    warn "$description did not stop after TERM; killing its process group"
    kill -KILL -- "-$pgid" 2>/dev/null || true
  fi
}

run_final_publish_bounded() {
  local final_pid watchdog_pid final_status=0
  local timeout_marker soft_timeout

  timeout_marker="$(mktemp /run/hexlicsrv-final-sync-timeout.XXXXXX)"
  cleanup_add_file "$timeout_marker"
  chmod 600 "$timeout_marker"
  soft_timeout=$((10#$SYNC_FINAL_TIMEOUT_SECONDS - 10))

  SYNC_AUTH_TOKEN="$SYNC_AUTH_TOKEN" \
    SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
    GH_SSH_PRIVATE_KEY="$GH_SSH_PRIVATE_KEY" \
    setsid /entrypoint.sh __hexlicsrv_sync_publish &
  final_pid=$!
  trap 'kill -TERM -- "-$final_pid" 2>/dev/null || true' TERM INT
  (
    trap - EXIT TERM INT
    sleep "$soft_timeout"
    if kill -0 -- "-$final_pid" 2>/dev/null; then
      printf '%s\n' timeout >"$timeout_marker"
      kill -TERM -- "-$final_pid" 2>/dev/null || true
      sleep 10
      kill -KILL -- "-$final_pid" 2>/dev/null || true
    fi
  ) &
  watchdog_pid=$!

  set +e
  while :; do
    wait "$final_pid"
    final_status=$?
    kill -0 "$final_pid" 2>/dev/null || break
  done
  set -e

  kill -TERM "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  trap - TERM INT

  if kill -0 -- "-$final_pid" 2>/dev/null; then
    [[ -s "$timeout_marker" ]] || printf '%s\n' orphaned >"$timeout_marker"
    if [[ "$(<"$timeout_marker")" == timeout ]]; then
      kill -KILL -- "-$final_pid" 2>/dev/null || true
    else
      terminate_sync_process_group "$final_pid" "Final shutdown sync"
    fi
  fi
  if [[ -s "$timeout_marker" ]]; then
    warn "Final shutdown sync exceeded its ${SYNC_FINAL_TIMEOUT_SECONDS}s process-group deadline"
    return 124
  fi
  return "$final_status"
}

supervise_server() {
  local app_pid sync_pid="" status=0 stopping=false
  local -a command=(
    "${INSTALL_PATH}/license_server"
    -f "$CONFIG_FILE"
    -C "$DB_CONNECTION"
    -p "$LICENSE_PORT"
    -c "${CONFIG_PATH}/hexlicsrv.crt"
    -k "${CONFIG_PATH}/hexlicsrv.key"
    -L "${INSTALL_PATH}/license_server.hexlic"
  )

  (
    local uid gid
    uid="$(id -u "$SERVICE_USER")"; gid="$(id -g "$SERVICE_USER")"
    exec setpriv --reuid "$uid" --regid "$gid" --init-groups \
      --inh-caps=-all --ambient-caps=-all \
      env -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
        -u GH_SSH_PRIVATE_KEY -u GIT_SSH_COMMAND \
        HOME=/var/lib/hexlicsrv USER="$SERVICE_USER" LOGNAME="$SERVICE_USER" \
        XDG_DATA_HOME=/var/lib/hexlicsrv/.local/share \
        XDG_CONFIG_HOME=/var/lib/hexlicsrv/.config "${command[@]}"
  ) &
  app_pid=$!
  log "Started license_server as ${SERVICE_USER} (pid=$app_pid, port=$LICENSE_PORT)"

  if sync_can_write && ((10#$SYNC_INTERVAL_SECONDS > 0)); then
    periodic_sync_loop &
    sync_pid=$!
  fi

  request_stop() {
    stopping=true
    log "Forwarding shutdown signal to license_server"
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
    kill -TERM "$sync_pid" 2>/dev/null || true
    wait "$sync_pid" 2>/dev/null || true
  fi
  if [[ "$stopping" == true ]] && sync_can_write; then
    log "Creating final snapshot after server shutdown"
    set +e
    run_final_publish_bounded
    local final_sync_status=$?
    set -e
    [[ "$final_sync_status" -eq 0 ]] || warn "Final shutdown sync failed"
  elif [[ "$stopping" == false ]] && sync_can_write; then
    warn "license_server exited without a requested shutdown; skipping final snapshot"
  fi
  if [[ "$stopping" == true ]]; then
    return 0
  fi
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

  # When local state is empty, invalid, or an explicit force restore was
  # requested, remote state must be resolved before any schema initialization.
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
  [[ "$INSTALL_PATH" == /opt/hexlicsrv && \
     "$DATA_PATH" == /opt/hexlicsrv/data && \
     "$RECOVERY_PATH" == /opt/hexlicsrv/recovery ]] \
    || die "Refusing stale-artifact cleanup for unexpected paths"
  find "$INSTALL_PATH" -mindepth 1 -maxdepth 1 \
    \( -name '_pack.*' -o -name '_payload.*' -o -name '_restore.*' \
       -o -name '_restore_commit.*' -o -name '_verify_commit.*' \
       -o -name '_release.*' -o -name '_release_candidate.*' \
       -o -name '_release_manifest_scan.*' \
       -o -name '_release_registry.*.json' \
       -o -name '_release_verify_upload.*' \
       -o -name "$ARCHIVE_NAME" \) -exec rm -rf -- {} +
  find "$DATA_PATH" -mindepth 1 -maxdepth 1 \
    \( -type f -o -type l \) \
    -name '.hexlicsrv.restore.*' \
    -delete
  find "$RECOVERY_PATH" -mindepth 1 -maxdepth 1 \
    \( -type f -o -type l \) \
    \( -name '.schema-state.*' -o -name '.schema-initializing.*' \
       -o -name '.preupgrade.*.tmp' \
       -o -name '.preupgrade-schema-state.*.tmp' \
       -o -name '.restored-schema-state.*' \
       -o -name '.restore-in-progress.*' \) -delete
}

cleanup_stale_runtime_secrets() {
  local path reference_dir sync_ssh_dir="/run/hexlicsrv-sync-ssh"
  local -a files=(
    /run/hexlicsrv-github-headers.*
    /run/hexlicsrv-final-sync-timeout.*
  )
  [[ "$sync_ssh_dir" == /run/hexlicsrv-sync-ssh ]] \
    || die "Refusing runtime secret cleanup for an unexpected path"
  for path in "${files[@]}"; do
    [[ -f "$path" || -L "$path" ]] \
      || die "Unsafe stale runtime secret artifact: $path"
    rm -f -- "$path"
  done
  for reference_dir in /run/hexlicsrv-schema-reference.*; do
    [[ -d "$reference_dir" || -L "$reference_dir" ]] \
      || die "Unsafe stale schema-reference path: $reference_dir"
    rm -rf -- "$reference_dir"
  done
  if [[ -L "$sync_ssh_dir" ]]; then
    rm -f -- "$sync_ssh_dir"
  elif [[ -e "$sync_ssh_dir" ]]; then
    [[ -d "$sync_ssh_dir" ]] \
      || die "Stale SSH secret path is not a directory"
    rm -rf -- "$sync_ssh_dir"
  fi
}

ensure_safe_runtime_directories() {
  local path
  for path in "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH" \
      "$KEYRING_PATH" "$RECOVERY_PATH"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] \
        || die "Runtime path is not a safe directory: $path"
    else
      mkdir -p -- "$path"
      [[ -d "$path" && ! -L "$path" ]] \
        || die "Could not create safe runtime directory: $path"
    fi
  done
}

write_default_config() {
  local target="$1" service_gid tmp
  [[ ! -e "$target" && ! -L "$target" ]] \
    || die "Refusing to replace an existing server configuration"
  service_gid="$(id -g "$SERVICE_USER")"
  tmp="$(mktemp "${CONFIG_PATH}/.hexlicsrv.conf.XXXXXX")"
  cleanup_add_file "$tmp"
  printf '%s\n' "$DB_CONNECTION" >"$tmp"
  chown root:"$service_gid" "$tmp"
  chmod 640 "$tmp"
  mv -f -- "$tmp" "$target"
  sync -f "$target" "$CONFIG_PATH" \
    || die "Could not durably create the default server configuration"
}

validate_server_config() {
  local target="$1" size
  [[ -f "$target" && ! -L "$target" ]] \
    || die "Server configuration is missing or unsafe"
  size="$(stat -c '%s' "$target")"
  [[ "$size" =~ ^[0-9]+$ ]] && ((10#$size > 0 && 10#$size <= 4096)) \
    || die "Server configuration has an invalid size"
  python3 - "$target" "$DB_CONNECTION" <<'PY' || \
    die "Server configuration must contain only the fixed SQLite connection"
import sys

with open(sys.argv[1], "r", encoding="utf-8", newline="") as stream:
    value = stream.read().replace("\r\n", "\n")
expected = sys.argv[2]
if value not in (expected, expected + "\n"):
    raise SystemExit(1)
PY
}

main() {
  local service_uid service_gid
  validate_configuration
  id -u "$SERVICE_USER" >/dev/null 2>&1 || die "Service user $SERVICE_USER is missing"
  service_uid="$(id -u "$SERVICE_USER")"; service_gid="$(id -g "$SERVICE_USER")"

  ensure_safe_runtime_directories
  cleanup_stale_runtime_secrets
  ensure_safe_work_dir
  cleanup_stale_runtime_artifacts
  cd "$INSTALL_PATH" || die "Could not enter install directory $INSTALL_PATH"
  CONFIG_FILE="${CONFIG_PATH}/hexlicsrv.conf"
  [[ ! -L "$CONFIG_FILE" ]] || die "Refusing symlinked server configuration"
  [[ ! -e "$CONFIG_FILE" || -f "$CONFIG_FILE" ]] \
    || die "Server configuration path is not a regular file"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    write_default_config "$CONFIG_FILE"
  fi
  validate_server_config "$CONFIG_FILE"

  log "Applying runtime patch"
  env -u SYNC_AUTH_TOKEN -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY -u GIT_SSH_COMMAND \
    python3 "${INSTALL_PATH}/license_patch.py" hexlicsrv-940 || die "Patch failed"
  [[ -f "${INSTALL_PATH}/license_server" && \
     ! -L "${INSTALL_PATH}/license_server" ]] \
    || die "Patched license_server is missing or unsafe"
  [[ -f "${INSTALL_PATH}/lsadm" && ! -L "${INSTALL_PATH}/lsadm" ]] \
    || die "Patched lsadm is missing or unsafe"
  [[ -f "${INSTALL_PATH}/license_server.hexlic" && \
     ! -L "${INSTALL_PATH}/license_server.hexlic" && \
     -s "${INSTALL_PATH}/license_server.hexlic" ]] \
    || die "Patched license file is missing, empty, or unsafe"
  chown root:root "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"
  chmod 755 "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"

  ensure_tls_certificate
  chown -R "$service_uid:$service_gid" "$LOGS_PATH" "$DATA_PATH" "$KEYRING_PATH"
  chown root:"$service_gid" "$CONFIG_PATH"
  chmod 750 "$CONFIG_PATH"
  chown root:"$service_gid" "$CONFIG_FILE" \
    "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key"
  chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/hexlicsrv.crt" \
    "${CONFIG_PATH}/hexlicsrv.key"
  if [[ -f "${CONFIG_PATH}/CA.srl" && ! -L "${CONFIG_PATH}/CA.srl" ]]; then
    chown root:"$service_gid" "${CONFIG_PATH}/CA.srl"
    chmod 640 "${CONFIG_PATH}/CA.srl"
  fi
  chown root:root "$RECOVERY_PATH"
  chmod 700 "$RECOVERY_PATH"
  chown -R root:root "$WORK_DIR"
  chmod 700 "$WORK_DIR"
  chown root:"$service_gid" "${INSTALL_PATH}/license_server.hexlic"
  chmod 640 "${INSTALL_PATH}/license_server.hexlic"

  recover_interrupted_data_restore
  recover_interrupted_schema_initialization
  recover_interrupted_schema_upgrade
  ensure_secret_service_bus
  adopt_unmarked_current_schema
  perform_startup_sync
  # SYNC_FORCE_RESTORE is deliberately a one-shot startup override.
  SYNC_FORCE_RESTORE=false
  ensure_schema
  commit_data_restore
  if sync_can_write; then
    perform_publish_best_effort "Post-schema"
  fi
  supervise_server
}

if [[ "${1:-}" == __hexlicsrv_sync_publish ]]; then
  (($# == 1)) || die "Invalid internal sync invocation"
  validate_configuration
  perform_sync publish
  exit 0
fi

main "$@"
