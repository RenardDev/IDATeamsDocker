#!/bin/bash

set -Eeuo pipefail
shopt -s nullglob
# Keep `set -e` semantics inside command substitutions on Bash 4.4+.
shopt -s inherit_errexit 2>/dev/null || true
umask 077

################################################################
# Global cleanup (tmp files/dirs)
################################################################

declare -a CLEANUP_FILES=()
declare -a CLEANUP_DIRS=()

cleanup_add_file() { CLEANUP_FILES+=("$1"); }
cleanup_add_dir()  { CLEANUP_DIRS+=("$1"); }

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
# App Configuration (MySQL)
################################################################

MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-lumina}"
MYSQL_USER="${MYSQL_USER:-lumina}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:?MYSQL_PASSWORD is required}"

# Optional: how long to wait for TCP connect to MySQL (seconds)
MYSQL_WAIT_TIMEOUT="${MYSQL_WAIT_TIMEOUT:-300}"

LUMINA_HOST="${LUMINA_HOST:-localhost}"
LUMINA_PORT="${LUMINA_PORT:-443}"
readonly LUMINA_SCHEMA_VERSION="940"
LUMINA_LOG_PATH="${LUMINA_LOG_PATH:-/dev/stdout}"

# Vault integration is opt-in. Supplying host/port alone no longer silently
# changes the schema type.
VAULT_ENABLED="${VAULT_ENABLED:-false}"
VAULT_HOST="${VAULT_HOST:-}"
VAULT_PORT="${VAULT_PORT:-}"

################################################################
# Unified Sync Configuration
################################################################

SYNC_ENABLED="${SYNC_ENABLED:-false}"
SYNC_METHOD="${SYNC_METHOD:-commits}"
SYNC_AUTH_TOKEN="${SYNC_AUTH_TOKEN:-}"
SYNC_READ_ONLY="${SYNC_READ_ONLY:-false}"

SYNC_HOST_ID="${SYNC_HOST_ID:-lumina}"
SYNC_CHUNK_SIZE_MB="${SYNC_CHUNK_SIZE_MB:-49}"
SYNC_INTERVAL_SECONDS="${SYNC_INTERVAL_SECONDS:-3600}"
SYNC_NETWORK_TIMEOUT_SECONDS="${SYNC_NETWORK_TIMEOUT_SECONDS:-300}"
SYNC_LOCK_TIMEOUT_SECONDS="${SYNC_LOCK_TIMEOUT_SECONDS:-30}"
SYNC_FINAL_TIMEOUT_SECONDS="${SYNC_FINAL_TIMEOUT_SECONDS:-300}"
SYNC_RELEASE_KEEP="${SYNC_RELEASE_KEEP:-3}"
SYNC_FORCE_RESTORE="${SYNC_FORCE_RESTORE:-false}"
SYNC_MAX_RESTORE_MB="${SYNC_MAX_RESTORE_MB:-10240}"
SYNC_MAX_EXTRACT_MB="${SYNC_MAX_EXTRACT_MB:-20480}"
SYNC_ENCRYPTION_PASSPHRASE="${SYNC_ENCRYPTION_PASSPHRASE:-}"

GH_REMOTE="${GH_REMOTE:-}"

GH_BRANCH="${GH_BRANCH:-main}"
GH_COMMIT_NAME="${GH_COMMIT_NAME:-Lumina CI}"
GH_COMMIT_EMAIL="${GH_COMMIT_EMAIL:-lumina@example.com}"
GH_SSH_PRIVATE_KEY="${GH_SSH_PRIVATE_KEY:-}"
GH_KNOWN_HOSTS="${GH_KNOWN_HOSTS:-}"

GH_RELEASE_TAG="${GH_RELEASE_TAG:-lumina}"
GH_RELEASE_NAME="${GH_RELEASE_NAME:-Lumina}"
GH_API="${GH_API:-}"
GH_UPLOAD="${GH_UPLOAD:-}"

# Keep secrets as shell variables, not ambient environment inherited by every
# helper process. Individual clients receive them only through protected files
# or a one-command environment assignment.
export -n MYSQL_PASSWORD MYSQL_ROOT_PASSWORD SYNC_AUTH_TOKEN \
  SYNC_ENCRYPTION_PASSPHRASE GH_SSH_PRIVATE_KEY GH_KNOWN_HOSTS \
  2>/dev/null || true

################################################################
# Paths & Constants
################################################################

INSTALL_PATH="/opt/lumina"
SYNC_RUNTIME_DIR="/run/lumina-sync"
GPG_HOME="/run/lumina-gnupg"

CA_PATH="${INSTALL_PATH}/CA"
CA_KEY_PATH="${CA_KEY_PATH:-/run/lumina-ca/CA.key}"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_STATE="${CONFIG_PATH}/lumina_schema.state"
SCHEMA_RECOVERY_SQL="${CONFIG_PATH}/.lumina_schema_upgrade_recovery.sql"
SCHEMA_RECOVERY_META="${CONFIG_PATH}/.lumina_schema_upgrade_recovery.json"
SCHEMA_RECOVERY_STATE="${CONFIG_PATH}/.lumina_schema_upgrade_recovery.state.json"
RESTORE_RECOVERY_SQL="${CONFIG_PATH}/.lumina_remote_restore_recovery.sql"
RESTORE_RECOVERY_META="${CONFIG_PATH}/.lumina_remote_restore_recovery.json"
RESTORE_RECOVERY_STATE="${CONFIG_PATH}/.lumina_remote_restore_recovery.state.json"
SCHEMA_INIT_META="${CONFIG_PATH}/.lumina_schema_init_recovery.json"
TLS_RECOVERY_CERT="${CONFIG_PATH}/.lumina_tls_rotation_recovery.crt"
TLS_RECOVERY_KEY="${CONFIG_PATH}/.lumina_tls_rotation_recovery.key"
TLS_RECOVERY_META="${CONFIG_PATH}/.lumina_tls_rotation_recovery.json"

WORK_DIR="${INSTALL_PATH}/_gitmirror"
REMOTE_DIR="${WORK_DIR}/backups/${SYNC_HOST_ID}"

DUMP_PATH="${INSTALL_PATH}/dump.sql"
PLAIN_ARCHIVE_NAME="dump.sql.zst"
ENCRYPTED_ARCHIVE_NAME="${PLAIN_ARCHIVE_NAME}.gpg"
ARCHIVE_NAME="$ENCRYPTED_ARCHIVE_NAME"
ARCHIVE_PATH="${INSTALL_PATH}/${ARCHIVE_NAME}"
MANIFEST_NAME="manifest.json"
# Release sync recognizes only this service-qualified namespace. Assets from
# older unqualified naming schemes are intentionally invisible to all readers,
# validators, publishers, and retention cleanup.
readonly RELEASE_ASSET_PREFIX="lumina--${SYNC_HOST_ID}--snapshot--"
readonly RELEASE_GENERATION_REGEX='^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}-[a-f0-9]{32}$'

RESTORED_SCHEMA_TYPE=""
RESTORED_SCHEMA_VERSION=""
RESTORED_SCHEMA_FINGERPRINT=""
RESTORE_PHASE_OPEN=1
SCHEMA_UPGRADE_PENDING=0
RESTORE_RECOVERY_PENDING=0
SCHEMA_INIT_PENDING=0
PACK_SIZE=""
PACK_SHA=""
PACK_CONTENT_SHA=""
PACK_HMAC=""
declare -a PACK_CHUNK_NAMES=()

################################################################
# Utils
################################################################

now_utc() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

log() { printf '[%s] %s\n' "$(now_utc)" "$*"; }

die() {
  printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2
  exit 1
}

is_true() {
  case "${1,,}" in
    true) return 0 ;;
    false) return 1 ;;
    *) die "Invalid boolean value: '$1'" ;;
  esac
}

normalize_uint() {
  local name="$1" min="$2" max="$3" raw value
  raw="${!name}"
  [[ "$raw" =~ ^[0-9]{1,9}$ ]] \
    || die "$name must be an unsigned decimal integer"
  value=$((10#$raw))
  (( value >= min && value <= max )) \
    || die "$name must be between $min and $max"
  printf -v "$name" '%d' "$value"
}

ensure_real_directory() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] \
      || die "Required directory is unsafe: $path"
  else
    mkdir -- "$path" || die "Failed to create directory: $path"
  fi
}

classify_endpoint_host() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys

value = sys.argv[1]
try:
    ipaddress.ip_address(value)
except ValueError:
    candidate = value[:-1] if value.endswith(".") else value
    labels = candidate.split(".")
    valid = (
        1 <= len(candidate) <= 253
        and all(
            1 <= len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        )
    )
    if not valid:
        raise SystemExit(2)
    print("DNS")
else:
    print("IP")
PY
}

validate_git_ref_name() {
  python3 - "$1" <<'PY'
import re
import sys

value = sys.argv[1]
valid = (
    1 <= len(value) <= 255
    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is not None
    and not value.startswith("-")
    and not value.endswith(("/", "."))
    and ".." not in value
    and "//" not in value
    and "@{" not in value
)
parts = value.split("/")
valid = valid and all(
    part not in {"", ".", ".."}
    and not part.startswith(".")
    and not part.endswith((".", ".lock"))
    for part in parts
)
raise SystemExit(0 if valid else 2)
PY
}

validate_gh_remote_syntax() {
  [[ "$1" != *'\'* ]] || return 1
  python3 - "$1" <<'PY'
import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
if (
    not value
    or any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in value)
    or any(ch in value for ch in "\\?#%")
):
    raise SystemExit(2)

host_re = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
user_re = re.compile(r"[A-Za-z0-9._-]+")
segment_re = re.compile(r"[A-Za-z0-9_.-]+")

def valid_host(host: str | None) -> bool:
    return bool(
        host
        and host_re.fullmatch(host)
        and ".." not in host
        and all(label and not label.startswith("-") and not label.endswith("-") for label in host.split("."))
    )

def valid_path(raw_path: str) -> bool:
    path = raw_path[1:] if raw_path.startswith("/") else raw_path
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    return len(parts) == 2 and all(
        segment_re.fullmatch(part) and part not in {".", ".."}
        for part in parts
    )

try:
    if value.startswith("https://") or value.startswith("ssh://"):
        parsed = urlsplit(value)
        expected_scheme = "https" if value.startswith("https://") else "ssh"
        if parsed.scheme != expected_scheme or parsed.query or parsed.fragment:
            raise ValueError
        if not valid_host(parsed.hostname):
            raise ValueError
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if expected_scheme == "https":
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
        else:
            if parsed.password is not None or (parsed.username is not None and not user_re.fullmatch(parsed.username)):
                raise ValueError
        if not valid_path(parsed.path):
            raise ValueError
    else:
        match = re.fullmatch(r"([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)", value)
        if not match or not user_re.fullmatch(match.group(1)) or not valid_host(match.group(2)):
            raise ValueError
        if not valid_path(match.group(3)):
            raise ValueError
except (ValueError, UnicodeError):
    raise SystemExit(2)
PY
}

validate_settings() {
  local resolved_log_path single_line_value vault_host_kind
  [[ -n "$MYSQL_HOST" && -n "$MYSQL_USER" ]] \
    || die "MYSQL_HOST and MYSQL_USER must not be empty"
  [[ "$MYSQL_USER" =~ ^[A-Za-z0-9_]{1,32}$ ]] \
    || die "MYSQL_USER must contain 1-32 letters, digits, or underscores"
  for single_line_value in "$MYSQL_HOST" "$MYSQL_USER" "$MYSQL_PASSWORD" \
      "$LUMINA_HOST" "$LUMINA_LOG_PATH" "$VAULT_HOST" "$VAULT_PORT"; do
    [[ "$single_line_value" != *$'\n'* && "$single_line_value" != *$'\r'* ]] \
      || die "Connection and path configuration values must not contain newlines"
  done
  [[ "$MYSQL_DATABASE" =~ ^[A-Za-z0-9_]+$ ]] \
    || die "MYSQL_DATABASE must contain only letters, digits, and underscores"
  normalize_uint MYSQL_PORT 1 65535
  normalize_uint MYSQL_WAIT_TIMEOUT 1 604800
  normalize_uint LUMINA_PORT 1 65535
  if ! LUMINA_HOST_KIND="$(classify_endpoint_host "$LUMINA_HOST")"; then
    die "LUMINA_HOST must be a valid DNS name or IP address"
  fi
  if [[ "$LUMINA_LOG_PATH" != "/dev/stdout" && "$LUMINA_LOG_PATH" != "/dev/stderr" ]]; then
    resolved_log_path="$(realpath -m -- "$LUMINA_LOG_PATH")" \
      || die "LUMINA_LOG_PATH cannot be resolved"
    [[ "$resolved_log_path" == "${LOGS_PATH}/"* ]] \
      || die "LUMINA_LOG_PATH must be /dev/stdout, /dev/stderr, or a file under $LOGS_PATH"
    LUMINA_LOG_PATH="$resolved_log_path"
  fi
  [[ "$SYNC_HOST_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ \
      && "$SYNC_HOST_ID" != *".."* ]] \
    || die "SYNC_HOST_ID must be a safe 1-64 character identifier"
  normalize_uint SYNC_CHUNK_SIZE_MB 1 49
  normalize_uint SYNC_INTERVAL_SECONDS 0 2678400
  (( SYNC_INTERVAL_SECONDS == 0 || SYNC_INTERVAL_SECONDS >= 60 )) \
    || die "SYNC_INTERVAL_SECONDS must be 0 or at least 60"
  normalize_uint SYNC_FINAL_TIMEOUT_SECONDS 30 540
  normalize_uint SYNC_NETWORK_TIMEOUT_SECONDS 10 3600
  normalize_uint SYNC_LOCK_TIMEOUT_SECONDS 1 3600
  normalize_uint SYNC_RELEASE_KEEP 1 20
  normalize_uint SYNC_MAX_RESTORE_MB 1 1048576
  normalize_uint SYNC_MAX_EXTRACT_MB 1 1048576
  if is_true "$SYNC_ENABLED"; then :; else :; fi
  if is_true "$SYNC_FORCE_RESTORE"; then :; else :; fi
  if is_true "$SYNC_READ_ONLY"; then :; else :; fi
  if is_true "$SYNC_FORCE_RESTORE" && ! is_true "$SYNC_ENABLED"; then
    die "SYNC_FORCE_RESTORE=true requires SYNC_ENABLED=true"
  fi
  case "${SYNC_METHOD,,}" in
    commits|releases) ;;
    *) die "Unknown SYNC_METHOD='$SYNC_METHOD'" ;;
  esac
  if is_true "$VAULT_ENABLED"; then
    [[ -n "$VAULT_HOST" && -n "$VAULT_PORT" ]] \
      || die "VAULT_HOST and VAULT_PORT are required when VAULT_ENABLED=true"
    if ! vault_host_kind="$(classify_endpoint_host "$VAULT_HOST")"; then
      die "VAULT_HOST must be a valid DNS name or IP address"
    fi
    [[ "$vault_host_kind" != "IP" || "$VAULT_HOST" != *:* ]] \
      || die "IPv6 VAULT_HOST is unsupported because the Lumina vault endpoint syntax cannot be verified safely"
    normalize_uint VAULT_PORT 1 65535
  fi
  for single_line_value in "$GH_REMOTE" "$GH_BRANCH" "$GH_COMMIT_NAME" "$GH_COMMIT_EMAIL" \
      "$GH_RELEASE_TAG" "$GH_RELEASE_NAME" "$GH_API" "$GH_UPLOAD"; do
    [[ "$single_line_value" != *$'\n'* && "$single_line_value" != *$'\r'* ]] \
      || die "Git sync configuration contains a newline in a single-line field"
  done
  validate_git_ref_name "$GH_BRANCH" \
    || die "GH_BRANCH must be a safe current Git ref name"
  validate_git_ref_name "$GH_RELEASE_TAG" \
    || die "GH_RELEASE_TAG must be a safe current Git ref name"
  if is_true "$SYNC_ENABLED"; then
    [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required when SYNC_ENABLED=true"
    validate_gh_remote_syntax "$GH_REMOTE" \
      || die "GH_REMOTE must be a strict HTTPS, SSH URL, or user@host:owner/repository remote"
    [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
      || die "SYNC_ENCRYPTION_PASSPHRASE is required whenever SYNC_ENABLED=true"
    [[ "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\n'* \
        && "$SYNC_ENCRYPTION_PASSPHRASE" != *$'\r'* ]] \
      || die "SYNC_ENCRYPTION_PASSPHRASE must not contain newlines"
    ((${#SYNC_ENCRYPTION_PASSPHRASE} >= 20)) \
      || die "SYNC_ENCRYPTION_PASSPHRASE must contain at least 20 characters"
    if [[ -n "$SYNC_AUTH_TOKEN" ]] \
        && { [[ "$SYNC_AUTH_TOKEN" == *$'\n'* ]] \
          || printf '%s' "$SYNC_AUTH_TOKEN" | LC_ALL=C grep -q '[[:cntrl:]]'; }; then
      die "SYNC_AUTH_TOKEN must not contain control characters"
    fi
    [[ ! "$GH_REMOTE" =~ ^https://[^/]*@ ]] \
      || die "Credentials embedded in GH_REMOTE are forbidden; use SYNC_AUTH_TOKEN"
    [[ ! "$GH_API" =~ ^https://[^/]*@ && ! "$GH_UPLOAD" =~ ^https://[^/]*@ ]] \
      || die "Credentials embedded in GH_API/GH_UPLOAD are forbidden"
    case "${SYNC_METHOD,,}" in
      releases)
        [[ "$GH_REMOTE" =~ ^https:// \
            || "$GH_REMOTE" =~ ^ssh:// \
            || "$GH_REMOTE" =~ ^[^@]+@[^:]+:.+ ]] \
          || die "Unsupported GH_REMOTE scheme for releases sync"
        if ! is_true "$SYNC_READ_ONLY"; then
          [[ -n "$SYNC_AUTH_TOKEN" ]] \
            || die "SYNC_AUTH_TOKEN is required for writable releases sync; set SYNC_READ_ONLY=true for anonymous reads"
        fi
        ;;
      commits)
        if [[ "$GH_REMOTE" =~ ^https:// ]]; then
          if ! is_true "$SYNC_READ_ONLY"; then
            [[ -n "$SYNC_AUTH_TOKEN" ]] \
              || die "SYNC_AUTH_TOKEN is required for writable HTTPS commits sync; set SYNC_READ_ONLY=true for anonymous reads"
          fi
        elif [[ "$GH_REMOTE" =~ ^(git@|ssh://) ]]; then
          [[ -n "$GH_SSH_PRIVATE_KEY" ]] \
            || die "GH_SSH_PRIVATE_KEY is required for SSH commits sync"
          [[ -n "$GH_KNOWN_HOSTS" ]] \
            || die "GH_KNOWN_HOSTS is required for SSH commits sync; host-key pinning cannot be disabled"
        else
          die "Unsupported GH_REMOTE scheme for commits sync (use https:// or ssh:// / git@)"
        fi
        ;;
    esac
  fi
}

ensure_file_within_mb() {
  local file="$1" max_mb="$2" label="$3" size max_bytes
  size="$(stat -c '%s' "$file")"
  max_bytes=$((max_mb * 1000000))
  (( size <= max_bytes )) \
    || die "$label exceeds configured limit (${size} bytes > ${max_mb} MB)"
}

cleanup_stale_fixed_temps() {
  local path resolved removed=0
  [[ "$INSTALL_PATH" == "/opt/lumina" && "$CONFIG_PATH" == "/opt/lumina/config" ]] \
    || die "Refusing stale cleanup for unexpected Lumina paths"
  [[ -d "$INSTALL_PATH" && ! -L "$INSTALL_PATH" \
      && -d "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] \
    || die "Refusing stale cleanup through an unsafe directory"

  for path in \
      "$INSTALL_PATH"/.dump.sql.* \
      "$INSTALL_PATH"/.dump.sql.zst.* \
      "$INSTALL_PATH"/.dump.sql.zst.gpg.* \
      "$INSTALL_PATH"/.restore.sql.* \
      "$CONFIG_PATH"/.lumina.conf.* \
      "$CONFIG_PATH"/..lumina_remote_restore_recovery.state.json.* \
      "$CONFIG_PATH"/..lumina_schema_upgrade_recovery.state.json.* \
      "$CONFIG_PATH"/..lumina_tls_rotation_recovery.crt.* \
      "$CONFIG_PATH"/..lumina_tls_rotation_recovery.key.* \
      "$CONFIG_PATH"/.lumina_schema.state.restore.* \
      "$CONFIG_PATH"/.restore-recovery.sql.* \
      "$CONFIG_PATH"/.restore-recovery.json.* \
      "$CONFIG_PATH"/.schema-init-recovery.json.* \
      "$CONFIG_PATH"/.schema-recovery.sql.* \
      "$CONFIG_PATH"/.schema-recovery.json.* \
      "$CONFIG_PATH"/.lumina_schema.state.* \
      "$CONFIG_PATH"/.tls-rotation-recovery.json.* \
      "$CONFIG_PATH"/.lumina.crt.restore.* \
      "$CONFIG_PATH"/.lumina.key.restore.* \
      "$CONFIG_PATH"/.lumina.key.* \
      "$CONFIG_PATH"/.lumina.crt.*; do
    [[ -e "$path" || -L "$path" ]] || continue
    [[ -f "$path" && ! -L "$path" ]] \
      || die "Unsafe stale Lumina temporary file: $path"
    rm -f -- "$path"
    removed=1
  done

  for path in \
      "$INSTALL_PATH"/_dbimport.* \
      "$INSTALL_PATH"/_dbrestore.* \
      "$INSTALL_PATH"/_commitverify.* \
      "$INSTALL_PATH"/_ghnamespace.* \
      "$INSTALL_PATH"/_ghrestore.* \
      "$INSTALL_PATH"/_ghcleanup.* \
      "$INSTALL_PATH"/_ghverify.* \
      "$INSTALL_PATH"/_ghpublish.*; do
    [[ -e "$path" || -L "$path" ]] || continue
    [[ -d "$path" && ! -L "$path" ]] \
      || die "Unsafe stale Lumina temporary directory: $path"
    resolved="$(realpath -e -- "$path")" || die "Cannot resolve stale Lumina temp directory"
    [[ "$resolved" == "$INSTALL_PATH/"* ]] \
      || die "Stale Lumina temp directory escapes the install path"
    rm -rf --one-file-system -- "$path"
    removed=1
  done
  if (( removed == 1 )); then
    sync -f "$INSTALL_PATH" || die "Failed to persist stale Lumina temp cleanup"
    sync -f "$CONFIG_PATH" || die "Failed to persist stale Lumina config-temp cleanup"
    log "Removed stale crash-interrupted Lumina temporary artifacts"
  fi
}

cleanup_sync_runtime_locked() {
  local path resolved
  [[ "$SYNC_RUNTIME_DIR" == "/run/lumina-sync" \
      && -d "$SYNC_RUNTIME_DIR" && ! -L "$SYNC_RUNTIME_DIR" ]] \
    || die "Refusing cleanup of an unsafe sync runtime directory"
  resolved="$(realpath -e -- "$SYNC_RUNTIME_DIR")" \
    || die "Cannot resolve sync runtime directory"
  [[ "$resolved" == "$SYNC_RUNTIME_DIR" ]] \
    || die "Sync runtime directory contains a symlink"
  while IFS= read -r -d '' path; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      resolved="$(realpath -e -- "$path")" || die "Cannot resolve sync runtime artifact"
      [[ "$resolved" == "$SYNC_RUNTIME_DIR/"* ]] \
        || die "Sync runtime artifact escapes its directory"
      rm -rf --one-file-system -- "$path"
    else
      rm -f -- "$path"
    fi
  done < <(find "$SYNC_RUNTIME_DIR" -mindepth 1 -maxdepth 1 -print0)
}

prepare_gpg_home() {
  local resolved
  [[ "$GPG_HOME" == "/run/lumina-gnupg" ]] \
    || die "Refusing to clean an unexpected GnuPG home"
  if [[ -e "$GPG_HOME" || -L "$GPG_HOME" ]]; then
    [[ -d "$GPG_HOME" && ! -L "$GPG_HOME" ]] \
      || die "GnuPG home is unsafe"
    resolved="$(realpath -e -- "$GPG_HOME")" \
      || die "Cannot resolve GnuPG home"
    [[ "$resolved" == "$GPG_HOME" ]] \
      || die "GnuPG home resolves outside its fixed path"
    [[ "$(stat -c '%u' "$GPG_HOME")" == "0" ]] \
      || die "GnuPG home must be owned by root"
    rm -rf --one-file-system -- "$GPG_HOME"
  fi
  install -d -o root -g root -m 0700 "$GPG_HOME"
  [[ -d "$GPG_HOME" && ! -L "$GPG_HOME" \
      && "$(realpath -e -- "$GPG_HOME")" == "$GPG_HOME" \
      && "$(stat -c '%u:%g:%a' "$GPG_HOME")" == "0:0:700" ]] \
    || die "Failed to create a private root-owned GnuPG home"
}

keyed_file_hmac_sha256() {
  local input_file="$1" domain="$2" passphrase_file result
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] || return 1
  passphrase_file="$(mktemp "${SYNC_RUNTIME_DIR}/hmac.XXXXXX")"
  cleanup_add_file "$passphrase_file"
  chmod 600 "$passphrase_file"
  printf '%s' "$SYNC_ENCRYPTION_PASSPHRASE" > "$passphrase_file"
  if ! result="$(python3 - "$input_file" "$passphrase_file" "$domain" <<'PY'
import hashlib
import hmac
import sys

input_path, passphrase_path, domain = sys.argv[1:]
with open(passphrase_path, "rb") as stream:
    passphrase = stream.read()
key = hashlib.pbkdf2_hmac(
    "sha256",
    passphrase,
    b"lumina-sync-v3-hmac",
    600_000,
    32,
)
digest = hmac.new(key, digestmod=hashlib.sha256)
digest.update(domain.encode("ascii") + b"|")
with open(input_path, "rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
  )"; then
    rm -f -- "$passphrase_file"
    return 1
  fi
  rm -f -- "$passphrase_file"
  [[ "$result" =~ ^[a-f0-9]{64}$ ]] || return 1
  printf '%s\n' "$result"
}

archive_hmac_sha256() {
  keyed_file_hmac_sha256 "$1" "archive"
}

verify_archive_hmac() {
  local archive="$1" expected="$2" actual
  [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  actual="$(archive_hmac_sha256 "$archive")" || return 1
  [[ "${actual,,}" == "${expected,,}" ]]
}

manifest_hmac_sha256() {
  local manifest="$1" canonical result
  canonical="$(mktemp "${SYNC_RUNTIME_DIR}/manifest-canonical.XXXXXX")"
  cleanup_add_file "$canonical"
  jq -cS 'del(.manifest_hmac_sha256)' < "$manifest" > "$canonical" || return 1
  result="$(keyed_file_hmac_sha256 "$canonical" "manifest")" || return 1
  rm -f -- "$canonical"
  printf '%s\n' "$result"
}

verify_manifest_hmac() {
  local manifest="$1" expected actual
  expected="$(jq -r '.manifest_hmac_sha256 // empty' < "$manifest")" || return 1
  [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  actual="$(manifest_hmac_sha256 "$manifest")" || return 1
  [[ "${actual,,}" == "${expected,,}" ]]
}

run_as_lumina_clean() {
  local runtime_uid
  runtime_uid="$(id -u lumina)" || die "Runtime user 'lumina' is missing"
  env -i \
    -u MYSQL_PASSWORD \
    -u MYSQL_PWD \
    -u MYSQL_ROOT_PASSWORD \
    -u SYNC_AUTH_TOKEN \
    -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY \
    -u GH_KNOWN_HOSTS \
    -u LUMINA_GIT_TOKEN_FILE \
    -u GIT_ASKPASS \
    -u GIT_SSH_COMMAND \
    -u SSH_AUTH_SOCK \
    -u GNUPGHOME \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/var/lib/lumina \
    USER=lumina \
    LOGNAME=lumina \
    XDG_DATA_HOME=/var/lib/lumina/.local/share \
    XDG_RUNTIME_DIR="/run/user/${runtime_uid}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:?D-Bus address is not initialized}" \
    gosu lumina:lumina "$@"
}

ensure_secret_service_bus() {
  local machine_id_file="/etc/machine-id"
  local dbus_machine_id_link="/var/lib/dbus/machine-id"
  local default_bus_address="unix:path=/run/lumina-dbus/session-bus"
  local bus_socket="" machine_id

  if [[ -e /var/lib/dbus || -L /var/lib/dbus ]]; then
    [[ -d /var/lib/dbus && ! -L /var/lib/dbus ]] \
      || die "D-Bus state directory is unsafe"
  else
    mkdir -p /var/lib/dbus
  fi

  if [[ -e "$machine_id_file" || -L "$machine_id_file" ]]; then
    [[ -f "$machine_id_file" && ! -L "$machine_id_file" ]] \
      || die "D-Bus machine-id path is unsafe"
  fi

  if [[ ! -s "$machine_id_file" ]]; then
    rm -f -- "$machine_id_file"
    dbus-uuidgen --ensure="$machine_id_file" \
      || die "Failed to generate D-Bus machine-id"
  fi
  [[ -f "$machine_id_file" && ! -L "$machine_id_file" ]] \
    || die "D-Bus machine-id was not created safely"
  machine_id="$(tr -d '\r\n' < "$machine_id_file")"
  [[ "$machine_id" =~ ^[A-Fa-f0-9]{32}$ ]] \
    || die "D-Bus machine-id has an invalid format"

  [[ ! -d "$dbus_machine_id_link" ]] || die "D-Bus machine-id link path is a directory"
  ln -sfn "$machine_id_file" "$dbus_machine_id_link"

  unset DISPLAY WAYLAND_DISPLAY
  export DBUS_SESSION_BUS_ADDRESS="$default_bus_address"
  local runtime_user="lumina"
  local runtime_uid
  id -u "$runtime_user" >/dev/null 2>&1 || die "Runtime user '$runtime_user' is missing"
  runtime_uid="$(id -u "$runtime_user")"

  export HOME="/var/lib/lumina"
  export XDG_DATA_HOME="${HOME}/.local/share"
  export XDG_RUNTIME_DIR="/run/user/${runtime_uid}"
  export USER="$runtime_user"
  export LOGNAME="$runtime_user"

  mkdir -p "$XDG_RUNTIME_DIR" /run/lumina-dbus "${XDG_DATA_HOME}/keyrings"
  chown -R "$runtime_user:$runtime_user" "$HOME" "$XDG_RUNTIME_DIR" /run/lumina-dbus
  chmod 700 "$XDG_RUNTIME_DIR"
  chmod 700 /run/lumina-dbus "${XDG_DATA_HOME}/keyrings"

  if ! run_as_lumina_clean timeout --foreground --kill-after=5s 20s dbus-send \
       --bus="$DBUS_SESSION_BUS_ADDRESS" \
       --type=method_call \
       --print-reply \
       --dest=org.freedesktop.DBus \
       /org/freedesktop/DBus \
       org.freedesktop.DBus.ListNames \
       >/dev/null 2>&1; then
    if [[ "$DBUS_SESSION_BUS_ADDRESS" == unix:path=/run/lumina-dbus/* ]]; then
      bus_socket="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
      bus_socket="${bus_socket%%,*}"
      rm -f -- "$bus_socket"
    fi

    local bus_info=()
    mapfile -t bus_info < <(
      run_as_lumina_clean timeout --foreground --kill-after=5s 20s dbus-daemon \
        --session \
        --address="$DBUS_SESSION_BUS_ADDRESS" \
        --fork \
        --print-address=1 \
        --print-pid=1
    )

    ((${#bus_info[@]} >= 2)) \
      || die "Failed to start the D-Bus session bus"

    export DBUS_SESSION_BUS_ADDRESS="${bus_info[0]}"
    [[ -z "$bus_socket" || ! -S "$bus_socket" ]] || chmod 600 "$bus_socket"
    log "Started D-Bus session bus (pid=${bus_info[1]})"
  else
    log "Using existing D-Bus session bus"
  fi

  # An empty login password unlocks the dedicated persistent service keyring.
  # Compose stores it separately and only the runtime user can access its files.
  printf '\n' | run_as_lumina_clean timeout --foreground --kill-after=5s 20s \
    gnome-keyring-daemon --unlock >/dev/null 2>&1 || true
  run_as_lumina_clean timeout --foreground --kill-after=5s 20s \
    gnome-keyring-daemon --start --components=secrets >/dev/null \
    || die "Failed to start the Secret Service"

  run_as_lumina_clean timeout --foreground --kill-after=5s 20s dbus-send \
    --bus="$DBUS_SESSION_BUS_ADDRESS" \
    --type=method_call \
    --print-reply \
    --dest=org.freedesktop.secrets \
    /org/freedesktop/secrets \
    org.freedesktop.DBus.Peer.Ping \
    >/dev/null 2>&1 \
    || die "Secret Service is not reachable through D-Bus"

  local probe_key="lumina-bootstrap-$$" probe_value="$(openssl rand -hex 16)" stored_value
  if ! printf '%s' "$probe_value" \
      | run_as_lumina_clean timeout --foreground --kill-after=5s 20s secret-tool store \
          --label='Lumina startup probe' application lumina-bootstrap probe "$probe_key" \
          >/dev/null 2>&1; then
    die "Secret Service is reachable but its collection is not writable/unlocked"
  fi
  stored_value="$(run_as_lumina_clean timeout --foreground --kill-after=5s 20s secret-tool lookup \
      application lumina-bootstrap probe "$probe_key" 2>/dev/null || true)"
  run_as_lumina_clean timeout --foreground --kill-after=5s 20s secret-tool clear \
      application lumina-bootstrap probe "$probe_key" >/dev/null 2>&1 || true
  [[ "$stored_value" == "$probe_value" ]] \
    || die "Secret Service write/read verification failed"

  log "Secret Service is reachable, unlocked, and writable"
}

wait_for_db() {
  log "Waiting for authenticated MySQL access at ${MYSQL_HOST}:${MYSQL_PORT} (timeout=${MYSQL_WAIT_TIMEOUT}s)..."

  local deadline=$((SECONDS + MYSQL_WAIT_TIMEOUT))
  while true; do
    if mysql_client --connect-timeout=5 --batch --skip-column-names \
        -e 'SELECT 1;' >/dev/null 2>&1; then
      log "MySQL is reachable and credentials are valid"
      return 0
    fi

    if (( SECONDS >= deadline )); then
      die "MySQL is not ready or credentials are invalid at ${MYSQL_HOST}:${MYSQL_PORT} (timeout ${MYSQL_WAIT_TIMEOUT}s)"
    fi

    sleep 3
  done
}

mysql_client() {
  MYSQL_PWD="$MYSQL_PASSWORD" mysql --no-defaults \
    --protocol=TCP \
    -h "$MYSQL_HOST" \
    -P "$MYSQL_PORT" \
    -u "$MYSQL_USER" \
    "$@"
}

mysql_query_scalar() {
  mysql_client \
    --batch \
    --skip-column-names \
    -e "$1"
}

db_table_count() {
  local cnt
  if ! cnt="$(mysql_query_scalar \
      "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MYSQL_DATABASE}';")"; then
    die "Failed to inspect MySQL schema '${MYSQL_DATABASE}'"
  fi
  cnt="${cnt//$'\r'/}"
  [[ "$cnt" =~ ^[0-9]{1,15}$ ]] || die "MySQL returned an invalid table count: '$cnt'"
  printf '%d\n' "$((10#$cnt))"
}

db_is_empty() {
  local cnt
  if ! cnt="$(db_table_count)"; then
    die "Unable to determine whether the database is empty"
  fi
  (( cnt == 0 ))
}

desired_schema_type() {
  if is_true "$VAULT_ENABLED"; then
    printf '%s\n' vault
  else
    printf '%s\n' lumina
  fi
}

db_schema_fingerprint() {
  local rows digest
  if ! rows="$(mysql_client --batch --skip-column-names --raw -e "
    SELECT schema_line FROM (
      SELECT CONCAT('D|', HEX(DEFAULT_CHARACTER_SET_NAME), '|',
                    HEX(DEFAULT_COLLATION_NAME), '|', IFNULL(HEX(SQL_PATH), '~')) AS schema_line
        FROM information_schema.SCHEMATA
       WHERE SCHEMA_NAME='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('T|', HEX(TABLE_NAME), '|', HEX(TABLE_TYPE), '|',
                    IFNULL(HEX(ENGINE), '~'), '|', IFNULL(HEX(TABLE_COLLATION), '~'), '|',
                    IFNULL(HEX(ROW_FORMAT), '~'), '|', HEX(CREATE_OPTIONS), '|',
                    HEX(TABLE_COMMENT)) AS schema_line
        FROM information_schema.TABLES
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('C|', HEX(TABLE_NAME), '|', LPAD(ORDINAL_POSITION, 10, '0'), '|',
                    HEX(COLUMN_NAME), '|', HEX(COLUMN_TYPE), '|', HEX(IS_NULLABLE), '|',
                    IFNULL(HEX(COLUMN_DEFAULT), '~'), '|', HEX(EXTRA), '|',
                    IFNULL(HEX(CHARACTER_SET_NAME), '~'), '|',
                    IFNULL(HEX(COLLATION_NAME), '~'), '|', HEX(COLUMN_COMMENT), '|',
                    IFNULL(HEX(GENERATION_EXPRESSION), '~'), '|', IFNULL(SRS_ID, '~')) AS schema_line
        FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('I|', HEX(TABLE_NAME), '|', HEX(INDEX_NAME), '|',
                    LPAD(SEQ_IN_INDEX, 10, '0'), '|', NON_UNIQUE, '|',
                    IFNULL(HEX(COLUMN_NAME), '~'), '|', IFNULL(SUB_PART, '~'), '|',
                    IFNULL(HEX(COLLATION), '~'), '|', HEX(NULLABLE), '|',
                    HEX(INDEX_TYPE), '|', HEX(IS_VISIBLE), '|',
                    IFNULL(HEX(EXPRESSION), '~')) AS schema_line
        FROM information_schema.STATISTICS
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('N|', HEX(TABLE_NAME), '|',
                    IFNULL(HEX(PARTITION_NAME), '~'), '|',
                    IFNULL(LPAD(PARTITION_ORDINAL_POSITION, 10, '0'), '~'), '|',
                    IFNULL(HEX(SUBPARTITION_NAME), '~'), '|',
                    IFNULL(LPAD(SUBPARTITION_ORDINAL_POSITION, 10, '0'), '~'), '|',
                    IFNULL(HEX(PARTITION_METHOD), '~'), '|',
                    IFNULL(HEX(PARTITION_EXPRESSION), '~'), '|',
                    IFNULL(HEX(SUBPARTITION_METHOD), '~'), '|',
                    IFNULL(HEX(SUBPARTITION_EXPRESSION), '~'), '|',
                    IFNULL(HEX(PARTITION_DESCRIPTION), '~')) AS schema_line
        FROM information_schema.PARTITIONS
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('K|', HEX(TABLE_NAME), '|', HEX(CONSTRAINT_NAME), '|',
                    HEX(CONSTRAINT_TYPE), '|', HEX(ENFORCED)) AS schema_line
        FROM information_schema.TABLE_CONSTRAINTS
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('U|', HEX(TABLE_NAME), '|', HEX(CONSTRAINT_NAME), '|',
                    HEX(COLUMN_NAME), '|', LPAD(ORDINAL_POSITION, 10, '0'), '|',
                    IFNULL(POSITION_IN_UNIQUE_CONSTRAINT, '~'), '|',
                    IFNULL(HEX(REFERENCED_TABLE_SCHEMA), '~'), '|',
                    IFNULL(HEX(REFERENCED_TABLE_NAME), '~'), '|',
                    IFNULL(HEX(REFERENCED_COLUMN_NAME), '~')) AS schema_line
        FROM information_schema.KEY_COLUMN_USAGE
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('F|', HEX(TABLE_NAME), '|', HEX(CONSTRAINT_NAME), '|',
                    IFNULL(HEX(UNIQUE_CONSTRAINT_SCHEMA), '~'), '|',
                    IFNULL(HEX(UNIQUE_CONSTRAINT_NAME), '~'), '|', HEX(MATCH_OPTION), '|',
                    HEX(UPDATE_RULE), '|', HEX(DELETE_RULE), '|',
                    IFNULL(HEX(REFERENCED_TABLE_NAME), '~')) AS schema_line
        FROM information_schema.REFERENTIAL_CONSTRAINTS
       WHERE CONSTRAINT_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('H|', HEX(CONSTRAINT_NAME), '|', HEX(CHECK_CLAUSE)) AS schema_line
        FROM information_schema.CHECK_CONSTRAINTS
       WHERE CONSTRAINT_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('V|', HEX(TABLE_NAME), '|', HEX(VIEW_DEFINITION), '|',
                    HEX(CHECK_OPTION), '|', HEX(IS_UPDATABLE), '|', HEX(DEFINER), '|',
                    HEX(SECURITY_TYPE), '|', HEX(CHARACTER_SET_CLIENT), '|',
                    HEX(COLLATION_CONNECTION)) AS schema_line
        FROM information_schema.VIEWS
       WHERE TABLE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('G|', HEX(TRIGGER_NAME), '|', HEX(EVENT_MANIPULATION), '|',
                    HEX(EVENT_OBJECT_TABLE), '|', LPAD(ACTION_ORDER, 10, '0'), '|',
                    IFNULL(HEX(ACTION_CONDITION), '~'), '|', HEX(ACTION_STATEMENT), '|',
                    HEX(ACTION_ORIENTATION), '|', HEX(ACTION_TIMING), '|', HEX(SQL_MODE), '|',
                    HEX(DEFINER), '|', HEX(CHARACTER_SET_CLIENT), '|',
                    HEX(COLLATION_CONNECTION), '|', HEX(DATABASE_COLLATION)) AS schema_line
        FROM information_schema.TRIGGERS
       WHERE TRIGGER_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('R|', HEX(ROUTINE_NAME), '|', HEX(ROUTINE_TYPE), '|',
                    HEX(DATA_TYPE), '|', HEX(DTD_IDENTIFIER), '|',
                    IFNULL(HEX(ROUTINE_DEFINITION), '~'), '|', HEX(IS_DETERMINISTIC), '|',
                    HEX(SQL_DATA_ACCESS), '|', HEX(SECURITY_TYPE), '|', HEX(SQL_MODE), '|',
                    HEX(DEFINER), '|', HEX(CHARACTER_SET_CLIENT), '|',
                    HEX(COLLATION_CONNECTION), '|', HEX(DATABASE_COLLATION)) AS schema_line
        FROM information_schema.ROUTINES
       WHERE ROUTINE_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('P|', HEX(SPECIFIC_NAME), '|', LPAD(ORDINAL_POSITION, 10, '0'), '|',
                    IFNULL(HEX(PARAMETER_MODE), '~'), '|', IFNULL(HEX(PARAMETER_NAME), '~'), '|',
                    HEX(DATA_TYPE), '|', HEX(DTD_IDENTIFIER)) AS schema_line
        FROM information_schema.PARAMETERS
       WHERE SPECIFIC_SCHEMA='${MYSQL_DATABASE}'
      UNION ALL
      SELECT CONCAT('E|', HEX(EVENT_NAME), '|', HEX(EVENT_DEFINITION), '|',
                    HEX(EVENT_TYPE), '|', IFNULL(HEX(INTERVAL_VALUE), '~'), '|',
                    IFNULL(HEX(INTERVAL_FIELD), '~'), '|', IFNULL(HEX(STARTS), '~'), '|',
                    IFNULL(HEX(ENDS), '~'), '|', HEX(STATUS), '|', HEX(ON_COMPLETION), '|',
                    HEX(SQL_MODE), '|', HEX(DEFINER), '|', HEX(TIME_ZONE), '|',
                    HEX(CHARACTER_SET_CLIENT), '|', HEX(COLLATION_CONNECTION), '|',
                    HEX(DATABASE_COLLATION)) AS schema_line
        FROM information_schema.EVENTS
       WHERE EVENT_SCHEMA='${MYSQL_DATABASE}'
    ) AS live_schema
    ORDER BY schema_line;")"; then
    die "Failed to calculate the live MySQL schema fingerprint"
  fi
  [[ -n "$rows" ]] || die "Cannot fingerprint an empty MySQL schema"
  digest="$(printf '%s\n' "$rows" | sha256sum | awk '{print $1}')"
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || die "Invalid live schema fingerprint"
  printf '%s\n' "$digest"
}

schema_state_matches_live() {
  local expected_type="$1" expected_version="${2:-}" count fingerprint
  [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] || return 1
  count="$(db_table_count)"
  (( count > 0 )) || return 1
  fingerprint="$(db_schema_fingerprint)"
  jq -e \
    --arg database "$MYSQL_DATABASE" \
    --arg schema_type "$expected_type" \
    --arg schema_version "$expected_version" \
    --arg schema_fingerprint_sha256 "$fingerprint" \
    --argjson table_count "$count" '
      type == "object"
      and .database == $database
      and .schema_type == $schema_type
      and ((.schema_version // "") | test("^[0-9]{1,9}$"))
      and ($schema_version == "" or .schema_version == $schema_version)
      and .schema_fingerprint_sha256 == $schema_fingerprint_sha256
      and .table_count == $table_count
    ' < "$SCHEMA_STATE" >/dev/null 2>&1
}

schema_state_is_trusted() {
  schema_state_matches_live "$1" "$LUMINA_SCHEMA_VERSION"
}

ensure_publishable_database() {
  local count expected_type
  count="$(db_table_count)"
  (( count > 0 )) || die "Refusing to publish a snapshot of an empty database"
  expected_type="$(desired_schema_type)"
  schema_state_is_trusted "$expected_type" \
    || die "Refusing to publish: schema state does not match the live database"
}

################################################################
# Payload (DB) - pack/import
################################################################

pack_payload() {
  local dump_tmp plain_tmp encrypted_tmp passphrase_file
  dump_tmp="$(mktemp "${INSTALL_PATH}/.dump.sql.XXXXXX")"
  plain_tmp="$(mktemp "${INSTALL_PATH}/.${PLAIN_ARCHIVE_NAME}.XXXXXX")"
  encrypted_tmp="$(mktemp "${INSTALL_PATH}/.${ENCRYPTED_ARCHIVE_NAME}.XXXXXX")"
  passphrase_file="$(mktemp "${SYNC_RUNTIME_DIR}/passphrase.XXXXXX")"
  cleanup_add_file "$dump_tmp"
  cleanup_add_file "$plain_tmp"
  cleanup_add_file "$encrypted_tmp"
  cleanup_add_file "$passphrase_file"
  chmod 600 "$passphrase_file"

  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "SYNC_ENCRYPTION_PASSPHRASE is required for write-sync"

  log "Dumping DB '${MYSQL_DATABASE}'" >&2

  if ! MYSQL_PWD="$MYSQL_PASSWORD" mariadb-dump --no-defaults \
    --protocol=TCP \
    -h "$MYSQL_HOST" \
    -P "$MYSQL_PORT" \
    -u "$MYSQL_USER" \
    --single-transaction \
    --quick \
    --routines \
    --events \
    --triggers \
    --hex-blob \
    --no-tablespaces \
    --skip-dump-date \
    --databases "$MYSQL_DATABASE" \
    > "$dump_tmp"; then
    rm -f -- "$dump_tmp" "$plain_tmp" "$encrypted_tmp" "$passphrase_file"
    die "mariadb-dump failed; no snapshot was published"
  fi
  [[ -s "$dump_tmp" ]] || die "mariadb-dump produced an empty file; no snapshot was published"
  ensure_file_within_mb "$dump_tmp" "$SYNC_MAX_EXTRACT_MB" "SQL dump"

  if ! zstd -q -T0 -19 -o "$plain_tmp" "$dump_tmp" || ! zstd -q -t "$plain_tmp"; then
    rm -f -- "$dump_tmp" "$plain_tmp" "$encrypted_tmp" "$passphrase_file"
    die "zstd compression or verification failed; no snapshot was published"
  fi

  PACK_CONTENT_SHA="$(sha256sum "$plain_tmp" | awk '{print $1}')"
  printf '%s' "$SYNC_ENCRYPTION_PASSPHRASE" > "$passphrase_file"

  if ! GNUPGHOME="$GPG_HOME" gpg --no-options --batch --yes --no-tty \
      --no-symkey-cache \
      --pinentry-mode loopback \
      --passphrase-file "$passphrase_file" \
      --symmetric --cipher-algo AES256 --compress-algo none \
      --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 \
      --output "$encrypted_tmp" "$plain_tmp"; then
    rm -f -- "$dump_tmp" "$plain_tmp" "$encrypted_tmp" "$passphrase_file"
    die "GPG encryption failed; no snapshot was published"
  fi

  PACK_SIZE="$(stat -c '%s' "$encrypted_tmp")"
  ensure_file_within_mb "$encrypted_tmp" "$SYNC_MAX_RESTORE_MB" "Encrypted snapshot"
  rm -f -- "$dump_tmp" "$plain_tmp" "$passphrase_file"
  mv -f -- "$encrypted_tmp" "$ARCHIVE_PATH"

  PACK_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
  PACK_HMAC="$(archive_hmac_sha256 "$ARCHIVE_PATH")" \
    || die "Snapshot HMAC generation failed; no snapshot was published"
  log "Prepared encrypted DB snapshot (sha=${PACK_SHA} size=${PACK_SIZE})" >&2
}

gpg_decrypt_bounded() {
  local encrypted="$1"
  local plain="$2"
  local passphrase_file output_limit output_size gpg_status head_status
  local -a pipeline_status
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] || return 1
  passphrase_file="$(mktemp "${SYNC_RUNTIME_DIR}/passphrase.XXXXXX")"
  cleanup_add_file "$passphrase_file"
  chmod 600 "$passphrase_file"
  printf '%s' "$SYNC_ENCRYPTION_PASSPHRASE" > "$passphrase_file"
  output_limit=$((SYNC_MAX_RESTORE_MB * 1000000 + 1))
  set +e
  GNUPGHOME="$GPG_HOME" gpg --no-options --batch --yes --no-tty \
      --no-symkey-cache \
      --pinentry-mode loopback \
      --passphrase-file "$passphrase_file" \
      --decrypt "$encrypted" | head -c "$output_limit" > "$plain"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  gpg_status="${pipeline_status[0]}"
  head_status="${pipeline_status[1]}"
  rm -f -- "$passphrase_file"
  output_size="$(stat -c '%s' "$plain")"
  (( output_size <= SYNC_MAX_RESTORE_MB * 1000000 \
      && gpg_status == 0 && head_status == 0 ))
}

decrypt_payload() {
  local encrypted="$1" plain="$2"
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "Encrypted snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
  if ! gpg_decrypt_bounded "$encrypted" "$plain"; then
    rm -f -- "$plain"
    die "Snapshot decryption/authentication failed or exceeded SYNC_MAX_RESTORE_MB"
  fi
}

recreate_database() {
  mysql_client -e \
    "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;" \
    || die "DROP/CREATE DATABASE failed; refusing to import over an existing schema"
}

import_plain_archive() {
  local plain="$1"
  local expected_schema_fingerprint="$2"
  local sql_tmp original_was_empty=0 extract_limit extract_size zstd_status head_status
  local import_ok=1 imported_count="" imported_fingerprint=""
  local -a pipeline_status
  [[ "$expected_schema_fingerprint" =~ ^[a-fA-F0-9]{64}$ ]] \
    || die "Snapshot schema fingerprint is invalid"
  sql_tmp="$(mktemp "${INSTALL_PATH}/.restore.sql.XXXXXX")"
  cleanup_add_file "$sql_tmp"
  extract_limit=$((SYNC_MAX_EXTRACT_MB * 1000000 + 1))
  set +e
  zstd -dc -- "$plain" | head -c "$extract_limit" > "$sql_tmp"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  zstd_status="${pipeline_status[0]}"
  head_status="${pipeline_status[1]}"
  extract_size="$(stat -c '%s' "$sql_tmp")"
  if (( extract_size > SYNC_MAX_EXTRACT_MB * 1000000 )); then
    rm -f -- "$sql_tmp"
    die "Decompressed SQL exceeds SYNC_MAX_EXTRACT_MB=${SYNC_MAX_EXTRACT_MB}"
  fi
  (( extract_size > 0 )) || die "Snapshot decompressed to an empty SQL file"
  (( zstd_status == 0 && head_status == 0 )) \
    || die "Snapshot decompression failed"

  if db_is_empty; then
    original_was_empty=1
    prepare_empty_restore_recovery
  else
    prepare_remote_restore_recovery
  fi

  verify_live_schema_against_recovery_marker "$RESTORE_RECOVERY_META" \
    || die "Restore target changed after rollback commit; refusing to recreate the database"
  recreate_database
  log "Importing DB from verified snapshot"
  if ! mysql_client < "$sql_tmp"; then
    import_ok=0
  elif ! imported_count="$(db_table_count)" || (( imported_count == 0 )); then
    import_ok=0
  elif ! imported_fingerprint="$(db_schema_fingerprint)"; then
    import_ok=0
  elif [[ "${imported_fingerprint,,}" != "${expected_schema_fingerprint,,}" ]]; then
    log "ERROR: imported schema fingerprint does not match the authenticated manifest"
    import_ok=0
  fi
  if (( import_ok == 0 )); then
    log "ERROR: snapshot import failed; rolling back the previous database"
    if restore_pending_remote_restore; then
      if (( original_was_empty == 1 )); then
        die "DB import failed; the previously empty target was reset to empty"
      fi
      die "DB import failed; the original database was restored from the durable local rollback dump"
    fi
    die "DB import and automatic rollback both failed; durable recovery artifacts were retained"
  fi
  rm -f -- "$sql_tmp"
  log "Snapshot import validated; rollback remains armed until schema validation/upgrade commits"
}

import_payload() {
  local source="$1"
  local expected_content_sha="$2"
  local expected_schema_fingerprint="$3"
  local tmp plain
  tmp="$(mktemp -d "${INSTALL_PATH}/_dbimport.XXXXXX")"
  cleanup_add_dir "$tmp"
  plain="$tmp/$PLAIN_ARCHIVE_NAME"

  decrypt_payload "$source" "$plain"

  if [[ -n "$expected_content_sha" ]]; then
    [[ "$expected_content_sha" =~ ^[a-fA-F0-9]{64}$ ]] \
      || die "Invalid decrypted content checksum in manifest"
    local actual_content_sha
    actual_content_sha="$(sha256sum "$plain" | awk '{print $1}')"
    [[ "$actual_content_sha" == "$expected_content_sha" ]] \
      || die "Decrypted snapshot checksum mismatch"
  fi
  import_plain_archive "$plain" "$expected_schema_fingerprint"
}

################################################################
# Chunking helpers
################################################################

validate_current_manifest() {
  local manifest="$1"
  [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
  jq -e \
    --arg host_id "$SYNC_HOST_ID" \
    --arg archive_name "$ARCHIVE_NAME" \
    --arg sync_method "${SYNC_METHOD,,}" \
    --arg release_generation_regex "$RELEASE_GENERATION_REGEX" '
      type == "object"
      and .version == 3
      and .service == "lumina"
      and .host_id == $host_id
      and ((.generation | type) == "string")
      and (
        if $sync_method == "commits" then .generation == ""
        elif $sync_method == "releases" then (.generation | test($release_generation_regex))
        else false
        end
      )
      and .encrypted == true
      and .encryption == "gpg-symmetric-aes256"
      and .archive_name == $archive_name
      and ((.archive_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.archive_hmac_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.manifest_hmac_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.content_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.archive_size_bytes | type) == "number")
      and (.archive_size_bytes >= 1)
      and ((.archive_size_bytes | floor) == .archive_size_bytes)
      and ((.chunk_size_mb | type) == "number")
      and (.chunk_size_mb >= 1 and .chunk_size_mb <= 49)
      and ((.chunk_size_mb | floor) == .chunk_size_mb)
      and ((.chunk_count | type) == "number")
      and (.chunk_count >= 1 and .chunk_count <= 10000)
      and ((.chunk_count | floor) == .chunk_count)
      and (.chunk_names | type == "array")
      and (.chunk_names | length == .chunk_count)
      and ((.chunk_names | unique | length) == (.chunk_names | length))
      and all(.chunk_names[];
        type == "string"
        and test("^[A-Za-z0-9._-]+$")
        and (contains("..") | not))
      and (.schema_type == "lumina" or .schema_type == "vault")
      and ((.schema_version // "") | test("^[0-9]{1,9}$"))
      and ((.schema_fingerprint_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
    ' < "$manifest" >/dev/null 2>&1 \
    && verify_manifest_hmac "$manifest"
}

validate_commit_namespace() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" part name schema_type schema_version
  local -a encrypted_parts=() declared_parts=()
  ensure_safe_remote_dir
  while IFS= read -r -d '' part; do
    name="$(basename "$part")"
    [[ -f "$part" && ! -L "$part" ]] \
      || die "Commit snapshot namespace contains a non-regular artifact"
    case "$name" in
      "$MANIFEST_NAME") ;;
      "$ENCRYPTED_ARCHIVE_NAME".part_[0-9][0-9][0-9][0-9][0-9])
        encrypted_parts+=("$name")
        ;;
      *) die "Commit snapshot namespace contains an unsupported artifact; refusing mutation" ;;
    esac
  done < <(find "$REMOTE_DIR" -mindepth 1 -maxdepth 1 -print0)

  if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
    ((${#encrypted_parts[@]} == 0)) \
      || die "Commit snapshot chunks exist without an authenticated v3 manifest; refusing overwrite"
    return 1
  fi
  validate_current_manifest "$manifest" \
    || die "Commit manifest is not an authentic current-v3 manifest"
  schema_type="$(jq -r '.schema_type' < "$manifest")"
  schema_version="$(jq -r '.schema_version' < "$manifest")"
  validate_snapshot_schema_compatibility "$schema_type" "$schema_version"
  mapfile -t declared_parts < <(jq -r '.chunk_names[]' < "$manifest")
  for name in "${declared_parts[@]}"; do
    [[ "$name" =~ ^dump\.sql\.zst\.gpg\.part_[0-9]{5}$ ]] \
      || die "Commit manifest references a non-current chunk name: '$name'"
  done
  for name in "${encrypted_parts[@]}"; do
    printf '%s\n' "${declared_parts[@]}" | grep -Fxq -- "$name" \
      || die "Unreferenced commit snapshot artifact conflicts with the current namespace: '$name'"
  done
  return 0
}

clear_authenticated_commit_snapshot() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" name
  ensure_safe_remote_dir
  [[ -f "$manifest" && ! -L "$manifest" ]] || return 0
  validate_current_manifest "$manifest" \
    || die "Refusing to replace an unauthenticated commit snapshot"
  while IFS= read -r name; do
    [[ "$name" =~ ^dump\.sql\.zst\.gpg\.part_[0-9]{5}$ ]] \
      || die "Unsafe chunk in authenticated commit manifest"
    [[ ! -L "${REMOTE_DIR}/${name}" ]] || die "Refusing symlinked commit chunk"
    rm -f -- "${REMOTE_DIR}/${name}"
  done < <(jq -r '.chunk_names[]' < "$manifest")
  rm -f -- "$manifest"
}

split_archive_into_remote() {
  local bs=$(( SYNC_CHUNK_SIZE_MB * 1000000 )) expected_chunks
  expected_chunks=$(( (PACK_SIZE + bs - 1) / bs ))
  (( expected_chunks >= 1 && expected_chunks <= 10000 )) \
    || die "Commit snapshot would require ${expected_chunks} chunks; limit is 10000"

  ensure_safe_remote_dir
  clear_authenticated_commit_snapshot

  log "Splitting DB archive to ${REMOTE_DIR} by ${SYNC_CHUNK_SIZE_MB}MB"

  split -b "$bs" -d -a 5 \
    "$ARCHIVE_PATH" \
    "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"

  PACK_CHUNK_NAMES=()
  local part
  for part in "${REMOTE_DIR}/${ARCHIVE_NAME}.part_"*; do
    PACK_CHUNK_NAMES+=("$(basename "$part")")
  done
  ((${#PACK_CHUNK_NAMES[@]} > 0)) || die "Snapshot split produced no chunks"
}

assemble_remote_archive() {
  local manifest="$1"
  local source_dir="$2"
  local dest="$3"

  rm -f "$dest"

  local -a names=()
  local declared_count declared_size declared_chunk_mb running_size=0 part_size max_bytes
  mapfile -t names < <(jq -r '.chunk_names[]? // empty' < "$manifest")
  declared_count="$(jq -r '.chunk_count // empty' < "$manifest")"
  [[ "$declared_count" =~ ^[0-9]{1,5}$ ]] || die "Manifest chunk_count is invalid"
  declared_count=$((10#$declared_count))
  (( declared_count == ${#names[@]} )) || die "Manifest chunk_count does not match chunk_names"
  ((${#names[@]} >= 1 && ${#names[@]} <= 10000)) \
    || die "Manifest contains an invalid number of chunks"
  declared_size="$(jq -r '.archive_size_bytes // empty' < "$manifest")"
  declared_chunk_mb="$(jq -r '.chunk_size_mb // empty' < "$manifest")"
  [[ "$declared_size" =~ ^[0-9]{1,15}$ ]] || die "Manifest archive_size_bytes is invalid"
  declared_size=$((10#$declared_size))
  [[ "$declared_chunk_mb" =~ ^[0-9]{1,2}$ ]] \
    && (( 10#$declared_chunk_mb >= 1 && 10#$declared_chunk_mb <= 49 )) \
    || die "Manifest chunk_size_mb is invalid"
  declared_chunk_mb=$((10#$declared_chunk_mb))
  max_bytes=$((SYNC_MAX_RESTORE_MB * 1000000))
  (( declared_size <= max_bytes )) || die "Manifest archive exceeds SYNC_MAX_RESTORE_MB"

  local name
  for name in "${names[@]}"; do
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$name" != *".."* ]] \
      || die "Unsafe chunk name in manifest: '$name'"
    [[ -f "$source_dir/$name" && ! -L "$source_dir/$name" ]] \
      || die "Snapshot chunk is missing or unsafe: '$name'"
    part_size="$(stat -c '%s' "$source_dir/$name")"
    (( part_size >= 1 && part_size <= declared_chunk_mb * 1000000 )) \
      || die "Snapshot chunk '$name' has an invalid size"
    running_size=$((running_size + part_size))
    (( running_size <= declared_size && running_size <= max_bytes )) \
      || die "Snapshot chunks exceed the declared/allowed size"
    cat -- "$source_dir/$name" >> "$dest"
  done
  (( running_size == declared_size )) || die "Snapshot chunks do not match declared archive size"
}

write_manifest() {
  local output="$1"
  local ts="$2"
  local generation="${3:-}"
  local chunks_json schema_type schema_version schema_fingerprint manifest_hmac
  local unsigned_tmp authenticated_tmp expected_type output_dir
  case "${SYNC_METHOD,,}" in
    commits)
      [[ -z "$generation" ]] || die "Commit manifests must have an empty generation"
      ;;
    releases)
      [[ "$generation" =~ $RELEASE_GENERATION_REGEX ]] \
        || die "Release manifests require the current generation format"
      ;;
    *) die "Cannot write a manifest for unknown SYNC_METHOD='$SYNC_METHOD'" ;;
  esac
  output_dir="$(dirname "$output")"
  [[ -d "$output_dir" && ! -L "$output_dir" ]] || die "Manifest output directory is unsafe"
  if [[ -e "$output" || -L "$output" ]]; then
    [[ -f "$output" && ! -L "$output" ]] || die "Manifest output path is unsafe"
  fi
  unsigned_tmp="$(mktemp "${output}.unsigned.XXXXXX")"
  authenticated_tmp="$(mktemp "${output}.auth.XXXXXX")"
  cleanup_add_file "$unsigned_tmp"
  cleanup_add_file "$authenticated_tmp"
  chunks_json="$(printf '%s\n' "${PACK_CHUNK_NAMES[@]}" | jq -R . | jq -s .)"
  expected_type="$(desired_schema_type)"
  schema_state_is_trusted "$expected_type" \
    || die "Cannot write a manifest from an untrusted schema state"
  schema_type="$(jq -r '.schema_type' < "$SCHEMA_STATE")"
  schema_version="$(jq -r '.schema_version' < "$SCHEMA_STATE")"
  schema_fingerprint="$(jq -r '.schema_fingerprint_sha256' < "$SCHEMA_STATE")"

  jq -n \
    --argjson version 3 \
    --arg service       "lumina" \
    --arg host_id       "${SYNC_HOST_ID}" \
    --arg timestamp_utc "$ts" \
    --arg generation "$generation" \
    --arg schema_type "$schema_type" \
    --arg schema_version "$schema_version" \
    --arg schema_fingerprint_sha256 "$schema_fingerprint" \
    --argjson chunk_size_mb      "${SYNC_CHUNK_SIZE_MB}" \
    --argjson chunk_count        "${#PACK_CHUNK_NAMES[@]}" \
    --argjson archive_size_bytes "${PACK_SIZE}" \
    --arg archive_name "$ARCHIVE_NAME" \
    --arg archive_sha256 "$PACK_SHA" \
    --arg archive_hmac_sha256 "$PACK_HMAC" \
    --arg content_sha256 "$PACK_CONTENT_SHA" \
    --argjson chunks "$chunks_json" \
     '{
       version:            $version,
       service:            $service,
       host_id:            $host_id,
       timestamp_utc:      $timestamp_utc,
       generation:         $generation,
       schema_type:        $schema_type,
       schema_version:     $schema_version,
       schema_fingerprint_sha256:$schema_fingerprint_sha256,
       encrypted:          true,
       encryption:         "gpg-symmetric-aes256",
       archive_name:       $archive_name,
       chunk_size_mb:      $chunk_size_mb,
       chunk_count:        $chunk_count,
       chunk_names:        $chunks,
       archive_size_bytes: $archive_size_bytes,
       archive_sha256:     $archive_sha256,
       archive_hmac_sha256:$archive_hmac_sha256,
       content_sha256:     $content_sha256
     }' > "$unsigned_tmp"

  manifest_hmac="$(manifest_hmac_sha256 "$unsigned_tmp")" \
    || die "Failed to authenticate snapshot manifest"
  jq --arg manifest_hmac_sha256 "$manifest_hmac" \
    '. + {manifest_hmac_sha256:$manifest_hmac_sha256}' \
    < "$unsigned_tmp" > "$authenticated_tmp"
  chmod 600 "$authenticated_tmp"
  sync -f "$authenticated_tmp" || die "Failed to flush authenticated snapshot manifest"
  mv -f -- "$authenticated_tmp" "$output"
  sync -f "$output_dir" || die "Failed to persist authenticated snapshot manifest"
  rm -f -- "$unsigned_tmp"

  log "Wrote manifest $output (chunks=${#PACK_CHUNK_NAMES[@]} sha=${PACK_SHA} size=${PACK_SIZE})"
}

validate_snapshot_schema_compatibility() {
  local schema_type="$1" schema_version="$2" expected_type
  expected_type="$(desired_schema_type)"
  [[ "$schema_type" == "$expected_type" ]] \
    || die "Snapshot schema type '$schema_type' is incompatible with configured type '$expected_type'"
  [[ "$schema_version" =~ ^[0-9]{1,9}$ ]] \
    || die "Snapshot schema version is invalid"
  schema_version=$((10#$schema_version))
  (( schema_version <= LUMINA_SCHEMA_VERSION )) \
    || die "Snapshot schema version ${schema_version} is newer than image schema version ${LUMINA_SCHEMA_VERSION}"
}

restore_from_remote() {
  local tmp sha_remote sha_local hmac_remote content_remote size_remote size_local schema_fingerprint
  ensure_safe_remote_dir

  [[ -f "${REMOTE_DIR}/${MANIFEST_NAME}" ]] \
    || die "Manifest not found: ${REMOTE_DIR}/${MANIFEST_NAME}"

  tmp="$(mktemp -d "${INSTALL_PATH}/_dbrestore.XXXXXX")"
  cleanup_add_dir "$tmp"

  validate_current_manifest "${REMOTE_DIR}/${MANIFEST_NAME}" \
    || die "Snapshot manifest is not an authentic current-v3 manifest"
  RESTORED_SCHEMA_TYPE="$(jq -r '.schema_type' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  RESTORED_SCHEMA_VERSION="$(jq -r '.schema_version' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  schema_fingerprint="$(jq -r '.schema_fingerprint_sha256' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  RESTORED_SCHEMA_FINGERPRINT="$schema_fingerprint"
  validate_snapshot_schema_compatibility "$RESTORED_SCHEMA_TYPE" "$RESTORED_SCHEMA_VERSION"

  assemble_remote_archive \
    "${REMOTE_DIR}/${MANIFEST_NAME}" "$REMOTE_DIR" "$tmp/payload"

  sha_remote="$(jq -r '.archive_sha256' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  size_remote="$(jq -r '.archive_size_bytes // empty' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  [[ "$sha_remote" =~ ^[a-fA-F0-9]{64}$ ]] \
    || die "Invalid archive checksum in manifest"
  [[ "$size_remote" =~ ^[0-9]+$ ]] || die "Invalid archive size in manifest"
  size_local="$(stat -c '%s' "$tmp/payload")"
  [[ "$size_local" == "$size_remote" ]] || die "Snapshot size does not match manifest"
  sha_local="$(sha256sum "$tmp/payload" | awk '{print $1}')"

  [[ "$sha_remote" == "$sha_local" ]] \
    || die "DB checksum mismatch: remote=$sha_remote local=$sha_local"
  hmac_remote="$(jq -r '.archive_hmac_sha256' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  verify_archive_hmac "$tmp/payload" "$hmac_remote" \
    || die "Snapshot HMAC verification failed"
  content_remote="$(jq -r '.content_sha256 // empty' < "${REMOTE_DIR}/${MANIFEST_NAME}")"
  [[ "$content_remote" =~ ^[a-fA-F0-9]{64}$ ]] \
    || die "Manifest has an invalid content checksum"
  import_payload "$tmp/payload" "$content_remote" "$schema_fingerprint"
  rm -rf -- "$tmp"

  log "DB restore completed (sha=$sha_remote)"
}

################################################################
# Commits mode
################################################################

ensure_tools_commits() {
  local missing=()
  local tools=(git ssh timeout zstd jq sha256sum split mysql mariadb-dump openssl gpg gosu python3 setsid flock du sort)

  for t in "${tools[@]}"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done

  ((${#missing[@]}==0)) || die "Missing tools: ${missing[*]}"
}

git_network() {
  timeout --foreground --kill-after=30s "$SYNC_NETWORK_TIMEOUT_SECONDS" git "$@"
}

GH_MODE=""
COMMITS_REMOTE_COMMIT=""
COMMITS_ADVERTISED_OID=""
COMMITS_TREE_INDEX=""
COMMITS_TREE_HAS_SNAPSHOT=false
COMMITS_TREE_MANIFEST_OID=""
COMMITS_TREE_MANIFEST_TMP=""

gh_git_mode_detect() {
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for commits mode"
  git check-ref-format --branch "$GH_BRANCH" >/dev/null 2>&1 \
    || die "GH_BRANCH is not a valid branch name"

  if [[ "$GH_REMOTE" =~ ^https:// ]]; then
    if [[ -n "$SYNC_AUTH_TOKEN" ]]; then
      GH_MODE="HTTPS_AUTH"
    else
      GH_MODE="HTTPS_PUBLIC"
    fi
  elif [[ "$GH_REMOTE" =~ ^git@ || "$GH_REMOTE" =~ ^ssh:// ]]; then
    [[ -n "$GH_SSH_PRIVATE_KEY" ]] || die "SSH remote requires GH_SSH_PRIVATE_KEY"
    GH_MODE="SSH_AUTH"
  else
    die "Unsupported GH_REMOTE scheme (use https:// or ssh:// / git@)"
  fi

  log "Commits mode: ${GH_MODE}"
}

ensure_safe_work_dir() {
  local install_real work_real
  [[ "$INSTALL_PATH" == "/opt/lumina" \
      && "$WORK_DIR" == "${INSTALL_PATH}/_gitmirror" \
      && "$REMOTE_DIR" == "${WORK_DIR}/backups/${SYNC_HOST_ID}" ]] \
    || die "Unexpected commits worktree path configuration"
  [[ -d "$INSTALL_PATH" && ! -L "$INSTALL_PATH" ]] \
    || die "Lumina install path is missing or symlinked"
  install_real="$(realpath -e -- "$INSTALL_PATH")" \
    || die "Cannot resolve Lumina install path"
  [[ "$install_real" == "$INSTALL_PATH" ]] \
    || die "Lumina install path contains a symlink"
  if [[ -e "$WORK_DIR" || -L "$WORK_DIR" ]]; then
    [[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] \
      || die "Commits worktree must be a real directory, not a symlink"
  else
    mkdir -m 700 -- "$WORK_DIR" || die "Failed to create commits worktree"
  fi
  work_real="$(realpath -e -- "$WORK_DIR")" || die "Cannot resolve commits worktree"
  [[ "$work_real" == "$WORK_DIR" && "$work_real" == "${install_real}/_gitmirror" ]] \
    || die "Commits worktree escapes the fixed Lumina directory"
}

ensure_safe_remote_dir() {
  local backups_dir="${WORK_DIR}/backups" work_real backups_real remote_real
  ensure_safe_work_dir
  work_real="$(realpath -e -- "$WORK_DIR")" || die "Cannot resolve commits worktree"
  if [[ -e "$backups_dir" || -L "$backups_dir" ]]; then
    [[ -d "$backups_dir" && ! -L "$backups_dir" ]] \
      || die "Remote commits backups path is not a real directory"
  else
    mkdir -m 700 -- "$backups_dir" || die "Failed to create commits backups directory"
  fi
  backups_real="$(realpath -e -- "$backups_dir")" \
    || die "Cannot resolve commits backups directory"
  [[ "$backups_real" == "$backups_dir" && "$backups_real" == "${work_real}/backups" ]] \
    || die "Commits backups directory escapes the worktree"
  if [[ -e "$REMOTE_DIR" || -L "$REMOTE_DIR" ]]; then
    [[ -d "$REMOTE_DIR" && ! -L "$REMOTE_DIR" ]] \
      || die "Remote commits host path is not a real directory"
  else
    mkdir -m 700 -- "$REMOTE_DIR" || die "Failed to create commits host directory"
  fi
  remote_real="$(realpath -e -- "$REMOTE_DIR")" \
    || die "Cannot resolve commits host directory"
  [[ "$remote_real" == "$REMOTE_DIR" \
      && "$remote_real" == "${backups_real}/${SYNC_HOST_ID}" \
      && "$remote_real" == "${work_real}/"* ]] \
    || die "Remote commits host directory escapes the worktree"
}

gh_git_setup() {
  ensure_safe_work_dir
  if [[ -e "$WORK_DIR/.git" || -L "$WORK_DIR/.git" ]]; then
    [[ -d "$WORK_DIR/.git" && ! -L "$WORK_DIR/.git" ]] \
      || die "Git metadata path is not a real directory"
  fi

  mkdir -p "$SYNC_RUNTIME_DIR"
  chmod 700 "$SYNC_RUNTIME_DIR"
  export GIT_TERMINAL_PROMPT=0
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_ATTR_NOSYSTEM=1
  export GIT_NO_REPLACE_OBJECTS=1

  # Keep the token out of the remote URL, git config, command line, and logs.
  if [[ "$GH_REMOTE" =~ ^https:// && -n "$SYNC_AUTH_TOKEN" ]]; then
    local askpass="${SYNC_RUNTIME_DIR}/git-askpass.sh"
    local token_file="${SYNC_RUNTIME_DIR}/git-token"
    printf '%s' "$SYNC_AUTH_TOKEN" > "$token_file"
    chmod 600 "$token_file"
    cleanup_add_file "$token_file"
    cat > "$askpass" <<'ASKPASS'
#!/bin/sh
case "$1" in
  *sername*) printf '%s\n' 'x-access-token' ;;
  *assword*) cat -- "$LUMINA_GIT_TOKEN_FILE" ;;
  *) exit 1 ;;
esac
ASKPASS
    chmod 700 "$askpass"
    cleanup_add_file "$askpass"
    export GIT_ASKPASS="$askpass"
    export LUMINA_GIT_TOKEN_FILE="$token_file"
  fi

  if [[ "$GH_REMOTE" =~ ^git@ || "$GH_REMOTE" =~ ^ssh:// ]]; then
    [[ -n "${GH_KNOWN_HOSTS:-}" ]] \
      || die "GH_KNOWN_HOSTS is required for SSH sync; insecure host-key bypass is disabled"
    mkdir -p "${SYNC_RUNTIME_DIR}/ssh"
    chmod 700 "${SYNC_RUNTIME_DIR}/ssh"

    local key="${SYNC_RUNTIME_DIR}/ssh/id_ed25519"

    if [[ -n "${GH_SSH_PRIVATE_KEY:-}" ]]; then
      if ! grep -q "BEGIN OPENSSH PRIVATE KEY" <<<"$GH_SSH_PRIVATE_KEY"; then
        key="${SYNC_RUNTIME_DIR}/ssh/id_rsa"
      fi
      printf '%s\n' "$GH_SSH_PRIVATE_KEY" > "$key"
      chmod 600 "$key"
    fi

    printf '%s\n' "$GH_KNOWN_HOSTS" > "${SYNC_RUNTIME_DIR}/ssh/known_hosts"
    chmod 600 "${SYNC_RUNTIME_DIR}/ssh/known_hosts"
    export GIT_SSH_COMMAND="ssh -F /dev/null -i ${key} \
      -o IdentitiesOnly=yes \
      -o UserKnownHostsFile=${SYNC_RUNTIME_DIR}/ssh/known_hosts \
      -o StrictHostKeyChecking=yes"
  fi

}

gh_git_reinitialize_repository() {
  ensure_safe_work_dir
  if [[ -e "$WORK_DIR" || -L "$WORK_DIR" ]]; then
    [[ -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] \
      || die "Commits worktree must be a real directory"
    rm -rf -- "$WORK_DIR"
  fi
  mkdir -m 700 -- "$WORK_DIR"
  git init --quiet --initial-branch="$GH_BRANCH" "$WORK_DIR"
  git -C "$WORK_DIR" remote add origin "$GH_REMOTE"
  git -C "$WORK_DIR" config user.name "$GH_COMMIT_NAME"
  git -C "$WORK_DIR" config user.email "$GH_COMMIT_EMAIL"
  git -C "$WORK_DIR" config protocol.version 2
  git -C "$WORK_DIR" config remote.origin.promisor true
  git -C "$WORK_DIR" config remote.origin.partialclonefilter blob:none
  git -C "$WORK_DIR" config fetch.recurseSubmodules false
  git -C "$WORK_DIR" config submodule.recurse false
  git -C "$WORK_DIR" config fetch.unpackLimit 1
  git -C "$WORK_DIR" config transfer.unpackLimit 1
  git -C "$WORK_DIR" config gc.auto 0
}

commits_remote_branch_exists() {
  local trace refs_file refs expected_ref="refs/heads/${GH_BRANCH}"
  local oid ref extra trace_size refs_size
  trace="$(mktemp /run/lumina-git-capabilities.XXXXXX)"
  refs_file="$(mktemp /run/lumina-git-refs.XXXXXX)"
  cleanup_add_file "$trace"
  cleanup_add_file "$refs_file"
  if ! (ulimit -f 2048 || exit 125; GIT_TRACE_PACKET="$trace" GIT_PROTOCOL=version=2 \
      git_network -C "$WORK_DIR" ls-remote --heads origin "$expected_ref") >"$refs_file"; then
    die "Failed to query remote branch '${GH_BRANCH}'"
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
  raw="$(mktemp /run/lumina-git-tree-path.XXXXXX)"
  cleanup_add_file "$raw"
  git -C "$WORK_DIR" ls-tree -z "$commit" -- "$path" >"$raw" \
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
  COMMITS_TREE_INDEX="$(mktemp /run/lumina-git-tree-index.XXXXXX)"
  cleanup_add_file "$COMMITS_TREE_INDEX"
  : >"$COMMITS_TREE_INDEX"
  if ! commits_tree_path_is_directory "$commit" backups; then return 0; fi
  if ! commits_tree_path_is_directory "$commit" "$scope"; then return 0; fi

  raw="$(mktemp /run/lumina-git-tree.XXXXXX)"
  cleanup_add_file "$raw"
  if ! (ulimit -f 4096 || exit 125; git -C "$WORK_DIR" ls-tree -r -z "$commit" -- "$scope") >"$raw"; then
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
      dump.sql.zst.gpg.part_[0-9][0-9][0-9][0-9][0-9]) ((chunk_count+=1)) ;;
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
  output="$(mktemp /run/lumina-commit-manifest.XXXXXX)"
  cleanup_add_file "$output"
  if ! (ulimit -f 4096 || exit 125; git_network -C "$WORK_DIR" cat-file blob \
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
      git_network -C "$WORK_DIR" cat-file -s "$oid") )"; then
    return 1
  fi
  [[ "$size" =~ ^[1-9][0-9]{0,15}$ ]] || return 1
  printf '%s\n' "$size"
}

commits_fetch_declared_chunks_bounded() {
  local manifest="$1" chunk_mb count_declared archive_size chunk_limit max_bytes
  local total=0 count=0 name oid expected declared_name size
  local objects_before objects_now objects_limit
  chunk_mb="$(jq -r '.chunk_size_mb' "$manifest")"
  count_declared="$(jq -r '.chunk_count' "$manifest")"
  archive_size="$(jq -r '.archive_size_bytes' "$manifest")"
  [[ "$chunk_mb" =~ ^[0-9]{1,2}$ && "$count_declared" =~ ^[0-9]{1,5}$ && \
     "$archive_size" =~ ^[0-9]{1,15}$ ]] \
    || die "Authenticated commits manifest has invalid numeric declarations"
  chunk_limit=$((10#$chunk_mb * 1000000))
  max_bytes=$((10#$SYNC_MAX_RESTORE_MB * 1000000))
  ((10#$archive_size <= max_bytes)) || die "Manifest archive exceeds SYNC_MAX_RESTORE_MB"
  objects_before="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
  [[ "$objects_before" =~ ^[0-9]+$ ]] || die "Could not measure Git object storage"
  objects_limit=$((10#$objects_before + 10#$archive_size + 67108864))
  while IFS=$'\t' read -r name oid; do
    [[ "$name" == "$MANIFEST_NAME" ]] && continue
    printf -v expected '%s.part_%05d' "$ARCHIVE_NAME" "$count"
    declared_name="$(jq -r --argjson index "$count" '.chunk_names[$index] // empty' "$manifest")"
    [[ "$name" == "$expected" && "$declared_name" == "$expected" ]] \
      || die "Commits tree chunks are not the exact authenticated current sequence"
    size="$(commits_blob_size_bounded "$oid" "$chunk_limit")" \
      || die "Chunk '$name' could not be size-checked within its hard bound"
    ((10#$size <= chunk_limit)) || die "Chunk '$name' exceeds manifest.chunk_size_mb"
    ((total += 10#$size, count += 1))
    ((total <= 10#$archive_size && total <= max_bytes)) \
      || die "Commits chunks exceed the declared/allowed aggregate size"
    objects_now="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
    [[ "$objects_now" =~ ^[0-9]+$ ]] && ((10#$objects_now <= objects_limit)) \
      || die "Git object storage exceeded the bounded target-namespace allowance"
  done <"$COMMITS_TREE_INDEX"
  ((count == 10#$count_declared)) \
    || die "Commits tree chunk count does not match the authenticated manifest"
  ((total == 10#$archive_size)) \
    || die "Commits tree chunk sizes do not match the authenticated manifest"
}

commits_materialize_target_namespace() {
  local commit="${1:-}" scope="backups/${SYNC_HOST_ID}" unexpected
  local name oid output size limit_kib
  if [[ -n "$commit" ]]; then
    git -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" "$commit"
  fi
  git -C "$WORK_DIR" symbolic-ref HEAD "refs/heads/${GH_BRANCH}"
  ensure_safe_remote_dir
  if [[ "$COMMITS_TREE_HAS_SNAPSHOT" == true ]]; then
    while IFS=$'\t' read -r name oid; do
      output="${REMOTE_DIR}/${name}"
      size="$(GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" cat-file -s "$oid")"
      [[ "$size" =~ ^[1-9][0-9]{0,15}$ ]] \
        || die "Could not re-read preflighted object size for '$name'"
      limit_kib=$(((10#$size + 1048576 + 1023) / 1024))
      if ! (ulimit -f "$limit_kib" || exit 125; GIT_NO_LAZY_FETCH=1 \
          git_network -C "$WORK_DIR" cat-file blob "$oid") >"$output"; then
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
  GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" mktree </dev/null
}

commits_rewrite_tree_entry() (
  local parent_tree="$1" entry_name="$2" child_tree="$3"
  local raw filtered entry path result
  raw="$(mktemp /run/lumina-parent-tree.XXXXXX)"
  filtered="$(mktemp /run/lumina-rewritten-tree.XXXXXX)"
  trap 'rm -f -- "$raw" "$filtered"' EXIT
  if ! (ulimit -f 65536 || exit 125; GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" \
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
  result="$(GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" \
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
  local new_backups_tree new_root_tree old_root_tree new_commit oid name file index=0
  local chunk_list declared_count expected
  COMMITS_COMMIT_CREATED=false
  target_input="$(mktemp /run/lumina-target-tree.XXXXXX)"
  cleanup_add_file "$target_input"
  : >"$target_input"
  file="${REMOTE_DIR}/${MANIFEST_NAME}"
  oid="$(GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" \
    hash-object -w --no-filters -- "$file")"
  [[ "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ]] \
    || die "Git returned an invalid manifest blob object"
  printf '100644 blob %s\t%s\0' "$oid" "$MANIFEST_NAME" >>"$target_input"
  chunk_list="$(mktemp /run/lumina-publish-chunks.XXXXXX)"
  cleanup_add_file "$chunk_list"
  jq -r '.chunk_names[]' "${REMOTE_DIR}/${MANIFEST_NAME}" >"$chunk_list" \
    || die "Could not read authenticated manifest chunk_names"
  declared_count="$(jq -r '.chunk_count' "${REMOTE_DIR}/${MANIFEST_NAME}")"
  [[ "$declared_count" =~ ^[0-9]{1,5}$ ]] && ((10#$declared_count <= 10000)) \
    || die "Authenticated manifest chunk_count is invalid"
  while IFS= read -r name; do
    printf -v expected '%s.part_%05d' "$ARCHIVE_NAME" "$index"
    file="${REMOTE_DIR}/${expected}"
    [[ "$name" == "$expected" && -f "$file" && ! -L "$file" ]] \
      || die "Refusing to publish an unsafe/non-current chunk '$name'"
    oid="$(GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" \
      hash-object -w --no-filters -- "$file")"
    [[ "$oid" =~ ^[0-9a-f]{40}$ || "$oid" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid chunk blob object"
    printf '100644 blob %s\t%s\0' "$oid" "$name" >>"$target_input"
    ((index+=1))
  done <"$chunk_list"
  rm -f -- "$chunk_list"
  ((index == 10#$declared_count)) \
    || die "Published chunk list does not match authenticated manifest.chunk_count"
  target_tree="$(GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" \
    mktree -z <"$target_input")" || die "Could not build target namespace tree"
  rm -f -- "$target_input"
  [[ "$target_tree" =~ ^[0-9a-f]{40}$ || "$target_tree" =~ ^[0-9a-f]{64}$ ]] \
    || die "Git returned an invalid target tree object"
  if [[ -n "$COMMITS_REMOTE_COMMIT" ]]; then
    root_tree="$(git -C "$WORK_DIR" rev-parse "${COMMITS_REMOTE_COMMIT}^{tree}")"
    old_root_tree="$root_tree"
    if commits_tree_path_is_directory "$COMMITS_REMOTE_COMMIT" backups; then
      backups_tree="$(git -C "$WORK_DIR" rev-parse "${COMMITS_REMOTE_COMMIT}:backups")"
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
      git_network -C "$WORK_DIR" commit-tree "$new_root_tree" -p "$COMMITS_REMOTE_COMMIT")"
    [[ "$new_commit" =~ ^[0-9a-f]{40}$ || "$new_commit" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid commit object"
    git -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" \
      "$new_commit" "$COMMITS_REMOTE_COMMIT"
  else
    new_commit="$(printf '%s\n' "$message" | GIT_NO_LAZY_FETCH=1 \
      git_network -C "$WORK_DIR" commit-tree "$new_root_tree")"
    [[ "$new_commit" =~ ^[0-9a-f]{40}$ || "$new_commit" =~ ^[0-9a-f]{64}$ ]] \
      || die "Git returned an invalid initial commit object"
    git -C "$WORK_DIR" update-ref "refs/heads/${GH_BRANCH}" "$new_commit"
  fi
  COMMITS_REMOTE_COMMIT="$new_commit"
  COMMITS_COMMIT_CREATED=true
}

gh_git_pull_hard() {
  local object_bytes schema_type schema_version git_scan_status grep_scan_status
  local -a scan_statuses=()
  gh_git_reinitialize_repository
  COMMITS_REMOTE_COMMIT=""
  COMMITS_ADVERTISED_OID=""
  COMMITS_TREE_HAS_SNAPSHOT=false
  log "Fetching ${GH_BRANCH} (mode=${GH_MODE}, blobless preflight)"
  if commits_remote_branch_exists; then
    if ! (ulimit -f 65536 || exit 125; git_network -C "$WORK_DIR" fetch --no-tags --depth=1 \
        --filter=blob:none origin "$COMMITS_ADVERTISED_OID"); then
      die "Blobless commits fetch exceeded the 64 MiB metadata bound or failed"
    fi
    COMMITS_REMOTE_COMMIT="$(git -C "$WORK_DIR" rev-parse "FETCH_HEAD^{commit}")"
    [[ "$COMMITS_REMOTE_COMMIT" == "$COMMITS_ADVERTISED_OID" ]] \
      || die "Fetched commit does not match the exact advertised branch tip"
    git -C "$WORK_DIR" update-ref "refs/remotes/origin/${GH_BRANCH}" \
      "$COMMITS_REMOTE_COMMIT"
    object_bytes="$(du -sb "$WORK_DIR/.git/objects" | awk '{print $1}')"
    [[ "$object_bytes" =~ ^[0-9]+$ ]] && ((10#$object_bytes <= 67108864)) \
      || die "Blobless fetch exceeded the 64 MiB Git metadata allowance"
    set +e
    GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" cat-file --batch-check='%(objecttype)' \
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
      validate_current_manifest "$COMMITS_TREE_MANIFEST_TMP" \
        || die "Commit manifest is not an authentic current-v3 manifest"
      schema_type="$(jq -r '.schema_type' "$COMMITS_TREE_MANIFEST_TMP")"
      schema_version="$(jq -r '.schema_version' "$COMMITS_TREE_MANIFEST_TMP")"
      validate_snapshot_schema_compatibility "$schema_type" "$schema_version"
      commits_fetch_declared_chunks_bounded "$COMMITS_TREE_MANIFEST_TMP"
    fi
    commits_materialize_target_namespace "$COMMITS_REMOTE_COMMIT"
  else
    COMMITS_TREE_INDEX="$(mktemp /run/lumina-git-tree-index.XXXXXX)"
    cleanup_add_file "$COMMITS_TREE_INDEX"
    : >"$COMMITS_TREE_INDEX"
    commits_materialize_target_namespace
  fi

}

commit_snapshot_is_complete() {
  local manifest="${REMOTE_DIR}/${MANIFEST_NAME}" tmp payload plain
  local declared_sha actual_sha declared_size actual_size declared_content actual_content
  ensure_safe_remote_dir
  [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
  tmp="$(mktemp -d "${INSTALL_PATH}/_commitverify.XXXXXX")"
  cleanup_add_dir "$tmp"
  payload="$tmp/payload"
  plain="$tmp/$PLAIN_ARCHIVE_NAME"
  validate_current_manifest "$manifest" || return 1
  declared_content="$(jq -r '.content_sha256 // empty' < "$manifest")"
  assemble_remote_archive "$manifest" "$REMOTE_DIR" "$payload"
  declared_sha="$(jq -r '.archive_sha256 // empty' < "$manifest")"
  declared_size="$(jq -r '.archive_size_bytes // empty' < "$manifest")"
  [[ "$declared_sha" =~ ^[a-fA-F0-9]{64}$ && "$declared_size" =~ ^[0-9]+$ ]] || return 1
  actual_sha="$(sha256sum "$payload" | awk '{print $1}')"
  actual_size="$(stat -c '%s' "$payload")"
  [[ "$actual_sha" == "$declared_sha" && "$actual_size" == "$declared_size" ]] || return 1
  verify_archive_hmac "$payload" "$(jq -r '.archive_hmac_sha256 // empty' < "$manifest")" || return 1
  gpg_decrypt_bounded "$payload" "$plain" || return 1
  actual_content="$(sha256sum "$plain" | awk '{print $1}')"
  [[ "$actual_content" == "$declared_content" && "$actual_content" == "$PACK_CONTENT_SHA" ]]
}

COMMITS_REMOTE_PRESENT=false
COMMITS_REMOTE_MANIFEST=""

commits_load_materialized_state() {
  COMMITS_REMOTE_PRESENT=false
  COMMITS_REMOTE_MANIFEST=""
  if validate_commit_namespace; then
    COMMITS_REMOTE_PRESENT=true
    COMMITS_REMOTE_MANIFEST="$(cat "${REMOTE_DIR}/${MANIFEST_NAME}")"
  fi
}

perform_commits_sync() {
  local phase="${1:-publish}"
  ensure_tools_commits
  wait_for_db

  gh_git_mode_detect
  gh_git_setup
  gh_git_pull_hard
  commits_load_materialized_state

  if [[ "$phase" == "restore" ]]; then
    if [[ "$COMMITS_REMOTE_PRESENT" != "true" ]]; then
      if is_true "$SYNC_FORCE_RESTORE"; then
        die "SYNC_FORCE_RESTORE=true was requested, but no commit snapshot exists"
      fi
      log "No DB snapshot in repo -> keep local"
      return 0
    fi
    if is_true "$SYNC_FORCE_RESTORE" || db_is_empty; then
      log "Restoring DB snapshot from repo"
      restore_from_remote
    else
      log "Local DB is non-empty -> snapshot restore skipped"
    fi
    return 0
  fi

  if is_true "$SYNC_READ_ONLY"; then
    log "SYNC_READ_ONLY=true: commits publish skipped"
    return 0
  fi
  if [[ "$GH_MODE" == "HTTPS_PUBLIC" ]]; then
    log "Read-only commits sync: publish skipped"
    return 0
  fi

  local need_push="yes" content_remote attempt=1
  ensure_publishable_database
  pack_payload

  while ((attempt <= 3)); do
    if ((attempt > 1)); then
      warn "Git push raced with another writer; bounded blobless refetch/retry $attempt of 3"
      gh_git_pull_hard
      commits_load_materialized_state
    fi
    need_push="yes"
    if [[ "$COMMITS_REMOTE_PRESENT" == "true" ]]; then
      content_remote="$(jq -r '.content_sha256 // empty' <<<"$COMMITS_REMOTE_MANIFEST")"
      if [[ -n "$content_remote" && "$content_remote" == "$PACK_CONTENT_SHA" ]]; then
        if (
          CLEANUP_FILES=()
          CLEANUP_DIRS=()
          trap cleanup EXIT
          commit_snapshot_is_complete
        ); then
          log "Same as remote; chunk, SHA, HMAC, GPG, and archive verification passed -> skipping push"
          need_push="no"
        else
          log "Remote content hash matches but snapshot chunks are incomplete/corrupt -> republishing"
        fi
      fi
    fi
    [[ "$need_push" == "yes" ]] \
      || { log "Local snapshot matches commits remote"; return 0; }

    split_archive_into_remote
    write_manifest "${REMOTE_DIR}/${MANIFEST_NAME}" "$(now_utc)"
    validate_commit_namespace \
      || die "Refusing to publish an invalid current commits namespace"
    commits_create_snapshot_commit \
      "mysql-backup(${SYNC_HOST_ID}/${MYSQL_DATABASE}): size=${PACK_SIZE} sha256=${PACK_SHA}"
    if [[ "$COMMITS_COMMIT_CREATED" != true ]]; then
      log "DB: nothing to commit"
      return 0
    fi
    if GIT_NO_LAZY_FETCH=1 git_network -C "$WORK_DIR" push origin \
        "HEAD:refs/heads/${GH_BRANCH}"; then
      log "Pushed DB snapshot commit"
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
  local missing=()
  local tools=(curl timeout zstd jq sha256sum split sort mysql mariadb-dump openssl gpg mktemp gosu python3 setsid flock)

  for t in "${tools[@]}"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done

  ((${#missing[@]}==0)) || die "Missing tools: ${missing[*]}"
}

GH_OWNER=""
GH_REPO=""
HTTPS_ENDPOINT_HOST=""
HTTPS_ENDPOINT_PORT=""
HTTPS_ENDPOINT_PATH=""

parse_https_endpoint() {
  local value="$1" label="$2" authority host port path

  [[ "$value" =~ ^https://([^/?#]+)(/[^?#]*)?$ ]] \
    || die "$label must be an HTTPS URL without query parameters or fragments"
  authority="${BASH_REMATCH[1]}"
  path="${BASH_REMATCH[2]:-}"
  [[ "$authority" =~ ^([A-Za-z0-9.-]+)(:([0-9]{1,5}))?$ ]] \
    || die "$label contains an invalid HTTPS authority"
  host="${BASH_REMATCH[1],,}"
  port="${BASH_REMATCH[3]:-443}"
  port=$((10#$port))
  (( port >= 1 && port <= 65535 )) || die "$label contains an invalid HTTPS port"

  HTTPS_ENDPOINT_HOST="$host"
  HTTPS_ENDPOINT_PORT="$port"
  HTTPS_ENDPOINT_PATH="$path"
}

parse_gh_remote() {
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for releases mode"
  validate_gh_remote_syntax "$GH_REMOTE" \
    || die "GH_REMOTE is not a strict two-segment Git remote"

  local url="$GH_REMOTE"
  local tmp host path port remote_host remote_port api_host api_port api_path transport
  local upload_host upload_port upload_path api_authority upload_authority

  if [[ "$url" =~ ^https:// ]]; then
    transport="https"
    tmp="${url#*://}"
    host="${tmp%%/*}"
    path="${tmp#*/}"
  elif [[ "$url" =~ ^ssh://([^/]+)/(.+)$ ]]; then
    transport="ssh"
    host="${BASH_REMATCH[1]}"
    host="${host#*@}"
    path="${BASH_REMATCH[2]}"
  elif [[ "$url" =~ ^[^@]+@([^:]+):(.*)$ ]]; then
    transport="ssh"
    host="${BASH_REMATCH[1]}"
    path="${BASH_REMATCH[2]}"
  else
    die "Unsupported GH_REMOTE: $GH_REMOTE"
  fi

  [[ "$host" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] \
    || die "Git remote host contains unsupported characters"
  host="${host,,}"
  remote_host="${host%%:*}"
  remote_port="443"
  if [[ "$host" =~ :([0-9]{1,5})$ ]]; then
    port=$((10#${BASH_REMATCH[1]}))
    (( port >= 1 && port <= 65535 )) \
      || die "Git remote host contains an invalid port"
    [[ "$transport" != "https" ]] || remote_port="$port"
  fi

  path="${path%.git}"
  [[ "$path" == */* && "$path" != */*/* ]] \
    || die "GH_REMOTE must contain exactly owner/repository path segments"
  GH_OWNER="${path%%/*}"
  GH_REPO="${path#*/}"

  [[ -n "$GH_OWNER" && -n "$GH_REPO" ]] \
    || die "Cannot parse owner/repo from GH_REMOTE ($GH_REMOTE)"
  [[ "$GH_OWNER" =~ ^[A-Za-z0-9_.-]+$ && "$GH_REPO" =~ ^[A-Za-z0-9_.-]+$ ]] \
    || die "GH_REMOTE owner/repository contains unsupported characters"
  [[ "$GH_OWNER" != "." && "$GH_OWNER" != ".." \
      && "$GH_REPO" != "." && "$GH_REPO" != ".." ]] \
    || die "GH_REMOTE owner/repository is unsafe"

  api_authority="$remote_host"
  [[ "$remote_port" == "443" ]] || api_authority+=":${remote_port}"

  if [[ -z "$GH_API" ]]; then
    if [[ "$remote_host" == "github.com" && "$remote_port" == "443" ]]; then
      GH_API="https://api.github.com"
    else
      GH_API="https://${api_authority}/api/v3"
    fi
  fi

  if [[ -z "$GH_UPLOAD" ]]; then
    if [[ "$remote_host" == "github.com" && "$remote_port" == "443" ]]; then
      GH_UPLOAD="https://uploads.github.com"
    else
      GH_UPLOAD="https://${api_authority}/api/uploads"
    fi
  fi

  parse_https_endpoint "$GH_API" "GH_API"
  api_host="$HTTPS_ENDPOINT_HOST"
  api_port="$HTTPS_ENDPOINT_PORT"
  api_path="$HTTPS_ENDPOINT_PATH"
  parse_https_endpoint "$GH_UPLOAD" "GH_UPLOAD"
  upload_host="$HTTPS_ENDPOINT_HOST"
  upload_port="$HTTPS_ENDPOINT_PORT"
  upload_path="$HTTPS_ENDPOINT_PATH"

  if [[ "$remote_host" == "github.com" ]]; then
    [[ "$remote_port" == "443" ]] \
      || die "Public GitHub release remotes must use the default HTTPS API port"
    [[ "$api_host" == "api.github.com" && "$api_port" == "443" \
        && ( -z "$api_path" || "$api_path" == "/" ) ]] \
      || die "GH_API for github.com must use only https://api.github.com"
    [[ "$upload_host" == "uploads.github.com" && "$upload_port" == "443" \
        && ( -z "$upload_path" || "$upload_path" == "/" ) ]] \
      || die "GH_UPLOAD for github.com must use only https://uploads.github.com"
    GH_API="https://api.github.com"
    GH_UPLOAD="https://uploads.github.com"
  else
    [[ "$api_host" == "$remote_host" \
        && ( "$api_path" == "/api/v3" || "$api_path" == "/api/v3/" ) ]] \
      || die "GH_API must use the GH_REMOTE host with the /api/v3 path"
    [[ "$upload_host" == "$remote_host" \
        && ( "$upload_path" == "/api/uploads" || "$upload_path" == "/api/uploads/" ) ]] \
      || die "GH_UPLOAD must use the GH_REMOTE host with the /api/uploads path"
    if [[ "$transport" == "https" ]]; then
      [[ "$api_port" == "$remote_port" && "$upload_port" == "$remote_port" ]] \
        || die "GH_API and GH_UPLOAD must use the HTTPS GH_REMOTE port"
    else
      [[ "$api_port" == "$upload_port" ]] \
        || die "Explicit SSH-remote GH_API and GH_UPLOAD endpoints must use the same HTTPS port"
    fi
    api_authority="$api_host"
    upload_authority="$upload_host"
    [[ "$api_port" == "443" ]] || api_authority+=":${api_port}"
    [[ "$upload_port" == "443" ]] || upload_authority+=":${upload_port}"
    GH_API="https://${api_authority}/api/v3"
    GH_UPLOAD="https://${upload_authority}/api/uploads"
  fi

  log "Releases: parsed host=${host} owner=${GH_OWNER} repo=${GH_REPO}"
}

AUTH_HEADER=()
HTTP_STATUS=""
HTTP_BODY_FILE=""

gh_auth_header() {
  AUTH_HEADER=()

  if [[ -n "$SYNC_AUTH_TOKEN" ]]; then
    local auth_header_file="${SYNC_RUNTIME_DIR}/curl-auth.header"
    if [[ "$SYNC_AUTH_TOKEN" == *$'\n'* ]] \
        || printf '%s' "$SYNC_AUTH_TOKEN" | LC_ALL=C grep -q '[[:cntrl:]]'; then
      die "SYNC_AUTH_TOKEN must not contain control characters"
    fi
    mkdir -p "$SYNC_RUNTIME_DIR"
    chmod 700 "$SYNC_RUNTIME_DIR"
    [[ ! -L "$auth_header_file" ]] || die "Refusing symlinked curl authorization file"
    printf 'Authorization: Bearer %s' "$SYNC_AUTH_TOKEN" > "$auth_header_file"
    chmod 600 "$auth_header_file"
    cleanup_add_file "$auth_header_file"
    AUTH_HEADER=(--header "@${auth_header_file}")
    if is_true "$SYNC_READ_ONLY"; then
      log "GitHub mode: authenticated read-only"
    else
      log "GitHub mode: read-write (token present)"
    fi
  else
    log "GitHub mode: read-only (no token)"
  fi
}

curl_bounded_file() {
  local max_bytes="$1"
  shift
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
  local file_blocks=$(( (max_bytes + 1023) / 1024 ))

  # Debian 12 ships curl 7.88, where --max-filesize is not a transfer-time
  # bound for chunked responses. RLIMIT_FSIZE stops file growth in the kernel;
  # callers also enforce the exact byte limit after curl returns.
  (
    ulimit -f "$file_blocks" || exit 1
    exec curl "$@"
  )
}

http_json() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local ctype="${4:-application/json}"

  # cleanup previous response file (if any)
  if [[ -n "${HTTP_BODY_FILE:-}" && -f "${HTTP_BODY_FILE:-}" ]]; then
    rm -f -- "${HTTP_BODY_FILE}" || true
  fi

  local tmpf
  tmpf="$(mktemp "${SYNC_RUNTIME_DIR}/http-json.XXXXXX")"
  cleanup_add_file "$tmpf"

  local code body_size
  if [[ -n "$data" ]]; then
    if ! code="$(
      curl_bounded_file 20000000 \
        -q --proto '=https' -sS --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" --max-filesize 20000000 -w '%{http_code}' \
        "${AUTH_HEADER[@]}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Content-Type: ${ctype}" \
        -X "$method" \
        --data "$data" \
        "$url" \
        -o "$tmpf"
    )"; then
      die "HTTP request failed: $method $url"
    fi
  else
    if ! code="$(
      curl_bounded_file 20000000 \
        -q --proto '=https' -sS --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" --max-filesize 20000000 -w '%{http_code}' \
        "${AUTH_HEADER[@]}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -X "$method" \
        "$url" \
        -o "$tmpf"
    )"; then
      die "HTTP request failed: $method $url"
    fi
  fi
  body_size="$(stat -c '%s' "$tmpf")" || die "Cannot inspect HTTP response size"
  (( body_size <= 20000000 )) || die "HTTP response exceeded the 20 MB safety limit"

  HTTP_STATUS="$code"
  HTTP_BODY_FILE="$tmpf"
}

gh_get_release_id_by_tag() {
  local encoded_tag url
  encoded_tag="$(jq -rn --arg value "$GH_RELEASE_TAG" '$value|@uri')"
  url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encoded_tag}"

  http_json "GET" "$url"

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
  local allow_create="${1:-true}" id
  id="$(gh_get_release_id_by_tag)"

  if [[ -z "$id" ]]; then
    if [[ "$allow_create" == "true" && -n "$SYNC_AUTH_TOKEN" ]] \
        && ! is_true "$SYNC_READ_ONLY"; then
      log "Release '${GH_RELEASE_TAG}' not found -> creating"
      id="$(gh_create_release)"
    else
      log "Release not found; creation is disabled for this sync phase/mode"
      GH_REL_ID=""
      return 0
    fi
  fi

  GH_REL_ID="$id"
  [[ "$GH_REL_ID" =~ ^[1-9][0-9]*$ ]] || die "GitHub returned an invalid release id"
  log "Using release id=$GH_REL_ID tag=${GH_RELEASE_TAG}"
}

gh_list_assets() {
  local page=1 page_count url all='[]'
  while (( page <= 11 )); do
    url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?per_page=100&page=${page}"
    http_json "GET" "$url"
    [[ "$HTTP_STATUS" == "200" ]] || die "GET $url failed (HTTP $HTTP_STATUS)"
    jq -e 'type == "array" and length <= 100' < "$HTTP_BODY_FILE" >/dev/null \
      || die "GET $url returned an invalid release asset page"
    page_count="$(jq 'length' < "$HTTP_BODY_FILE")"
    if (( page == 11 )); then
      (( page_count == 0 )) \
        || die "Release asset listing exceeds the 1000-asset safety limit"
      break
    fi
    all="$(jq -s '.[0] + .[1]' <(printf '%s' "$all") "$HTTP_BODY_FILE")"
    (( page_count < 100 )) && break
    ((page++))
  done
  printf '%s\n' "$all"
}

gh_delete_asset_id() {
  local id="$1"
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || die "Invalid release asset id"
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"

  http_json "DELETE" "$url"

  [[ "$HTTP_STATUS" =~ ^20[04]$ ]] || die "DELETE asset $id failed (HTTP $HTTP_STATUS)"
  log "Deleted asset id=$id"
}

gh_upload_asset() {
  local file="$1"
  local name encoded_name
  name="$(basename "$file")"
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$name" != *".."* ]] \
    || die "Unsafe release asset name: '$name'"
  encoded_name="$(jq -rn --arg value "$name" '$value|@uri')"

  local url="${GH_UPLOAD}/repos/${GH_OWNER}/${GH_REPO}/releases/${GH_REL_ID}/assets?name=${encoded_name}"

  local code
  if ! code="$(
    curl -q --proto '=https' -sS --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" -w '%{http_code}' \
      "${AUTH_HEADER[@]}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Content-Type: application/octet-stream" \
      --data-binary @"$file" \
      "$url" \
      -o /dev/null
  )"; then
    log "ERROR: UPLOAD ${name} failed (network error)"
    return 1
  fi

  if [[ ! "$code" =~ ^2[0-9][0-9]$ ]]; then
    log "ERROR: UPLOAD ${name} failed (HTTP ${code})"
    return 1
  fi
  log "Uploaded asset ${name}"
}

gh_download_asset_id_to() {
  local name="$1"
  local id="$2"
  local remote_size="$3"
  local out="$4"
  local max_bytes="${5:-$((SYNC_MAX_RESTORE_MB * 1000000))}"
  local api_hop_limit="$max_bytes"

  [[ -n "$GH_REL_ID" ]] || return 1
  [[ ! -L "$out" ]] || return 1
  [[ "$name" == "$RELEASE_ASSET_PREFIX"* \
      && "$name" =~ ^[A-Za-z0-9._-]+$ && "$name" != *".."* ]] || return 1
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$remote_size" =~ ^[0-9]{1,15}$ ]] || return 1
  (( remote_size >= 1 && remote_size <= max_bytes )) || return 1
  (( api_hop_limit >= 1000000 )) || api_hop_limit=1000000

  local actual_size
  local url="${GH_API}/repos/${GH_OWNER}/${GH_REPO}/releases/assets/${id}"
  local code redirect_code location headers response_body download_tmp
  headers="$(mktemp "${SYNC_RUNTIME_DIR}/asset-headers.XXXXXX")"
  response_body="$(mktemp "${SYNC_RUNTIME_DIR}/asset-api-body.XXXXXX")"
  download_tmp="$(mktemp "${SYNC_RUNTIME_DIR}/asset-download.XXXXXX")"
  cleanup_add_file "$headers"
  cleanup_add_file "$response_body"
  cleanup_add_file "$download_tmp"
  chmod 600 "$headers" "$response_body" "$download_tmp"

  # Never forward the API Authorization header across a redirect. The API hop
  # is authenticated and redirect-free; any returned HTTPS storage URL is then
  # downloaded by a separate curl invocation without AUTH_HEADER.
  if ! code="$(
    curl_bounded_file "$api_hop_limit" \
      -q --proto '=https' -sS --connect-timeout 15 \
      --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" --max-filesize "$max_bytes" \
      -D "$headers" -w '%{http_code}' \
      "${AUTH_HEADER[@]}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "Accept: application/octet-stream" \
      -o "$response_body" \
      "$url"
  )"; then
    rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
    return 1
  fi
  actual_size="$(stat -c '%s' "$response_body")" || return 1
  (( actual_size <= max_bytes )) || {
    rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
    return 1
  }

  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
    mv -f -- "$response_body" "$download_tmp" || return 1
  elif [[ "$code" =~ ^3[0-9][0-9]$ ]]; then
    location="$(python3 - "$headers" <<'PY'
import sys
from urllib.parse import urlsplit

raw = open(sys.argv[1], "rb").read().splitlines()
locations = []
for line in raw:
    if line.lower().startswith(b"location:"):
        value = line.split(b":", 1)[1].strip()
        if not value or any(byte < 0x20 or byte == 0x7F for byte in value):
            raise SystemExit(2)
        locations.append(value.decode("ascii", "strict"))
if not locations:
    raise SystemExit(2)
value = locations[-1]
parsed = urlsplit(value)
if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
    raise SystemExit(2)
try:
    parsed.port
except ValueError:
    raise SystemExit(2)
if parsed.fragment:
    raise SystemExit(2)
print(value)
PY
    )" || {
      rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
      return 1
    }
    if ! redirect_code="$(
      curl_bounded_file "$max_bytes" \
        -q --proto '=https' --proto-redir '=https' -L --max-redirs 5 -sS \
        --connect-timeout 15 --max-time "$SYNC_NETWORK_TIMEOUT_SECONDS" \
        --max-filesize "$max_bytes" -w '%{http_code}' \
        -o "$download_tmp" "$location"
    )"; then
      rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
      return 1
    fi
    [[ "$redirect_code" =~ ^2[0-9][0-9]$ ]] || {
      log "WARN: DOWNLOAD ${name} storage request failed (HTTP ${redirect_code})"
      rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
      return 1
    }
  else
    log "WARN: DOWNLOAD ${name} failed (HTTP ${code})"
    rm -f -- "$headers" "$response_body" "$download_tmp" "$out"
    return 1
  fi
  rm -f -- "$headers" "$response_body"
  actual_size="$(stat -c '%s' "$download_tmp")"
  if [[ "$actual_size" != "$remote_size" || "$actual_size" -gt "$max_bytes" ]]; then
    rm -f -- "$download_tmp" "$out"
    return 1
  fi
  [[ ! -L "$out" ]] || {
    rm -f -- "$download_tmp"
    return 1
  }
  if ! mv -f -- "$download_tmp" "$out"; then
    rm -f -- "$out"
    return 1
  fi
  log "Downloaded asset ${name} -> ${out}"
}

declare -a RELEASE_VALIDATED_MANIFESTS=()
declare -A RELEASE_VALIDATED_ASSET_IDS=()
declare -A RELEASE_VALIDATED_ASSET_SIZES=()
declare -A RELEASE_VALIDATED_MANIFEST_FILES=()
RELEASE_VALIDATED_REGISTRY_DIGEST=""
RELEASE_VALIDATED_NAMESPACE_DIGEST=""

release_current_registry_from_assets() {
  local assets="$1" current
  current="$(jq -ce --arg prefix "$RELEASE_ASSET_PREFIX" '
    [.[] | select(((.name | type) == "string") and (.name | startswith($prefix)))]
  ' <<<"$assets")" || return 1
  jq -e --arg prefix "$RELEASE_ASSET_PREFIX" '
    type == "array"
    and length <= 1000
    and ((map(.name) | unique | length) == length)
    and all(.[];
      type == "object"
      and ((.name | type) == "string")
      and (.name | startswith($prefix))
      and (.name | test("^[A-Za-z0-9._-]+$"))
      and ((.name | contains("..")) | not)
      and ((.id | type) == "number")
      and (.id >= 1 and .id <= 9007199254740991 and (.id | floor) == .id)
      and ((.size | type) == "number")
      and (.size >= 1 and .size <= 49000000 and (.size | floor) == .size)
      and (((.name | endswith("--manifest.json")) | not) or (.size <= 1000000))
      and ((.created_at | type) == "string")
      and (.created_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
    )
  ' <<<"$current" >/dev/null || return 1
  printf '%s\n' "$current"
}

release_registry_digest() {
  jq -cS 'sort_by(.name) | map({created_at,id,name,size})' \
    | sha256sum | awk '{print $1}'
}

release_registry_matches_digest() {
  local expected_digest="$1" assets current_assets actual_digest
  [[ "$expected_digest" =~ ^[a-f0-9]{64}$ ]] || return 1
  assets="$(gh_list_assets)" || return 1
  current_assets="$(release_current_registry_from_assets "$assets")" || return 1
  actual_digest="$(release_registry_digest <<<"$current_assets")" || return 1
  [[ "$actual_digest" == "$expected_digest" ]]
}

release_chunk_generation_from_name() {
  local name="$1" part_suffix base archive_suffix generation
  ((${#name} > 11)) || return 1
  part_suffix="${name: -11}"
  [[ "$part_suffix" =~ ^\.part_[0-9]{5}$ ]] || return 1
  base="${name:0:${#name}-11}"
  archive_suffix="--${ARCHIVE_NAME}"
  [[ "$base" == "${RELEASE_ASSET_PREFIX}"*"${archive_suffix}" ]] || return 1
  generation="${base#"$RELEASE_ASSET_PREFIX"}"
  generation="${generation%"$archive_suffix"}"
  [[ "$base" == "${RELEASE_ASSET_PREFIX}${generation}${archive_suffix}" \
      && "$generation" =~ $RELEASE_GENERATION_REGEX ]] || return 1
  printf '%s\n' "$generation"
}

release_validate_namespace() {
  local assets assets_after current_assets current_assets_after registry_digest registry_digest_after
  local manifest_output manifest_asset manifest_file generation expected_manifest name artifact_generation
  local schema_type schema_version
  local manifest_hmac namespace_digest id size created_at
  local -a manifests=() namespace_auth_lines=()
  local tmp
  declare -A referenced=() completed_generations=()

  RELEASE_VALIDATED_MANIFESTS=()
  RELEASE_VALIDATED_ASSET_IDS=()
  RELEASE_VALIDATED_ASSET_SIZES=()
  RELEASE_VALIDATED_MANIFEST_FILES=()
  RELEASE_VALIDATED_REGISTRY_DIGEST=""
  RELEASE_VALIDATED_NAMESPACE_DIGEST=""

  assets="$(gh_list_assets)"
  current_assets="$(release_current_registry_from_assets "$assets")" \
    || die "Lumina release registry contains duplicate names or invalid asset metadata"
  registry_digest="$(release_registry_digest <<<"$current_assets")"
  [[ "$registry_digest" =~ ^[a-f0-9]{64}$ ]] \
    || die "Failed to fingerprint the Lumina release asset registry"
  while IFS=$'\t' read -r name id size created_at; do
    [[ -n "$name" && "$id" =~ ^[1-9][0-9]*$ && "$size" =~ ^[1-9][0-9]*$ ]] \
      || die "Lumina release registry contains invalid normalized metadata"
    RELEASE_VALIDATED_ASSET_IDS["$name"]="$id"
    RELEASE_VALIDATED_ASSET_SIZES["$name"]="$size"
  done < <(jq -r 'sort_by(.name)[] | [.name, (.id | tostring), (.size | tostring), .created_at] | @tsv' <<<"$current_assets")

  manifest_output="$(release_manifest_names_from_assets "$current_assets")"
  [[ -z "$manifest_output" ]] || mapfile -t manifests <<< "$manifest_output"
  ((${#manifests[@]} <= 21)) \
    || die "Lumina release namespace exceeds the 21-generation safety limit"
  for manifest_asset in "${manifests[@]}"; do
    [[ "$manifest_asset" =~ ^[A-Za-z0-9._-]+$ && "$manifest_asset" != *".."* ]] \
      || die "Unsafe release manifest asset name: '$manifest_asset'"
    tmp="$(mktemp -d "${INSTALL_PATH}/_ghnamespace.XXXXXX")"
    cleanup_add_dir "$tmp"
    manifest_file="$tmp/manifest.json"
    [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]+x}" \
        && -n "${RELEASE_VALIDATED_ASSET_SIZES[$manifest_asset]+x}" ]] \
      || die "Release manifest '$manifest_asset' is missing exact registry metadata"
    gh_download_asset_id_to \
      "$manifest_asset" \
      "${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]}" \
      "${RELEASE_VALIDATED_ASSET_SIZES[$manifest_asset]}" \
      "$manifest_file" 1000000 \
      || die "Cannot read release manifest '$manifest_asset'"
    validate_current_manifest "$manifest_file" \
      || die "Release manifest '$manifest_asset' is not authentic current-v3 data"
    schema_type="$(jq -r '.schema_type' < "$manifest_file")"
    schema_version="$(jq -r '.schema_version' < "$manifest_file")"
    validate_snapshot_schema_compatibility "$schema_type" "$schema_version"
    generation="$(jq -r '.generation // empty' < "$manifest_file")"
    [[ "$generation" =~ $RELEASE_GENERATION_REGEX ]] \
      || die "Release manifest '$manifest_asset' does not use the current generation format"
    expected_manifest="${RELEASE_ASSET_PREFIX}${generation}--manifest.json"
    [[ "$manifest_asset" == "$expected_manifest" ]] \
      || die "Release manifest name/generation mismatch: '$manifest_asset'"
    manifest_hmac="$(jq -r '.manifest_hmac_sha256 // empty' < "$manifest_file")"
    [[ "$manifest_hmac" =~ ^[a-fA-F0-9]{64}$ ]] \
      || die "Release manifest '$manifest_asset' has invalid authentication metadata"
    namespace_auth_lines+=("${manifest_asset}:${manifest_hmac,,}")
    RELEASE_VALIDATED_MANIFEST_FILES["$manifest_asset"]="$manifest_file"
    completed_generations["$generation"]=1
    referenced["$manifest_asset"]=1
    while IFS= read -r name; do
      [[ "$name" == "${RELEASE_ASSET_PREFIX}${generation}--${ARCHIVE_NAME}.part_"* \
          && "$name" =~ \.part_[0-9]{5}$ ]] \
        || die "Release manifest '$manifest_asset' references a non-current chunk: '$name'"
      referenced["$name"]=1
    done < <(jq -r '.chunk_names[]' < "$manifest_file")
  done

  while IFS= read -r name; do
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$name" != *".."* ]] \
      || die "Unsafe artifact name in the Lumina release namespace: '$name'"
    [[ -z "${referenced[$name]+x}" ]] || continue
    if artifact_generation="$(release_chunk_generation_from_name "$name")"; then
      if [[ -n "${completed_generations[$artifact_generation]+x}" ]]; then
        die "Unreferenced artifact '$name' conflicts with completed generation '$artifact_generation'"
      fi
      # A writer may have uploaded chunks but not its manifest yet. Without an
      # authenticated manifest there is no safe ownership proof for deletion,
      # and readers must not treat that partial generation as a snapshot.
      continue
    fi
    die "Unsupported artifact '$name' conflicts with the current Lumina release namespace"
  done < <(jq -r '.[].name' <<<"$current_assets")

  # Ensure the registry used for authentication did not change while manifests
  # were downloaded and checked.
  assets_after="$(gh_list_assets)"
  current_assets_after="$(release_current_registry_from_assets "$assets_after")" \
    || die "Lumina release registry became invalid during validation"
  registry_digest_after="$(release_registry_digest <<<"$current_assets_after")"
  [[ "$registry_digest_after" == "$registry_digest" ]] \
    || die "Lumina release registry changed during validation"

  namespace_auth_lines+=("registry:${registry_digest}")
  namespace_digest="$({
    for name in "${namespace_auth_lines[@]}"; do
      printf '%s\0' "$name"
    done
  } | LC_ALL=C sort -z | sha256sum | awk '{print $1}')"
  [[ "$namespace_digest" =~ ^[a-f0-9]{64}$ ]] \
    || die "Failed to fingerprint the validated Lumina release namespace"
  RELEASE_VALIDATED_MANIFESTS=("${manifests[@]}")
  RELEASE_VALIDATED_REGISTRY_DIGEST="$registry_digest"
  RELEASE_VALIDATED_NAMESPACE_DIGEST="$namespace_digest"
}

RELEASE_PLAIN_ARCHIVE=""
RELEASE_SCHEMA_TYPE=""
RELEASE_SCHEMA_VERSION=""
RELEASE_SCHEMA_FINGERPRINT=""

release_fetch_candidate() {
  local manifest_asset="$1"
  local tmp="$2"
  local manifest="$tmp/manifest.json"
  local payload="$tmp/payload"
  local plain="$tmp/$PLAIN_ARCHIVE_NAME"
  local sha_remote sha_local hmac_remote size_remote size_local content_remote content_local
  local count name declared_chunk_mb remaining_bytes chunk_limit part_size generation id registered_size
  local expected_registry_digest="$RELEASE_VALIDATED_REGISTRY_DIGEST"
  local -a names=()

  [[ "$expected_registry_digest" =~ ^[a-f0-9]{64}$ \
      && -n "${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]+x}" \
      && -n "${RELEASE_VALIDATED_ASSET_SIZES[$manifest_asset]+x}" ]] || return 1
  gh_download_asset_id_to \
    "$manifest_asset" \
    "${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]}" \
    "${RELEASE_VALIDATED_ASSET_SIZES[$manifest_asset]}" \
    "$manifest" 1000000 || return 1
  validate_current_manifest "$manifest" || return 1
  sha_remote="$(jq -r '.archive_sha256 // empty' < "$manifest")"
  content_remote="$(jq -r '.content_sha256 // empty' < "$manifest")"
  [[ "$sha_remote" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  [[ "$content_remote" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  size_remote="$(jq -r '.archive_size_bytes // empty' < "$manifest")"
  declared_chunk_mb="$(jq -r '.chunk_size_mb // empty' < "$manifest")"
  [[ "$size_remote" =~ ^[0-9]{1,15}$ ]] || return 1
  size_remote=$((10#$size_remote))
  (( size_remote >= 1 && size_remote <= SYNC_MAX_RESTORE_MB * 1000000 )) || return 1
  [[ "$declared_chunk_mb" =~ ^[0-9]{1,2}$ ]] || return 1
  declared_chunk_mb=$((10#$declared_chunk_mb))
  (( declared_chunk_mb >= 1 && declared_chunk_mb <= 49 )) || return 1
  remaining_bytes="$size_remote"

  mapfile -t names < <(jq -r '.chunk_names[]? // empty' < "$manifest")
  count="$(jq -r '.chunk_count // empty' < "$manifest")"
  [[ "$count" =~ ^[0-9]{1,5}$ ]] || return 1
  count=$((10#$count))
  (( count == ${#names[@]} )) || return 1
  ((${#names[@]} >= 1 && ${#names[@]} <= 10000)) || return 1
  generation="$(jq -r '.generation // empty' < "$manifest")"
  [[ "$manifest_asset" == "${RELEASE_ASSET_PREFIX}${generation}--manifest.json" ]] || return 1

  : > "$payload"
  for name in "${names[@]}"; do
    [[ "$name" == "${RELEASE_ASSET_PREFIX}${generation}--${ARCHIVE_NAME}.part_"* \
        && "$name" =~ \.part_[0-9]{5}$ ]] || return 1
    chunk_limit=$((declared_chunk_mb * 1000000))
    (( remaining_bytes < chunk_limit )) && chunk_limit="$remaining_bytes"
    (( chunk_limit >= 1 )) || return 1
    [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$name]+x}" \
        && -n "${RELEASE_VALIDATED_ASSET_SIZES[$name]+x}" ]] || return 1
    id="${RELEASE_VALIDATED_ASSET_IDS[$name]}"
    registered_size="${RELEASE_VALIDATED_ASSET_SIZES[$name]}"
    (( registered_size >= 1 && registered_size <= chunk_limit )) || return 1
    gh_download_asset_id_to "$name" "$id" "$registered_size" "$tmp/$name" "$chunk_limit" \
      || return 1
    part_size="$(stat -c '%s' "$tmp/$name")"
    remaining_bytes=$((remaining_bytes - part_size))
    cat -- "$tmp/$name" >> "$payload"
  done
  (( remaining_bytes == 0 )) || return 1

  sha_local="$(sha256sum "$payload" | awk '{print $1}')"
  [[ "$sha_local" == "$sha_remote" ]] || return 1
  size_local="$(stat -c '%s' "$payload")"
  [[ "$size_local" == "$size_remote" ]] || return 1
  hmac_remote="$(jq -r '.archive_hmac_sha256' < "$manifest")"
  verify_archive_hmac "$payload" "$hmac_remote" || return 1

  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] || {
    log "Encrypted release snapshot requires SYNC_ENCRYPTION_PASSPHRASE"
    return 1
  }
  if ! gpg_decrypt_bounded "$payload" "$plain"; then
    rm -f -- "$plain"
    return 1
  fi

  content_local="$(sha256sum "$plain" | awk '{print $1}')"
  [[ "$content_local" == "$content_remote" ]] || return 1
  RELEASE_PLAIN_ARCHIVE="$plain"
  RELEASE_SCHEMA_TYPE="$(jq -r '.schema_type' < "$manifest")"
  RELEASE_SCHEMA_VERSION="$(jq -r '.schema_version' < "$manifest")"
  RELEASE_SCHEMA_FINGERPRINT="$(jq -r '.schema_fingerprint_sha256' < "$manifest")"
  validate_snapshot_schema_compatibility "$RELEASE_SCHEMA_TYPE" "$RELEASE_SCHEMA_VERSION"
  release_registry_matches_digest "$expected_registry_digest" || return 2
  return 0
}

release_restore_phase() {
  if ! is_true "$SYNC_FORCE_RESTORE" && ! db_is_empty; then
    log "Local DB is non-empty -> release restore skipped"
    return 0
  fi
  release_validate_namespace

  local -a candidates=("${RELEASE_VALIDATED_MANIFESTS[@]}")
  if ((${#candidates[@]} == 0)); then
    if is_true "$SYNC_FORCE_RESTORE"; then
      die "SYNC_FORCE_RESTORE=true was requested, but no release snapshot exists"
    fi
    log "No release snapshot found -> keep local DB"
    return 0
  fi

  local candidate tmp fetch_status
  for candidate in "${candidates[@]}"; do
    tmp="$(mktemp -d "${INSTALL_PATH}/_ghrestore.XXXXXX")"
    cleanup_add_dir "$tmp"
    log "Trying release snapshot '$candidate'"
    if release_fetch_candidate "$candidate" "$tmp"; then
      RESTORED_SCHEMA_TYPE="$RELEASE_SCHEMA_TYPE"
      RESTORED_SCHEMA_VERSION="$RELEASE_SCHEMA_VERSION"
      RESTORED_SCHEMA_FINGERPRINT="$RELEASE_SCHEMA_FINGERPRINT"
      import_plain_archive "$RELEASE_PLAIN_ARCHIVE" "$RELEASE_SCHEMA_FINGERPRINT"
      log "Release DB restore completed from '$candidate'"
      return 0
    else
      fetch_status=$?
      (( fetch_status != 2 )) \
        || die "Release registry changed while a restore candidate was being verified"
    fi
    log "WARN: release snapshot '$candidate' is incomplete or invalid; trying the previous generation"
  done
  die "No complete, authentic release snapshot could be restored"
}

release_manifest_names_from_assets() {
  local assets="$1"
  jq -r --arg prefix "$RELEASE_ASSET_PREFIX" '
    [.[] | select((.name | startswith($prefix)) and (.name | endswith("--manifest.json")))]
    | sort_by(.created_at, .id) | reverse | .[].name
  ' <<<"$assets"
}

release_delete_generation() {
  local manifest_asset="$1" protected_manifest="${2:-}" manifest_file manifest_id name generation id verify_tmp
  local -a chunk_names=()
  [[ "$manifest_asset" == "${RELEASE_ASSET_PREFIX}"* && "$manifest_asset" =~ ^[A-Za-z0-9._-]+$ \
      && "$manifest_asset" != *".."* ]] \
    || die "Unsafe generation manifest name: '$manifest_asset'"
  [[ -z "$protected_manifest" || "$manifest_asset" != "$protected_manifest" ]] \
    || die "Refusing to delete the pinned complete release generation"

  release_validate_namespace
  [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]+x}" \
      && -n "${RELEASE_VALIDATED_MANIFEST_FILES[$manifest_asset]+x}" ]] \
    || die "Generation '$manifest_asset' is not present in the authenticated release registry"
  if [[ -n "$protected_manifest" ]]; then
    [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$protected_manifest]+x}" ]] \
      || die "Pinned complete release generation disappeared before cleanup"
    verify_tmp="$(mktemp -d "${INSTALL_PATH}/_ghpinverify.XXXXXX")"
    cleanup_add_dir "$verify_tmp"
    if ! (release_fetch_candidate "$protected_manifest" "$verify_tmp"); then
      die "Pinned release generation is no longer fully verifiable; refusing cleanup"
    fi
  fi

  manifest_file="${RELEASE_VALIDATED_MANIFEST_FILES[$manifest_asset]}"
  validate_current_manifest "$manifest_file" \
    || die "Refusing to clean a generation that is not authentic current-v3 data"
  generation="$(jq -r '.generation // empty' < "$manifest_file")"
  [[ "$manifest_asset" == "${RELEASE_ASSET_PREFIX}${generation}--manifest.json" ]] \
    || die "Refusing to clean a generation with mismatched metadata"
  mapfile -t chunk_names < <(jq -r '.chunk_names[]' < "$manifest_file")
  for name in "${chunk_names[@]}"; do
    [[ "$name" == "${RELEASE_ASSET_PREFIX}${generation}--${ARCHIVE_NAME}.part_"* \
        && "$name" =~ \.part_[0-9]{5}$ ]] \
      || die "Unsafe chunk name while cleaning '$manifest_asset'"
  done

  # Hide the generation from new readers before removing only the exact asset
  # IDs declared by its authenticated manifest and the validated unique registry.
  manifest_id="${RELEASE_VALIDATED_ASSET_IDS[$manifest_asset]}"
  gh_delete_asset_id "$manifest_id"
  for name in "${chunk_names[@]}"; do
    if [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$name]+x}" ]]; then
      id="${RELEASE_VALIDATED_ASSET_IDS[$name]}"
      gh_delete_asset_id "$id"
    fi
  done
}

release_cleanup_old_generations() {
  local -a manifests=()
  local protected_manifest="${1:-}" index
  release_validate_namespace
  manifests=("${RELEASE_VALIDATED_MANIFESTS[@]}")
  [[ -n "$protected_manifest" ]] || protected_manifest="${manifests[0]:-}"

  ((${#manifests[@]} > SYNC_RELEASE_KEEP)) || return 0
  for ((index=SYNC_RELEASE_KEEP; index<${#manifests[@]}; index++)); do
    [[ "${manifests[$index]}" == "$protected_manifest" ]] && continue
    release_delete_generation "${manifests[$index]}" "$protected_manifest"
  done
}

release_preflight_asset_capacity() {
  local needed="$1" assets asset_count stale_manifest pinned_manifest="" candidate verify_tmp index fetch_status
  local -a completed_manifests=()
  (( needed >= 2 && needed <= 1000 )) || die "Invalid release asset count for new generation"

  # A previous writer may have committed its manifest and crashed before
  # retention. Re-authenticate the registry and retire only its oldest complete
  # generations, preserving at least one complete recovery point. Manifest-first
  # deletion makes an interrupted cleanup invisible to readers; orphan chunks
  # are never inferred, wildcarded, or garbage-collected.
  while true; do
    release_validate_namespace
    completed_manifests=("${RELEASE_VALIDATED_MANIFESTS[@]}")
    assets="$(gh_list_assets)"
    asset_count="$(jq 'length' <<<"$assets")"
    [[ "$asset_count" =~ ^[0-9]{1,4}$ ]] \
      || die "Release asset count is invalid"
    (( asset_count + needed <= 1000 )) && return 0

    if [[ -z "$pinned_manifest" ]]; then
      for candidate in "${completed_manifests[@]}"; do
        verify_tmp="$(mktemp -d "${INSTALL_PATH}/_ghcapacityverify.XXXXXX")"
        cleanup_add_dir "$verify_tmp"
        if (release_fetch_candidate "$candidate" "$verify_tmp"); then
          pinned_manifest="$candidate"
          log "Release capacity recovery pinned fully verified generation '$pinned_manifest'"
          break
        else
          fetch_status=$?
          (( fetch_status != 2 )) \
            || die "Release registry changed during capacity recovery verification"
        fi
      done
      [[ -n "$pinned_manifest" ]] \
        || die "Release is full and has no fully verified generation; refusing any remote mutation"
    fi
    [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$pinned_manifest]+x}" ]] \
      || die "Pinned complete release generation disappeared; refusing cleanup"

    stale_manifest=""
    for ((index=${#completed_manifests[@]}-1; index>=0; index--)); do
      candidate="${completed_manifests[$index]}"
      if [[ "$candidate" != "$pinned_manifest" ]]; then
        stale_manifest="$candidate"
        break
      fi
    done
    [[ -n "$stale_manifest" ]] \
      || die "Release needs $needed free asset slots, but no stale authenticated generation can be removed safely"
    log "Release capacity recovery: retiring stale authenticated generation '$stale_manifest'"
    release_delete_generation "$stale_manifest" "$pinned_manifest"
  done
}

release_uploaded_chunks_match_local() {
  local source_dir="$1" assets current_assets registry_digest name id remote_size local_size downloaded created_at
  declare -A asset_ids=() asset_sizes=()

  assets="$(gh_list_assets)" || return 1
  current_assets="$(release_current_registry_from_assets "$assets")" || return 1
  registry_digest="$(release_registry_digest <<<"$current_assets")" || return 1
  [[ "$registry_digest" =~ ^[a-f0-9]{64}$ ]] || return 1
  while IFS=$'\t' read -r name id remote_size created_at; do
    [[ -n "$name" && "$id" =~ ^[1-9][0-9]*$ && "$remote_size" =~ ^[1-9][0-9]*$ ]] \
      || return 1
    asset_ids["$name"]="$id"
    asset_sizes["$name"]="$remote_size"
  done < <(jq -r 'sort_by(.name)[] | [.name, (.id | tostring), (.size | tostring), .created_at] | @tsv' <<<"$current_assets")

  for name in "${PACK_CHUNK_NAMES[@]}"; do
    [[ -n "${asset_ids[$name]+x}" && -n "${asset_sizes[$name]+x}" ]] || return 1
    id="${asset_ids[$name]}"
    remote_size="${asset_sizes[$name]}"
    local_size="$(stat -c '%s' "$source_dir/$name")" || return 1
    [[ "$remote_size" == "$local_size" ]] || return 1
    downloaded="$(mktemp "${SYNC_RUNTIME_DIR}/asset-verify.XXXXXX")"
    cleanup_add_file "$downloaded"
    gh_download_asset_id_to "$name" "$id" "$remote_size" "$downloaded" "$local_size" \
      || return 1
    cmp -s -- "$source_dir/$name" "$downloaded" || return 1
  done
  release_registry_matches_digest "$registry_digest"
}

release_asset_matches_file() {
  local name="$1" file="$2" assets current_assets registry_digest asset id remote_size local_size downloaded
  if ! assets="$(gh_list_assets)"; then return 1; fi
  current_assets="$(release_current_registry_from_assets "$assets")" || return 1
  registry_digest="$(release_registry_digest <<<"$current_assets")" || return 1
  asset="$(jq -ce --arg name "$name" '
    [.[] | select(.name == $name)] | if length == 1 then .[0] else empty end
  ' <<<"$current_assets")" || return 1
  [[ -n "$asset" ]] || return 1
  id="$(jq -r '.id' <<<"$asset")" || return 1
  remote_size="$(jq -r '.size' <<<"$asset")" || return 1
  local_size="$(stat -c '%s' "$file")"
  [[ "$remote_size" =~ ^[0-9]{1,15}$ && "$remote_size" == "$local_size" ]] || return 1
  downloaded="$(mktemp "${SYNC_RUNTIME_DIR}/asset-verify.XXXXXX")"
  cleanup_add_file "$downloaded"
  gh_download_asset_id_to "$name" "$id" "$remote_size" "$downloaded" "$local_size" || return 1
  cmp -s -- "$file" "$downloaded" || return 1
  release_registry_matches_digest "$registry_digest"
}

release_delete_asset_names() {
  local name assets current_assets id size created_at
  declare -A asset_ids=()
  ((${#@} > 0)) || return 0
  assets="$(gh_list_assets)" || return 1
  current_assets="$(release_current_registry_from_assets "$assets")" || return 1
  while IFS=$'\t' read -r name id size created_at; do
    [[ -n "$name" && "$id" =~ ^[1-9][0-9]*$ ]] || return 1
    asset_ids["$name"]="$id"
  done < <(jq -r 'sort_by(.name)[] | [.name, (.id | tostring), (.size | tostring), .created_at] | @tsv' <<<"$current_assets")
  for name in "$@"; do
    [[ -n "${asset_ids[$name]+x}" ]] || continue
    if ! (gh_delete_asset_id "${asset_ids[$name]}"); then
      log "WARN: failed to clean partial release asset '$name'"
    fi
  done
}

release_publish_phase() {
  if is_true "$SYNC_READ_ONLY"; then
    log "SYNC_READ_ONLY=true: releases publish skipped"
    return 0
  fi
  [[ -n "$SYNC_AUTH_TOKEN" ]] || { log "Read-only releases sync: publish skipped"; return 0; }
  [[ -n "$SYNC_ENCRYPTION_PASSPHRASE" ]] \
    || die "SYNC_ENCRYPTION_PASSPHRASE is required for write-sync"

  release_validate_namespace
  ensure_publishable_database
  pack_payload
  # Packing can be long-running. Refresh and fully authenticate a single asset
  # snapshot after it finishes, then pin that completed-manifest namespace until
  # the first remote mutation.
  release_validate_namespace

  local -a candidates=("${RELEASE_VALIDATED_MANIFESTS[@]}")
  local latest_manifest_tmp latest_candidate remote_content=""
  local validated_namespace_digest="$RELEASE_VALIDATED_NAMESPACE_DIGEST"
  if ((${#candidates[@]} > 0)); then
    latest_candidate="${candidates[0]}"
    latest_manifest_tmp="$(mktemp "${SYNC_RUNTIME_DIR}/latest-manifest.XXXXXX")"
    cleanup_add_file "$latest_manifest_tmp"
    [[ -n "${RELEASE_VALIDATED_ASSET_IDS[$latest_candidate]+x}" \
        && -n "${RELEASE_VALIDATED_ASSET_SIZES[$latest_candidate]+x}" ]] \
      || die "Advertised latest release manifest lacks exact registry metadata"
    gh_download_asset_id_to \
      "$latest_candidate" \
      "${RELEASE_VALIDATED_ASSET_IDS[$latest_candidate]}" \
      "${RELEASE_VALIDATED_ASSET_SIZES[$latest_candidate]}" \
      "$latest_manifest_tmp" 1000000 \
      || die "Advertised latest release manifest disappeared or could not be downloaded; refusing publish"
    validate_current_manifest "$latest_manifest_tmp" \
      || die "Latest release manifest changed or failed authentication during publish"
    remote_content="$(jq -r '.content_sha256 // empty' < "$latest_manifest_tmp")"
  fi
  if [[ -n "$remote_content" && "$remote_content" == "$PACK_CONTENT_SHA" ]]; then
    local verify_tmp fetch_status
    verify_tmp="$(mktemp -d "${INSTALL_PATH}/_ghverify.XXXXXX")"
    cleanup_add_dir "$verify_tmp"
    if release_fetch_candidate "${candidates[0]}" "$verify_tmp"; then
      log "DB matches latest release snapshot; download, hash, HMAC, and archive verification passed -> nothing to upload"
      return 0
    else
      fetch_status=$?
      (( fetch_status != 2 )) \
        || die "Release registry changed while the latest snapshot was being verified"
    fi
    log "Release content hash matches but referenced assets are incomplete/invalid -> republishing"
  fi

  local tmp generation prefix manifest_path bs part
  local -a uploaded_names=()
  tmp="$(mktemp -d "${INSTALL_PATH}/_ghpublish.XXXXXX")"
  cleanup_add_dir "$tmp"
  generation="$(date -u +'%Y%m%dT%H%M%SZ')-${PACK_CONTENT_SHA:0:12}-$(openssl rand -hex 16)"
  prefix="${RELEASE_ASSET_PREFIX}${generation}--${ARCHIVE_NAME}.part_"
  bs=$(( SYNC_CHUNK_SIZE_MB * 1000000 ))
  local expected_chunks=$(( (PACK_SIZE + bs - 1) / bs ))
  (( expected_chunks >= 1 && expected_chunks <= 999 )) \
    || die "Release snapshot would require ${expected_chunks} chunks; GitHub leaves at most 999 chunk slots plus one manifest"
  split -b "$bs" -d -a 5 "$ARCHIVE_PATH" "$tmp/$prefix"
  PACK_CHUNK_NAMES=()
  for part in "$tmp/$prefix"*; do
    PACK_CHUNK_NAMES+=("$(basename "$part")")
  done
  ((${#PACK_CHUNK_NAMES[@]} > 0)) || die "Snapshot split produced no release chunks"
  manifest_path="$tmp/${RELEASE_ASSET_PREFIX}${generation}--manifest.json"
  write_manifest "$manifest_path" "$(now_utc)" "$generation"
  release_validate_namespace
  [[ "$RELEASE_VALIDATED_NAMESPACE_DIGEST" == "$validated_namespace_digest" ]] \
    || die "Completed release namespace changed during local preparation; refusing publish"
  release_preflight_asset_capacity "$(( ${#PACK_CHUNK_NAMES[@]} + 1 ))"

  # Generation chunks first, generation manifest last. Readers only consider
  # complete manifests, so an interrupted upload leaves the previous snapshot valid.
  for part in "${PACK_CHUNK_NAMES[@]}"; do
    if gh_upload_asset "$tmp/$part"; then
      uploaded_names+=("$part")
    elif release_asset_matches_file "$part" "$tmp/$part"; then
      log "Upload response for '$part' was lost, but the remote asset verifies"
      uploaded_names+=("$part")
    else
      release_delete_asset_names "$part" "${uploaded_names[@]}"
      die "Release chunk upload failed; partial generation was cleaned up"
    fi
  done
  if ! release_uploaded_chunks_match_local "$tmp"; then
    release_delete_asset_names "${uploaded_names[@]}"
    die "Uploaded release chunks failed name/size verification; partial generation was cleaned up"
  fi
  if gh_upload_asset "$manifest_path"; then
    if ! release_asset_matches_file "$(basename "$manifest_path")" "$manifest_path"; then
      release_delete_asset_names "$(basename "$manifest_path")" "${uploaded_names[@]}"
      die "Uploaded release manifest failed verification; partial generation was cleaned up"
    fi
  else
    if release_asset_matches_file "$(basename "$manifest_path")" "$manifest_path"; then
      log "Manifest upload response was lost, but the remote manifest verifies"
    else
      release_delete_asset_names "$(basename "$manifest_path")" "${uploaded_names[@]}"
      die "Release manifest upload failed; unpublished generation chunks were cleaned up"
    fi
  fi
  log "Published atomic encrypted release generation '$generation'"
  release_validate_namespace
  release_cleanup_old_generations "$(basename "$manifest_path")"
}

perform_releases_sync() {
  local phase="${1:-publish}"
  ensure_tools_releases
  wait_for_db
  [[ -n "$GH_REMOTE" ]] || die "GH_REMOTE is required for releases mode"
  parse_gh_remote
  gh_auth_header
  if [[ "$phase" == "publish" ]]; then
    gh_ensure_release true
  else
    gh_ensure_release false
  fi
  if [[ -z "$GH_REL_ID" ]]; then
    if [[ "$phase" == "restore" ]] && is_true "$SYNC_FORCE_RESTORE"; then
      die "SYNC_FORCE_RESTORE=true was requested, but the configured release does not exist"
    fi
    log "No release id -> sync skipped"
    return 0
  fi
  case "$phase" in
    restore) release_restore_phase ;;
    publish) release_publish_phase ;;
    *) die "Unknown release sync phase '$phase'" ;;
  esac
}


################################################################
# Bootstrap & Launch
################################################################


write_managed_config() {
  local config_file="${CONFIG_PATH}/lumina.conf"
  if [[ -e "$config_file" || -L "$config_file" ]]; then
    [[ -f "$config_file" && ! -L "$config_file" ]] \
      || die "Lumina config path must be a regular non-symlink file"
  fi
  local value server port database user password vault_value tmp
  for value in "$MYSQL_HOST" "$MYSQL_PORT" "$MYSQL_DATABASE" "$MYSQL_USER" "$MYSQL_PASSWORD" "$VAULT_HOST" "$VAULT_PORT"; do
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
      || die "Config values must not contain newlines"
  done

  # Quote every connection-string component, double embedded quotes for the
  # connection-string parser, then escape for the outer Lumina config string.
  connection_quote() {
    local component="$1" escaped="" char i
    for ((i=0; i<${#component}; i++)); do
      char="${component:i:1}"
      case "$char" in
        '\') escaped+='\\' ;;
        '"') escaped+='\"\"' ;;
        *) escaped+="$char" ;;
      esac
    done
    printf '\\"%s\\"' "$escaped"
  }
  server="$(connection_quote "$MYSQL_HOST")"
  port="$(connection_quote "$MYSQL_PORT")"
  database="$(connection_quote "$MYSQL_DATABASE")"
  user="$(connection_quote "$MYSQL_USER")"
  password="$(connection_quote "$MYSQL_PASSWORD")"

  tmp="$(mktemp "${CONFIG_PATH}/.lumina.conf.XXXXXX")"
  cleanup_add_file "$tmp"
  printf 'CONNSTR="mysql;Server=%s;Port=%s;Database=%s;Uid=%s;Pwd=%s;"\n' \
    "$server" "$port" "$database" "$user" "$password" > "$tmp"
  if is_true "$VAULT_ENABLED"; then
    vault_value="${VAULT_HOST}:${VAULT_PORT}"
    vault_value="${vault_value//\\/\\\\}"
    vault_value="${vault_value//\"/\\\"}"
    printf 'VAULT_HOST="%s"\n' "$vault_value" >> "$tmp"
  fi
  chmod 640 "$tmp"
  chown root:lumina "$tmp"
  if [[ ! -f "$config_file" ]] || ! cmp -s "$tmp" "$config_file"; then
    sync -f "$tmp" || die "Failed to flush generated Lumina config"
    mv -f -- "$tmp" "$config_file"
    sync -f "$CONFIG_PATH" || die "Failed to persist generated Lumina config"
    log "Updated managed config $config_file"
  else
    rm -f -- "$tmp"
  fi
}

persist_recovery_copy() {
  local source="$1" destination="$2" label="$3" tmp
  [[ -f "$source" && ! -L "$source" ]] || die "$label source is missing or unsafe"
  [[ ! -e "$destination" && ! -L "$destination" ]] \
    || die "$label destination already exists"
  tmp="$(mktemp "${CONFIG_PATH}/.$(basename "$destination").XXXXXX")"
  cleanup_add_file "$tmp"
  cp -- "$source" "$tmp" || die "Failed to copy $label"
  chmod 600 "$tmp"
  chown root:root "$tmp"
  sync -f "$tmp" || die "Failed to flush $label"
  mv -- "$tmp" "$destination" || die "Failed to commit $label"
  sync -f "$CONFIG_PATH" || die "Failed to persist $label"
}

validate_recovery_file() {
  local file="$1" expected_size="$2" expected_sha="$3" max_bytes="$4" label="$5"
  local actual_size actual_sha
  [[ -f "$file" && ! -L "$file" ]] || {
    log "ERROR: $label is missing or unsafe"
    return 1
  }
  [[ "$expected_size" =~ ^[0-9]{1,15}$ && "$expected_sha" =~ ^[a-fA-F0-9]{64}$ ]] \
    || return 1
  actual_size="$(stat -c '%s' "$file")" || return 1
  [[ "$actual_size" == "$expected_size" ]] || {
    log "ERROR: $label size does not match its recovery marker"
    return 1
  }
  (( 10#$actual_size >= 1 && 10#$actual_size <= max_bytes )) || {
    log "ERROR: $label exceeds its recovery size limit"
    return 1
  }
  actual_sha="$(sha256sum "$file" | awk '{print $1}')" || return 1
  [[ "${actual_sha,,}" == "${expected_sha,,}" ]] || {
    log "ERROR: $label checksum does not match its recovery marker"
    return 1
  }
}

restore_recovery_schema_state() {
  local backup="$1" state_present="$2" expected_size="$3" expected_sha="$4"
  local tmp
  [[ ! -L "$SCHEMA_STATE" ]] || {
    log "ERROR: refusing to replace symlinked schema state"
    return 1
  }
  if [[ "$state_present" == "true" ]]; then
    validate_recovery_file "$backup" "$expected_size" "$expected_sha" 1000000 \
      "schema-state recovery backup" || return 1
    tmp="$(mktemp "${CONFIG_PATH}/.lumina_schema.state.restore.XXXXXX")" || return 1
    cleanup_add_file "$tmp"
    cp -- "$backup" "$tmp" || return 1
    chmod 640 "$tmp" || return 1
    chown root:lumina "$tmp" || return 1
    sync -f "$tmp" || return 1
    mv -f -- "$tmp" "$SCHEMA_STATE" || return 1
  else
    [[ ! -e "$backup" && ! -L "$backup" ]] || {
      log "ERROR: unexpected schema-state recovery artifact"
      return 1
    }
    rm -f -- "$SCHEMA_STATE" || return 1
  fi
  sync -f "$CONFIG_PATH" || return 1
}

verify_live_schema_against_recovery_marker() {
  local marker="$1" original_empty count expected_count fingerprint expected_fingerprint
  local state_present state_size state_sha current_state_size current_state_sha
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  original_empty="$(jq -r '.original_empty' < "$marker")" || return 1
  count="$(db_table_count)" || return 1
  if [[ "$original_empty" == "true" ]]; then
    (( count == 0 )) || return 1
    [[ ! -e "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] || return 1
    return 0
  fi
  expected_count="$(jq -r '.original_table_count' < "$marker")" || return 1
  expected_fingerprint="$(jq -r '.original_schema_fingerprint_sha256' < "$marker")" || return 1
  [[ "$expected_count" =~ ^[0-9]{1,15}$ && "$expected_fingerprint" =~ ^[a-fA-F0-9]{64}$ ]] \
    || return 1
  (( count == 10#$expected_count )) || return 1
  fingerprint="$(db_schema_fingerprint)" || return 1
  [[ "${fingerprint,,}" == "${expected_fingerprint,,}" ]] || return 1
  state_present="$(jq -r '.state_present' < "$marker")" || return 1
  if [[ "$state_present" == "true" ]]; then
    [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] || return 1
    state_size="$(jq -r '.state_size_bytes' < "$marker")" || return 1
    state_sha="$(jq -r '.state_sha256' < "$marker")" || return 1
    current_state_size="$(stat -c '%s' "$SCHEMA_STATE")" || return 1
    current_state_sha="$(sha256sum "$SCHEMA_STATE" | awk '{print $1}')" || return 1
    [[ "$current_state_size" == "$state_size" \
        && "${current_state_sha,,}" == "${state_sha,,}" ]] || return 1
  else
    [[ ! -e "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] || return 1
  fi
}

clear_remote_restore_recovery() {
  local artifact
  for artifact in "$RESTORE_RECOVERY_META" "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE"; do
    [[ ! -L "$artifact" ]] || return 1
  done
  # Removing the marker is the transaction commit point. Any later crash leaves
  # only harmless orphaned backups, which startup discards without touching DB.
  rm -f -- "$RESTORE_RECOVERY_META" || return 1
  sync -f "$CONFIG_PATH" || return 1
  rm -f -- "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE" || return 1
  sync -f "$CONFIG_PATH" || return 1
  RESTORE_RECOVERY_PENDING=0
}

prepare_remote_restore_recovery() {
  local artifact sql_tmp meta_tmp archive_sha archive_size original_count original_fingerprint
  local state_present=false state_sha="" state_size=0 expected_type current_count current_fingerprint
  for artifact in "$RESTORE_RECOVERY_META" "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE"; do
    [[ ! -e "$artifact" && ! -L "$artifact" ]] \
      || die "A remote-restore recovery artifact already exists; startup recovery must run first"
  done
  original_count="$(db_table_count)"
  (( original_count > 0 )) || die "Cannot create a non-empty restore rollback for an empty database"
  original_fingerprint="$(db_schema_fingerprint)"
  expected_type="$(desired_schema_type)"
  if [[ -e "$SCHEMA_STATE" || -L "$SCHEMA_STATE" ]]; then
    [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
      || die "Existing schema state is not a safe regular file"
    schema_state_matches_live "$expected_type" \
      || die "Existing schema state does not match the live database; refusing destructive restore"
    state_present=true
  fi

  sql_tmp="$(mktemp "${CONFIG_PATH}/.restore-recovery.sql.XXXXXX")"
  meta_tmp="$(mktemp "${CONFIG_PATH}/.restore-recovery.json.XXXXXX")"
  cleanup_add_file "$sql_tmp"
  cleanup_add_file "$meta_tmp"
  log "Creating durable rollback dump before destructive remote restore"
  if ! MYSQL_PWD="$MYSQL_PASSWORD" mariadb-dump --no-defaults \
      --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" \
      --single-transaction --quick --routines --events --triggers --hex-blob \
      --no-tablespaces --skip-dump-date \
      --databases "$MYSQL_DATABASE" > "$sql_tmp"; then
    rm -f -- "$sql_tmp" "$meta_tmp"
    die "Rollback dump failed; refusing destructive restore"
  fi
  [[ -s "$sql_tmp" ]] || die "Rollback dump is empty; refusing destructive restore"
  ensure_file_within_mb "$sql_tmp" "$SYNC_MAX_EXTRACT_MB" "Remote-restore rollback dump"
  archive_size="$(stat -c '%s' "$sql_tmp")"
  archive_sha="$(sha256sum "$sql_tmp" | awk '{print $1}')"
  chmod 600 "$sql_tmp"
  chown root:root "$sql_tmp"
  sync -f "$sql_tmp" || die "Failed to flush remote-restore rollback dump"
  mv -- "$sql_tmp" "$RESTORE_RECOVERY_SQL"
  sync -f "$CONFIG_PATH" || die "Failed to persist remote-restore rollback dump"

  if [[ "$state_present" == "true" ]]; then
    persist_recovery_copy "$SCHEMA_STATE" "$RESTORE_RECOVERY_STATE" \
      "remote-restore schema-state backup"
    state_size="$(stat -c '%s' "$RESTORE_RECOVERY_STATE")"
    state_sha="$(sha256sum "$RESTORE_RECOVERY_STATE" | awk '{print $1}')"
  fi

  current_count="$(db_table_count)"
  current_fingerprint="$(db_schema_fingerprint)"
  [[ "$current_count" == "$original_count" \
      && "${current_fingerprint,,}" == "${original_fingerprint,,}" ]] \
    || die "Live schema changed while the remote-restore rollback was being prepared"
  jq -n \
    --arg database "$MYSQL_DATABASE" \
    --arg created_utc "$(now_utc)" \
    --arg archive_sha256 "$archive_sha" \
    --arg original_schema_fingerprint_sha256 "$original_fingerprint" \
    --arg state_sha256 "$state_sha" \
    --argjson archive_size_bytes "$archive_size" \
    --argjson original_table_count "$original_count" \
    --argjson state_present "$state_present" \
    --argjson state_size_bytes "$state_size" \
    '{version:2,kind:"remote-restore",original_empty:false,database:$database,created_utc:$created_utc,
      archive_sha256:$archive_sha256,archive_size_bytes:$archive_size_bytes,
      original_table_count:$original_table_count,
      original_schema_fingerprint_sha256:$original_schema_fingerprint_sha256,
      state_present:$state_present,state_sha256:$state_sha256,state_size_bytes:$state_size_bytes}' \
    > "$meta_tmp"
  chmod 600 "$meta_tmp"
  chown root:root "$meta_tmp"
  sync -f "$meta_tmp" || die "Failed to flush remote-restore recovery metadata"
  mv -- "$meta_tmp" "$RESTORE_RECOVERY_META"
  sync -f "$CONFIG_PATH" || die "Failed to persist remote-restore recovery metadata"
  RESTORE_RECOVERY_PENDING=1
  verify_live_schema_against_recovery_marker "$RESTORE_RECOVERY_META" \
    || die "Live schema/state changed before destructive remote restore; rollback remains armed"
}

prepare_empty_restore_recovery() {
  local artifact meta_tmp count
  for artifact in "$RESTORE_RECOVERY_META" "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE"; do
    [[ ! -e "$artifact" && ! -L "$artifact" ]] \
      || die "A remote-restore recovery artifact already exists; startup recovery must run first"
  done
  count="$(db_table_count)"
  (( count == 0 )) || die "Cannot create an empty restore rollback for a non-empty database"
  [[ ! -e "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
    || die "An empty database has a stale/unsafe schema state; remove it explicitly before restore"
  meta_tmp="$(mktemp "${CONFIG_PATH}/.restore-recovery.json.XXXXXX")"
  cleanup_add_file "$meta_tmp"
  jq -n \
    --arg database "$MYSQL_DATABASE" \
    --arg created_utc "$(now_utc)" \
    '{version:2,kind:"remote-restore",original_empty:true,database:$database,created_utc:$created_utc,
      original_table_count:0,state_present:false,state_sha256:"",state_size_bytes:0}' \
    > "$meta_tmp"
  chmod 600 "$meta_tmp"
  chown root:root "$meta_tmp"
  sync -f "$meta_tmp" || die "Failed to flush empty-restore recovery metadata"
  mv -- "$meta_tmp" "$RESTORE_RECOVERY_META"
  sync -f "$CONFIG_PATH" || die "Failed to persist empty-restore recovery metadata"
  RESTORE_RECOVERY_PENDING=1
  verify_live_schema_against_recovery_marker "$RESTORE_RECOVERY_META" \
    || die "Empty restore target changed before destructive restore; rollback remains armed"
}

validate_remote_restore_recovery() {
  local database original_empty expected_sha expected_size state_present state_sha state_size
  [[ -f "$RESTORE_RECOVERY_META" && ! -L "$RESTORE_RECOVERY_META" ]] || {
    log "ERROR: remote-restore recovery metadata is missing or unsafe"
    return 1
  }
  jq -e '
    type == "object"
    and .version == 2
    and .kind == "remote-restore"
    and (.original_empty | type == "boolean")
    and (.database | type == "string")
    and (.state_present | type == "boolean")
    and (if .state_present then
      ((.state_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.state_size_bytes | type) == "number")
      and (.state_size_bytes >= 1) and ((.state_size_bytes | floor) == .state_size_bytes)
    else .state_sha256 == "" and .state_size_bytes == 0 end)
    and (if .original_empty then
      .original_table_count == 0 and (.state_present | not)
    else
      ((.archive_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.archive_size_bytes | type) == "number")
      and (.archive_size_bytes >= 1) and ((.archive_size_bytes | floor) == .archive_size_bytes)
      and ((.original_table_count | type) == "number") and (.original_table_count >= 1)
      and ((.original_table_count | floor) == .original_table_count)
      and ((.original_schema_fingerprint_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
    end)
  ' < "$RESTORE_RECOVERY_META" >/dev/null || {
    log "ERROR: invalid remote-restore recovery metadata"
    return 1
  }
  database="$(jq -r '.database' < "$RESTORE_RECOVERY_META")"
  [[ "$database" == "$MYSQL_DATABASE" ]] || {
    log "ERROR: remote-restore rollback targets database '$database', not '$MYSQL_DATABASE'"
    return 1
  }
  original_empty="$(jq -r '.original_empty' < "$RESTORE_RECOVERY_META")"
  state_present="$(jq -r '.state_present' < "$RESTORE_RECOVERY_META")"
  state_sha="$(jq -r '.state_sha256' < "$RESTORE_RECOVERY_META")"
  state_size="$(jq -r '.state_size_bytes' < "$RESTORE_RECOVERY_META")"
  if [[ "$state_present" == "true" ]]; then
    validate_recovery_file "$RESTORE_RECOVERY_STATE" "$state_size" "$state_sha" 1000000 \
      "remote-restore schema-state backup" || return 1
  else
    [[ ! -e "$RESTORE_RECOVERY_STATE" && ! -L "$RESTORE_RECOVERY_STATE" ]] || return 1
  fi
  if [[ "$original_empty" == "false" ]]; then
    expected_sha="$(jq -r '.archive_sha256' < "$RESTORE_RECOVERY_META")"
    expected_size="$(jq -r '.archive_size_bytes' < "$RESTORE_RECOVERY_META")"
    validate_recovery_file "$RESTORE_RECOVERY_SQL" "$expected_size" "$expected_sha" \
      "$((SYNC_MAX_EXTRACT_MB * 1000000))" "remote-restore rollback dump" || return 1
  else
    [[ ! -e "$RESTORE_RECOVERY_SQL" && ! -L "$RESTORE_RECOVERY_SQL" ]] || return 1
  fi
}

restore_pending_remote_restore() {
  local original_empty count fingerprint expected_count expected_fingerprint
  local state_present state_sha state_size
  validate_remote_restore_recovery || return 1
  original_empty="$(jq -r '.original_empty' < "$RESTORE_RECOVERY_META")"
  state_present="$(jq -r '.state_present' < "$RESTORE_RECOVERY_META")"
  state_sha="$(jq -r '.state_sha256' < "$RESTORE_RECOVERY_META")"
  state_size="$(jq -r '.state_size_bytes' < "$RESTORE_RECOVERY_META")"
  if [[ "$original_empty" == "true" ]]; then
    log "Resetting interrupted restore target to its original empty state"
    mysql_client -e \
      "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;" \
      || { log "ERROR: failed to reset interrupted empty-database restore"; return 1; }
    restore_recovery_schema_state "$RESTORE_RECOVERY_STATE" false 0 "" || return 1
    count="$(db_table_count)" || return 1
    (( count == 0 )) || return 1
    clear_remote_restore_recovery || return 1
    return 0
  fi

  log "Restoring durable local rollback before any startup remote restore"
  mysql_client -e \
    "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;" \
    || { log "ERROR: failed to recreate database for remote-restore rollback"; return 1; }
  mysql_client < "$RESTORE_RECOVERY_SQL" || {
    log "ERROR: durable remote-restore rollback import failed; artifacts were retained"
    return 1
  }
  count="$(db_table_count)" || return 1
  fingerprint="$(db_schema_fingerprint)" || return 1
  expected_count="$(jq -r '.original_table_count' < "$RESTORE_RECOVERY_META")"
  expected_fingerprint="$(jq -r '.original_schema_fingerprint_sha256' < "$RESTORE_RECOVERY_META")"
  [[ "$count" == "$expected_count" \
      && "${fingerprint,,}" == "${expected_fingerprint,,}" ]] || {
    log "ERROR: restored local rollback does not match its original schema fingerprint"
    return 1
  }
  restore_recovery_schema_state "$RESTORE_RECOVERY_STATE" "$state_present" "$state_size" "$state_sha" \
    || return 1
  if [[ "$state_present" == "true" ]]; then
    schema_state_matches_live "$(desired_schema_type)" \
      || { log "ERROR: restored schema state does not match the restored database"; return 1; }
  fi
  clear_remote_restore_recovery || return 1
  log "Durable local rollback recovery completed"
}

recover_pending_remote_restore() {
  local artifact orphan_found=0
  if [[ ! -e "$RESTORE_RECOVERY_META" && ! -L "$RESTORE_RECOVERY_META" ]]; then
    for artifact in "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE"; do
      if [[ -e "$artifact" || -L "$artifact" ]]; then
        [[ -f "$artifact" && ! -L "$artifact" ]] \
          || die "Unsafe orphaned remote-restore recovery artifact"
        orphan_found=1
      fi
    done
    if (( orphan_found == 1 )); then
      log "Discarding orphaned remote-restore backups: no recovery marker was committed"
      rm -f -- "$RESTORE_RECOVERY_SQL" "$RESTORE_RECOVERY_STATE"
      sync -f "$CONFIG_PATH" || die "Failed to persist orphaned rollback cleanup"
    fi
    return 0
  fi
  log "Pending remote-restore rollback marker found"
  restore_pending_remote_restore \
    || die "Automatic remote-restore crash recovery failed; artifacts were retained for retry/manual recovery"
}

clear_schema_init_recovery() {
  [[ ! -L "$SCHEMA_INIT_META" ]] || return 1
  rm -f -- "$SCHEMA_INIT_META" || return 1
  sync -f "$CONFIG_PATH" || return 1
  SCHEMA_INIT_PENDING=0
}

prepare_schema_init_recovery() {
  local schema_type="$1" meta_tmp
  [[ ! -e "$SCHEMA_INIT_META" && ! -L "$SCHEMA_INIT_META" ]] \
    || die "A schema-initialization recovery marker already exists"
  meta_tmp="$(mktemp "${CONFIG_PATH}/.schema-init-recovery.json.XXXXXX")"
  cleanup_add_file "$meta_tmp"
  jq -n \
    --arg database "$MYSQL_DATABASE" \
    --arg schema_type "$schema_type" \
    --arg target_version "$LUMINA_SCHEMA_VERSION" \
    --arg created_utc "$(now_utc)" \
    '{version:1,kind:"schema-initialization",database:$database,schema_type:$schema_type,target_version:$target_version,created_utc:$created_utc}' \
    > "$meta_tmp"
  chmod 600 "$meta_tmp"
  chown root:root "$meta_tmp"
  sync -f "$meta_tmp" || die "Failed to flush schema-initialization recovery marker"
  mv -f -- "$meta_tmp" "$SCHEMA_INIT_META"
  sync -f "$CONFIG_PATH" || die "Failed to persist schema-initialization recovery marker"
  SCHEMA_INIT_PENDING=1
}

recover_pending_schema_initialization() {
  local database schema_type
  [[ -e "$SCHEMA_INIT_META" || -L "$SCHEMA_INIT_META" ]] || return 0
  [[ -f "$SCHEMA_INIT_META" && ! -L "$SCHEMA_INIT_META" ]] \
    || die "Unsafe schema-initialization recovery marker"
  jq -e '
    type == "object"
    and .version == 1
    and .kind == "schema-initialization"
    and (.database | type == "string")
    and (.schema_type == "lumina" or .schema_type == "vault")
  ' < "$SCHEMA_INIT_META" >/dev/null \
    || die "Invalid schema-initialization recovery marker"
  database="$(jq -r '.database' < "$SCHEMA_INIT_META")"
  schema_type="$(jq -r '.schema_type' < "$SCHEMA_INIT_META")"
  [[ "$database" == "$MYSQL_DATABASE" ]] \
    || die "Interrupted schema initialization targets database '$database', not '$MYSQL_DATABASE'"
  log "Resetting interrupted ${schema_type} schema initialization before remote restore"
  mysql_client -e \
    "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;" \
    || die "Failed to reset interrupted schema initialization"
  [[ ! -L "$SCHEMA_STATE" ]] || die "Refusing symlinked schema state during initialization recovery"
  rm -f -- "$SCHEMA_STATE"
  sync -f "$CONFIG_PATH" || die "Failed to persist schema-state cleanup"
  clear_schema_init_recovery \
    || die "Failed to finalize interrupted schema-initialization recovery"
}

validate_recovery_marker_exclusivity() {
  local marker_count=0 marker
  for marker in "$RESTORE_RECOVERY_META" "$SCHEMA_RECOVERY_META" "$SCHEMA_INIT_META"; do
    if [[ -e "$marker" || -L "$marker" ]]; then
      marker_count=$((marker_count + 1))
    fi
  done
  (( marker_count <= 1 )) \
    || die "Conflicting recovery markers found; refusing an ambiguous automatic recovery"
}

clear_schema_upgrade_recovery() {
  local artifact
  for artifact in "$SCHEMA_RECOVERY_META" "$SCHEMA_RECOVERY_SQL" "$SCHEMA_RECOVERY_STATE"; do
    [[ ! -L "$artifact" ]] || return 1
  done
  rm -f -- "$SCHEMA_RECOVERY_META" || return 1
  sync -f "$CONFIG_PATH" || return 1
  rm -f -- "$SCHEMA_RECOVERY_SQL" "$SCHEMA_RECOVERY_STATE" || return 1
  sync -f "$CONFIG_PATH" || return 1
  SCHEMA_UPGRADE_PENDING=0
}

prepare_schema_upgrade_recovery() {
  local artifact sql_tmp meta_tmp archive_sha archive_size original_count original_fingerprint
  local state_present=true state_sha="" state_size=0 current_count current_fingerprint expected_type
  for artifact in "$SCHEMA_RECOVERY_META" "$SCHEMA_RECOVERY_SQL" "$SCHEMA_RECOVERY_STATE"; do
    [[ ! -e "$artifact" && ! -L "$artifact" ]] \
      || die "A schema-upgrade recovery artifact already exists; startup recovery must run first"
  done
  original_count="$(db_table_count)"
  (( original_count > 0 )) || die "Cannot prepare schema-upgrade recovery for an empty database"
  original_fingerprint="$(db_schema_fingerprint)"
  expected_type="$(desired_schema_type)"
  [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
    || die "A trusted schema state is required before schema upgrade"
  schema_state_matches_live "$expected_type" \
    || die "Existing schema state does not match the live database; refusing schema upgrade"

  sql_tmp="$(mktemp "${CONFIG_PATH}/.schema-recovery.sql.XXXXXX")"
  meta_tmp="$(mktemp "${CONFIG_PATH}/.schema-recovery.json.XXXXXX")"
  cleanup_add_file "$sql_tmp"
  cleanup_add_file "$meta_tmp"
  log "Creating durable pre-upgrade recovery dump"
  if ! MYSQL_PWD="$MYSQL_PASSWORD" mariadb-dump --no-defaults \
      --protocol=TCP -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" \
      --single-transaction --quick --routines --events --triggers --hex-blob \
      --no-tablespaces --skip-dump-date \
      --databases "$MYSQL_DATABASE" > "$sql_tmp"; then
    rm -f -- "$sql_tmp" "$meta_tmp"
    die "Pre-upgrade recovery dump failed; schema was not changed"
  fi
  [[ -s "$sql_tmp" ]] || die "Pre-upgrade recovery dump is empty; schema was not changed"
  ensure_file_within_mb "$sql_tmp" "$SYNC_MAX_EXTRACT_MB" "Schema-upgrade recovery dump"
  archive_size="$(stat -c '%s' "$sql_tmp")"
  archive_sha="$(sha256sum "$sql_tmp" | awk '{print $1}')"
  chmod 600 "$sql_tmp"
  chown root:root "$sql_tmp"
  sync -f "$sql_tmp" || die "Failed to flush schema-upgrade recovery dump"
  mv -- "$sql_tmp" "$SCHEMA_RECOVERY_SQL"
  sync -f "$CONFIG_PATH" || die "Failed to persist schema-upgrade recovery dump"
  if [[ "$state_present" == "true" ]]; then
    persist_recovery_copy "$SCHEMA_STATE" "$SCHEMA_RECOVERY_STATE" \
      "schema-upgrade schema-state backup"
    state_size="$(stat -c '%s' "$SCHEMA_RECOVERY_STATE")"
    state_sha="$(sha256sum "$SCHEMA_RECOVERY_STATE" | awk '{print $1}')"
  fi
  current_count="$(db_table_count)"
  current_fingerprint="$(db_schema_fingerprint)"
  [[ "$current_count" == "$original_count" \
      && "${current_fingerprint,,}" == "${original_fingerprint,,}" ]] \
    || die "Live schema changed while schema-upgrade recovery was being prepared"

  jq -n \
    --arg database "$MYSQL_DATABASE" \
    --arg target_version "$LUMINA_SCHEMA_VERSION" \
    --arg created_utc "$(now_utc)" \
    --arg archive_sha256 "$archive_sha" \
    --arg original_schema_fingerprint_sha256 "$original_fingerprint" \
    --arg state_sha256 "$state_sha" \
    --argjson archive_size_bytes "$archive_size" \
    --argjson original_table_count "$original_count" \
    --argjson state_present "$state_present" \
    --argjson state_size_bytes "$state_size" \
    '{version:2,kind:"schema-upgrade",original_empty:false,database:$database,
      target_version:$target_version,created_utc:$created_utc,
      archive_sha256:$archive_sha256,archive_size_bytes:$archive_size_bytes,
      original_table_count:$original_table_count,
      original_schema_fingerprint_sha256:$original_schema_fingerprint_sha256,
      state_present:$state_present,state_sha256:$state_sha256,state_size_bytes:$state_size_bytes}' \
    > "$meta_tmp"
  chmod 600 "$meta_tmp"
  chown root:root "$meta_tmp"
  sync -f "$meta_tmp" || die "Failed to flush schema-upgrade recovery metadata"
  mv -- "$meta_tmp" "$SCHEMA_RECOVERY_META"
  sync -f "$CONFIG_PATH" || die "Failed to persist schema-upgrade recovery metadata"
  SCHEMA_UPGRADE_PENDING=1
  verify_live_schema_against_recovery_marker "$SCHEMA_RECOVERY_META" \
    || die "Live schema/state changed before schema upgrade; recovery remains armed"
}

validate_schema_upgrade_recovery() {
  local database expected_sha expected_size state_present state_sha state_size
  [[ -f "$SCHEMA_RECOVERY_META" && ! -L "$SCHEMA_RECOVERY_META" ]] || return 1
  jq -e '
    type == "object"
    and .version == 2
    and .kind == "schema-upgrade"
    and .original_empty == false
    and (.database | type == "string")
    and ((.target_version // "") | test("^[0-9]{1,9}$"))
    and ((.archive_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
    and ((.archive_size_bytes | type) == "number") and (.archive_size_bytes >= 1)
    and ((.archive_size_bytes | floor) == .archive_size_bytes)
    and ((.original_table_count | type) == "number") and (.original_table_count >= 1)
    and ((.original_table_count | floor) == .original_table_count)
    and ((.original_schema_fingerprint_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
    and (.state_present | type == "boolean")
    and (if .state_present then
      ((.state_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.state_size_bytes | type) == "number") and (.state_size_bytes >= 1)
      and ((.state_size_bytes | floor) == .state_size_bytes)
    else .state_sha256 == "" and .state_size_bytes == 0 end)
  ' < "$SCHEMA_RECOVERY_META" >/dev/null || return 1
  database="$(jq -r '.database' < "$SCHEMA_RECOVERY_META")"
  [[ "$database" == "$MYSQL_DATABASE" ]] || return 1
  expected_sha="$(jq -r '.archive_sha256' < "$SCHEMA_RECOVERY_META")"
  expected_size="$(jq -r '.archive_size_bytes' < "$SCHEMA_RECOVERY_META")"
  validate_recovery_file "$SCHEMA_RECOVERY_SQL" "$expected_size" "$expected_sha" \
    "$((SYNC_MAX_EXTRACT_MB * 1000000))" "schema-upgrade recovery dump" || return 1
  state_present="$(jq -r '.state_present' < "$SCHEMA_RECOVERY_META")"
  state_sha="$(jq -r '.state_sha256' < "$SCHEMA_RECOVERY_META")"
  state_size="$(jq -r '.state_size_bytes' < "$SCHEMA_RECOVERY_META")"
  if [[ "$state_present" == "true" ]]; then
    validate_recovery_file "$SCHEMA_RECOVERY_STATE" "$state_size" "$state_sha" 1000000 \
      "schema-upgrade schema-state backup" || return 1
  else
    [[ ! -e "$SCHEMA_RECOVERY_STATE" && ! -L "$SCHEMA_RECOVERY_STATE" ]] || return 1
  fi
}

restore_pending_schema_upgrade() {
  local count fingerprint expected_count expected_fingerprint state_present state_sha state_size
  validate_schema_upgrade_recovery || {
    log "ERROR: schema-upgrade recovery metadata/backups are invalid or unsafe"
    return 1
  }
  log "Restoring durable pre-upgrade database before any remote restore"
  mysql_client -e \
    "DROP DATABASE IF EXISTS \`${MYSQL_DATABASE}\`; CREATE DATABASE \`${MYSQL_DATABASE}\`;" \
    || { log "ERROR: failed to recreate database for schema-upgrade recovery"; return 1; }
  mysql_client < "$SCHEMA_RECOVERY_SQL" || {
    log "ERROR: schema-upgrade recovery import failed; recovery artifacts were retained"
    return 1
  }
  count="$(db_table_count)" || return 1
  fingerprint="$(db_schema_fingerprint)" || return 1
  expected_count="$(jq -r '.original_table_count' < "$SCHEMA_RECOVERY_META")"
  expected_fingerprint="$(jq -r '.original_schema_fingerprint_sha256' < "$SCHEMA_RECOVERY_META")"
  [[ "$count" == "$expected_count" \
      && "${fingerprint,,}" == "${expected_fingerprint,,}" ]] || {
    log "ERROR: recovered database does not match its pre-upgrade schema fingerprint"
    return 1
  }
  state_present="$(jq -r '.state_present' < "$SCHEMA_RECOVERY_META")"
  state_sha="$(jq -r '.state_sha256' < "$SCHEMA_RECOVERY_META")"
  state_size="$(jq -r '.state_size_bytes' < "$SCHEMA_RECOVERY_META")"
  restore_recovery_schema_state "$SCHEMA_RECOVERY_STATE" "$state_present" "$state_size" "$state_sha" \
    || return 1
  if [[ "$state_present" == "true" ]]; then
    schema_state_matches_live "$(desired_schema_type)" \
      || { log "ERROR: restored schema state does not match the recovered database"; return 1; }
  fi
  clear_schema_upgrade_recovery || return 1
  log "Pre-upgrade database recovery completed"
}

recover_pending_schema_upgrade() {
  local artifact orphan_found=0
  if [[ ! -e "$SCHEMA_RECOVERY_META" && ! -L "$SCHEMA_RECOVERY_META" ]]; then
    for artifact in "$SCHEMA_RECOVERY_SQL" "$SCHEMA_RECOVERY_STATE"; do
      if [[ -e "$artifact" || -L "$artifact" ]]; then
        [[ -f "$artifact" && ! -L "$artifact" ]] \
          || die "Unsafe orphaned schema-upgrade recovery artifact"
        orphan_found=1
      fi
    done
    if (( orphan_found == 1 )); then
      log "Discarding orphaned schema-upgrade backups: no recovery marker was committed"
      rm -f -- "$SCHEMA_RECOVERY_SQL" "$SCHEMA_RECOVERY_STATE"
      sync -f "$CONFIG_PATH" || die "Failed to persist orphaned recovery cleanup"
    fi
    return 0
  fi
  log "Pending schema-upgrade recovery marker found"
  restore_pending_schema_upgrade \
    || die "Automatic schema-upgrade crash recovery failed; artifacts were retained for retry/manual recovery"
}

write_schema_state() {
  local schema_type="$1" schema_version="$2" table_count="$3" fingerprint tmp
  [[ "$schema_type" == "lumina" || "$schema_type" == "vault" ]] \
    || die "Refusing to write an unknown schema type"
  [[ "$schema_version" == "$LUMINA_SCHEMA_VERSION" ]] \
    || die "Refusing to write a non-current schema version"
  [[ "$table_count" =~ ^[0-9]{1,15}$ ]] && (( 10#$table_count > 0 )) \
    || die "Refusing to write schema state for an empty/invalid database"
  if [[ -e "$SCHEMA_STATE" || -L "$SCHEMA_STATE" ]]; then
    [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
      || die "Schema state path must be a regular non-symlink file"
  fi
  fingerprint="$(db_schema_fingerprint)"
  tmp="$(mktemp "${CONFIG_PATH}/.lumina_schema.state.XXXXXX")"
  cleanup_add_file "$tmp"
  jq -n \
    --arg database "$MYSQL_DATABASE" \
    --arg schema_type "$schema_type" \
    --arg schema_version "$schema_version" \
    --arg schema_fingerprint_sha256 "$fingerprint" \
    --arg timestamp_utc "$(now_utc)" \
    --argjson table_count "$table_count" \
    '{database:$database,schema_type:$schema_type,schema_version:$schema_version,
      schema_fingerprint_sha256:$schema_fingerprint_sha256,
      timestamp_utc:$timestamp_utc,table_count:$table_count}' \
    > "$tmp"
  chmod 640 "$tmp"
  chown root:lumina "$tmp"
  sync -f "$tmp" || die "Failed to flush schema state"
  mv -f -- "$tmp" "$SCHEMA_STATE"
  sync -f "$CONFIG_PATH" || die "Failed to persist schema state"
}

run_schema_cli() {
  run_as_lumina_clean "${INSTALL_PATH}/lumina_server" \
      -f "${CONFIG_PATH}/lumina.conf" "$@"
}

upgrade_database_schema() {
  local post_count="" post_fingerprint="" current_fingerprint="" upgrade_ok=1
  if (( RESTORE_RECOVERY_PENDING == 1 )); then
    [[ "$RESTORED_SCHEMA_FINGERPRINT" =~ ^[a-fA-F0-9]{64}$ ]] \
      || die "Authenticated restore schema fingerprint is unavailable before upgrade"
    current_fingerprint="$(db_schema_fingerprint)"
    [[ "${current_fingerprint,,}" == "${RESTORED_SCHEMA_FINGERPRINT,,}" ]] \
      || die "Restored live schema changed before upgrade; remote rollback remains armed"
  else
    prepare_schema_upgrade_recovery
    verify_live_schema_against_recovery_marker "$SCHEMA_RECOVERY_META" \
      || die "Live schema/state changed before upgrade; recovery remains armed"
  fi
  log "Upgrading non-empty schema with lumina_server --upgrade-schema"
  if ! run_schema_cli --upgrade-schema; then
    upgrade_ok=0
  elif ! post_count="$(db_table_count)"; then
    upgrade_ok=0
  elif (( post_count == 0 )); then
    upgrade_ok=0
  elif ! post_fingerprint="$(db_schema_fingerprint)"; then
    upgrade_ok=0
  else
    [[ "$post_fingerprint" =~ ^[a-f0-9]{64}$ ]] || upgrade_ok=0
  fi

  if (( upgrade_ok == 0 )); then
    if (( RESTORE_RECOVERY_PENDING == 1 )); then
      die "Schema upgrade failed validation; remote-restore rollback remains armed"
    else
      log "ERROR: schema upgrade failed validation; restoring pre-upgrade database"
      if restore_pending_schema_upgrade; then
        die "Schema upgrade failed; the original database and schema state were restored"
      fi
      die "Schema upgrade and automatic recovery both failed; recovery artifacts were retained"
    fi
  fi
  log "Schema upgrade to version ${LUMINA_SCHEMA_VERSION} completed"
}

ensure_database_schema() {
  local count desired_type actual_type="" actual_version="" state_type state_version live_fingerprint
  count="$(db_table_count)"
  desired_type="$(desired_schema_type)"

  if (( count == 0 )); then
    [[ ! -e "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
      || die "Empty database has a stale or unsafe schema state; refusing automatic initialization"
    log "Recreating empty MySQL schema (${desired_type})"
    prepare_schema_init_recovery "$desired_type"
    run_schema_cli --recreate-schema "$desired_type" \
      || die "Schema recreation failed"
    count="$(db_table_count)"
    (( count > 0 )) || die "Schema recreation completed without creating tables"
    actual_type="$desired_type"
    actual_version="$LUMINA_SCHEMA_VERSION"
  else
    log "MySQL schema already contains $count table(s); recreation skipped"
    if [[ -n "$RESTORED_SCHEMA_TYPE" ]]; then
      actual_type="$RESTORED_SCHEMA_TYPE"
      [[ "$RESTORED_SCHEMA_VERSION" =~ ^[0-9]{1,9}$ \
          && "$RESTORED_SCHEMA_FINGERPRINT" =~ ^[a-fA-F0-9]{64}$ ]] \
        || die "Restored snapshot schema metadata is incomplete"
      actual_version="$((10#$RESTORED_SCHEMA_VERSION))"
      validate_snapshot_schema_compatibility "$actual_type" "$actual_version"
      live_fingerprint="$(db_schema_fingerprint)"
      [[ "${live_fingerprint,,}" == "${RESTORED_SCHEMA_FINGERPRINT,,}" ]] \
        || die "Restored live schema no longer matches its authenticated manifest"
    elif [[ -e "$SCHEMA_STATE" || -L "$SCHEMA_STATE" ]]; then
      [[ -f "$SCHEMA_STATE" && ! -L "$SCHEMA_STATE" ]] \
        || die "Existing schema state is not a safe regular file"
      state_type="$(jq -r '.schema_type // "unknown"' < "$SCHEMA_STATE" 2>/dev/null || true)"
      state_version="$(jq -r '.schema_version // "unknown"' < "$SCHEMA_STATE" 2>/dev/null || true)"
      [[ "$state_type" == "lumina" || "$state_type" == "vault" ]] \
        || die "Schema state has an invalid schema type"
      [[ "$state_version" =~ ^[0-9]{1,9}$ ]] \
        || die "Schema state has an invalid schema version"
      [[ "$state_type" == "$desired_type" ]] \
        || die "Existing schema type is '$state_type' but configuration requests '$desired_type'"
      schema_state_matches_live "$state_type" "$state_version" \
        || die "Schema state fingerprint/table count does not match the live database"
      actual_type="$state_type"
      actual_version="$((10#$state_version))"
    else
      die "Non-empty database has no trusted schema state or authenticated restore metadata; refusing startup"
    fi
    [[ "$actual_type" == "$desired_type" ]] \
      || die "Live schema type '$actual_type' is incompatible with configured type '$desired_type'"
    if [[ "$actual_version" =~ ^[0-9]{1,9}$ ]] \
        && (( 10#$actual_version > 10#$LUMINA_SCHEMA_VERSION )); then
      die "Database schema version ${actual_version} is newer than image schema version ${LUMINA_SCHEMA_VERSION}"
    fi
    if [[ "$actual_version" != "$LUMINA_SCHEMA_VERSION" ]]; then
      upgrade_database_schema
      count="$(db_table_count)"
      (( count > 0 )) || die "Schema became empty after a successful upgrade"
      actual_version="$LUMINA_SCHEMA_VERSION"
    fi
  fi
  actual_type="$desired_type"
  actual_version="$LUMINA_SCHEMA_VERSION"
  count="$(db_table_count)"
  (( count > 0 )) || die "Schema validation completed with an empty database"
  write_schema_state "$actual_type" "$actual_version" "$count"
  schema_state_is_trusted "$desired_type" \
    || die "New schema state does not match the live database; recovery remains armed"
  if (( SCHEMA_UPGRADE_PENDING == 1 )); then
    clear_schema_upgrade_recovery \
      || die "Schema upgraded, but durable recovery artifacts could not be finalized"
  fi
  if (( SCHEMA_INIT_PENDING == 1 )); then
    clear_schema_init_recovery \
      || die "Schema initialized, but its durable recovery marker could not be finalized"
  fi
}

tls_pair_matches() {
  local cert="$1" key="$2" cert_public key_public
  [[ -f "$cert" && ! -L "$cert" && -s "$cert" \
      && -f "$key" && ! -L "$key" && -s "$key" ]] || return 1
  cert_public="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum | awk '{print $1}')" || return 1
  key_public="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null \
    | sha256sum | awk '{print $1}')" || return 1
  [[ "$cert_public" =~ ^[a-f0-9]{64}$ && "$cert_public" == "$key_public" ]]
}

tls_certificate_name_matches() {
  local cert="$1"
  if [[ "$LUMINA_HOST_KIND" == "IP" ]]; then
    openssl x509 -checkip "$LUMINA_HOST" -noout -in "$cert" >/dev/null 2>&1
  else
    openssl x509 -checkhost "$LUMINA_HOST" -noout -in "$cert" >/dev/null 2>&1
  fi
}

tls_certificate_is_valid() {
  local cert="$1" key="$2" ca_cert="${CA_PATH}/CA.pem"
  [[ -f "$ca_cert" && ! -L "$ca_cert" && -s "$ca_cert" ]] || return 1
  tls_pair_matches "$cert" "$key" \
    && openssl x509 -checkend 86400 -noout -in "$cert" >/dev/null 2>&1 \
    && openssl verify -CAfile "$ca_cert" "$cert" >/dev/null 2>&1 \
    && tls_certificate_name_matches "$cert"
}

clear_tls_rotation_recovery() {
  local artifact
  for artifact in "$TLS_RECOVERY_META" "$TLS_RECOVERY_CERT" "$TLS_RECOVERY_KEY"; do
    [[ ! -L "$artifact" ]] || return 1
  done
  rm -f -- "$TLS_RECOVERY_META" || return 1
  sync -f "$CONFIG_PATH" || return 1
  rm -f -- "$TLS_RECOVERY_CERT" "$TLS_RECOVERY_KEY" || return 1
  sync -f "$CONFIG_PATH" || return 1
}

prepare_tls_rotation_recovery() {
  local cert="$1" key="$2" artifact meta_tmp
  local cert_present=false key_present=false cert_sha="" key_sha="" cert_size=0 key_size=0
  for artifact in "$TLS_RECOVERY_META" "$TLS_RECOVERY_CERT" "$TLS_RECOVERY_KEY"; do
    [[ ! -e "$artifact" && ! -L "$artifact" ]] \
      || die "A TLS rotation recovery artifact already exists; startup recovery must run first"
  done
  [[ ! -L "$cert" && ! -L "$key" ]] || die "Refusing symlinked TLS key/certificate"
  if [[ -e "$cert" ]]; then
    [[ -f "$cert" && -s "$cert" ]] || die "TLS certificate path is not a non-empty regular file"
    persist_recovery_copy "$cert" "$TLS_RECOVERY_CERT" "TLS certificate recovery backup"
    cert_present=true
    cert_size="$(stat -c '%s' "$TLS_RECOVERY_CERT")"
    cert_sha="$(sha256sum "$TLS_RECOVERY_CERT" | awk '{print $1}')"
  fi
  if [[ -e "$key" ]]; then
    [[ -f "$key" && -s "$key" ]] || die "TLS key path is not a non-empty regular file"
    persist_recovery_copy "$key" "$TLS_RECOVERY_KEY" "TLS key recovery backup"
    key_present=true
    key_size="$(stat -c '%s' "$TLS_RECOVERY_KEY")"
    key_sha="$(sha256sum "$TLS_RECOVERY_KEY" | awk '{print $1}')"
  fi
  meta_tmp="$(mktemp "${CONFIG_PATH}/.tls-rotation-recovery.json.XXXXXX")"
  cleanup_add_file "$meta_tmp"
  jq -n \
    --arg created_utc "$(now_utc)" \
    --arg cert_sha256 "$cert_sha" \
    --arg key_sha256 "$key_sha" \
    --argjson cert_present "$cert_present" \
    --argjson key_present "$key_present" \
    --argjson cert_size_bytes "$cert_size" \
    --argjson key_size_bytes "$key_size" \
    '{version:1,kind:"tls-rotation",created_utc:$created_utc,
      cert_present:$cert_present,cert_sha256:$cert_sha256,cert_size_bytes:$cert_size_bytes,
      key_present:$key_present,key_sha256:$key_sha256,key_size_bytes:$key_size_bytes}' \
    > "$meta_tmp"
  chmod 600 "$meta_tmp"
  chown root:root "$meta_tmp"
  sync -f "$meta_tmp" || die "Failed to flush TLS recovery marker"
  mv -- "$meta_tmp" "$TLS_RECOVERY_META"
  sync -f "$CONFIG_PATH" || die "Failed to persist TLS recovery marker"
}

validate_tls_rotation_recovery() {
  local cert_present key_present cert_sha key_sha cert_size key_size
  [[ -f "$TLS_RECOVERY_META" && ! -L "$TLS_RECOVERY_META" ]] || return 1
  jq -e '
    type == "object" and .version == 1 and .kind == "tls-rotation"
    and (.cert_present | type == "boolean") and (.key_present | type == "boolean")
    and (if .cert_present then
      ((.cert_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.cert_size_bytes | type) == "number") and (.cert_size_bytes >= 1)
      and ((.cert_size_bytes | floor) == .cert_size_bytes)
    else .cert_sha256 == "" and .cert_size_bytes == 0 end)
    and (if .key_present then
      ((.key_sha256 // "") | test("^[A-Fa-f0-9]{64}$"))
      and ((.key_size_bytes | type) == "number") and (.key_size_bytes >= 1)
      and ((.key_size_bytes | floor) == .key_size_bytes)
    else .key_sha256 == "" and .key_size_bytes == 0 end)
  ' < "$TLS_RECOVERY_META" >/dev/null || return 1
  cert_present="$(jq -r '.cert_present' < "$TLS_RECOVERY_META")"
  key_present="$(jq -r '.key_present' < "$TLS_RECOVERY_META")"
  cert_sha="$(jq -r '.cert_sha256' < "$TLS_RECOVERY_META")"
  key_sha="$(jq -r '.key_sha256' < "$TLS_RECOVERY_META")"
  cert_size="$(jq -r '.cert_size_bytes' < "$TLS_RECOVERY_META")"
  key_size="$(jq -r '.key_size_bytes' < "$TLS_RECOVERY_META")"
  if [[ "$cert_present" == "true" ]]; then
    validate_recovery_file "$TLS_RECOVERY_CERT" "$cert_size" "$cert_sha" 1000000 \
      "TLS certificate recovery backup" || return 1
  else
    [[ ! -e "$TLS_RECOVERY_CERT" && ! -L "$TLS_RECOVERY_CERT" ]] || return 1
  fi
  if [[ "$key_present" == "true" ]]; then
    validate_recovery_file "$TLS_RECOVERY_KEY" "$key_size" "$key_sha" 1000000 \
      "TLS key recovery backup" || return 1
  else
    [[ ! -e "$TLS_RECOVERY_KEY" && ! -L "$TLS_RECOVERY_KEY" ]] || return 1
  fi
}

verify_tls_targets_against_recovery_marker() {
  local cert="$1" key="$2" cert_present key_present expected_size expected_sha
  local actual_size actual_sha
  validate_tls_rotation_recovery || return 1
  cert_present="$(jq -r '.cert_present' < "$TLS_RECOVERY_META")"
  key_present="$(jq -r '.key_present' < "$TLS_RECOVERY_META")"
  if [[ "$cert_present" == "true" ]]; then
    [[ -f "$cert" && ! -L "$cert" ]] || return 1
    expected_size="$(jq -r '.cert_size_bytes' < "$TLS_RECOVERY_META")"
    expected_sha="$(jq -r '.cert_sha256' < "$TLS_RECOVERY_META")"
    actual_size="$(stat -c '%s' "$cert")" || return 1
    actual_sha="$(sha256sum "$cert" | awk '{print $1}')" || return 1
    [[ "$actual_size" == "$expected_size" && "${actual_sha,,}" == "${expected_sha,,}" ]] \
      || return 1
  else
    [[ ! -e "$cert" && ! -L "$cert" ]] || return 1
  fi
  if [[ "$key_present" == "true" ]]; then
    [[ -f "$key" && ! -L "$key" ]] || return 1
    expected_size="$(jq -r '.key_size_bytes' < "$TLS_RECOVERY_META")"
    expected_sha="$(jq -r '.key_sha256' < "$TLS_RECOVERY_META")"
    actual_size="$(stat -c '%s' "$key")" || return 1
    actual_sha="$(sha256sum "$key" | awk '{print $1}')" || return 1
    [[ "$actual_size" == "$expected_size" && "${actual_sha,,}" == "${expected_sha,,}" ]] \
      || return 1
  else
    [[ ! -e "$key" && ! -L "$key" ]] || return 1
  fi
}

restore_tls_recovery_file() {
  local backup="$1" target="$2" present="$3" tmp
  [[ ! -L "$target" ]] || return 1
  if [[ "$present" == "true" ]]; then
    tmp="$(mktemp "${CONFIG_PATH}/.$(basename "$target").restore.XXXXXX")" || return 1
    cleanup_add_file "$tmp"
    cp -- "$backup" "$tmp" || return 1
    chmod 640 "$tmp" || return 1
    chown root:lumina "$tmp" || return 1
    sync -f "$tmp" || return 1
    mv -f -- "$tmp" "$target" || return 1
  else
    rm -f -- "$target" || return 1
  fi
}

recover_pending_tls_rotation() {
  local cert="${CONFIG_PATH}/lumina.crt" key="${CONFIG_PATH}/lumina.key"
  local artifact orphan_found=0 cert_present key_present
  if [[ ! -e "$TLS_RECOVERY_META" && ! -L "$TLS_RECOVERY_META" ]]; then
    for artifact in "$TLS_RECOVERY_CERT" "$TLS_RECOVERY_KEY"; do
      if [[ -e "$artifact" || -L "$artifact" ]]; then
        [[ -f "$artifact" && ! -L "$artifact" ]] \
          || die "Unsafe orphaned TLS recovery artifact"
        orphan_found=1
      fi
    done
    if (( orphan_found == 1 )); then
      log "Discarding orphaned TLS backups: no rotation marker was committed"
      rm -f -- "$TLS_RECOVERY_CERT" "$TLS_RECOVERY_KEY"
      sync -f "$CONFIG_PATH" || die "Failed to persist orphaned TLS recovery cleanup"
    fi
    return 0
  fi
  validate_tls_rotation_recovery \
    || die "TLS rotation recovery marker/backups are invalid or unsafe"
  cert_present="$(jq -r '.cert_present' < "$TLS_RECOVERY_META")"
  key_present="$(jq -r '.key_present' < "$TLS_RECOVERY_META")"
  log "Recovering interrupted TLS certificate rotation"
  restore_tls_recovery_file "$TLS_RECOVERY_CERT" "$cert" "$cert_present" \
    || die "Failed to restore the previous TLS certificate"
  restore_tls_recovery_file "$TLS_RECOVERY_KEY" "$key" "$key_present" \
    || die "Failed to restore the previous TLS key"
  sync -f "$CONFIG_PATH" || die "Failed to persist recovered TLS files"
  clear_tls_rotation_recovery \
    || die "TLS files were recovered, but recovery artifacts could not be finalized"
}

ensure_tls_certificate() {
  local cert="${CONFIG_PATH}/lumina.crt" key="${CONFIG_PATH}/lumina.key"
  local ca_cert="${CA_PATH}/CA.pem" openssl_cfg csr new_key new_cert san_line
  [[ ! -e "$TLS_RECOVERY_META" && ! -L "$TLS_RECOVERY_META" ]] \
    || die "Pending TLS rotation recovery must be resolved before certificate validation"
  [[ ! -L "$cert" && ! -L "$key" ]] || die "Refusing symlinked TLS key/certificate"
  if tls_certificate_is_valid "$cert" "$key"; then
    chown root:lumina "$cert" "$key"
    chmod 640 "$cert" "$key"
    log "Reusing valid TLS certificate for $LUMINA_HOST"
    return 0
  fi

  [[ -f "$ca_cert" && ! -L "$ca_cert" && -s "$ca_cert" \
      && -f "$CA_KEY_PATH" && ! -L "$CA_KEY_PATH" && -s "$CA_KEY_PATH" ]] \
    || die "A valid leaf certificate is absent and safe CA.pem/CA.key files are unavailable"
  prepare_tls_rotation_recovery "$cert" "$key"
  openssl_cfg="$(mktemp "${SYNC_RUNTIME_DIR}/openssl-config.XXXXXX")"
  csr="$(mktemp "${SYNC_RUNTIME_DIR}/lumina-csr.XXXXXX")"
  new_key="$(mktemp "${CONFIG_PATH}/.lumina.key.XXXXXX")"
  new_cert="$(mktemp "${CONFIG_PATH}/.lumina.crt.XXXXXX")"
  cleanup_add_file "$openssl_cfg"
  cleanup_add_file "$csr"
  cleanup_add_file "$new_key"
  cleanup_add_file "$new_cert"
  if [[ "$LUMINA_HOST_KIND" == "DNS" ]]; then
    san_line="DNS.1=${LUMINA_HOST}"
  else
    san_line="IP.1=${LUMINA_HOST}"
  fi
  cat > "$openssl_cfg" <<EOF
[req]
distinguished_name=req_distinguished_name
[req_distinguished_name]
[v3_req]
keyUsage=critical, digitalSignature, keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names
[alt_names]
${san_line}
EOF
  openssl req -newkey rsa:3072 -nodes -keyout "$new_key" -out "$csr" \
    -subj "/CN=${LUMINA_HOST}" -config "$openssl_cfg" -reqexts v3_req \
    >/dev/null 2>&1 || die "CSR generation failed; TLS rollback remains armed"
  openssl x509 -req -in "$csr" -CA "$ca_cert" -CAkey "$CA_KEY_PATH" \
    -set_serial "0x$(openssl rand -hex 16)" -out "$new_cert" -days 365 -sha512 \
    -extensions v3_req -extfile "$openssl_cfg" >/dev/null 2>&1 \
    || die "Certificate signing failed; TLS rollback remains armed"
  tls_certificate_is_valid "$new_cert" "$new_key" \
    || die "Generated TLS certificate failed verification; TLS rollback remains armed"
  chmod 640 "$new_key" "$new_cert"
  chown root:lumina "$new_key" "$new_cert"
  sync -f "$new_key" || die "Failed to flush new TLS key; rollback remains armed"
  sync -f "$new_cert" || die "Failed to flush new TLS certificate; rollback remains armed"
  verify_tls_targets_against_recovery_marker "$cert" "$key" \
    || die "Existing TLS targets changed during rotation; rollback remains armed"
  [[ ! -L "$key" && ! -L "$cert" ]] || die "TLS target became a symlink; rollback remains armed"
  mv -f -- "$new_key" "$key"
  mv -f -- "$new_cert" "$cert"
  sync -f "$CONFIG_PATH" || die "Failed to persist new TLS pair; rollback remains armed"
  tls_certificate_is_valid "$cert" "$key" \
    || die "Installed TLS pair failed verification; rollback remains armed"
  clear_tls_rotation_recovery \
    || die "TLS pair was installed, but rotation recovery could not be finalized"
  log "Generated TLS certificate for $LUMINA_HOST"
}

sync_run() {
  local phase="$1" sync_lock_fd lock_file="/run/lumina-sync.lock"
  if [[ "$phase" == "restore" && "$RESTORE_PHASE_OPEN" -ne 1 ]]; then
    die "Restore phase is closed; runtime sync is publish-only"
  fi
  [[ ! -L "$lock_file" ]] || die "Refusing symlinked sync lock"
  exec {sync_lock_fd}>"$lock_file"
  flock -w "$SYNC_LOCK_TIMEOUT_SECONDS" -x "$sync_lock_fd" \
    || die "Timed out waiting ${SYNC_LOCK_TIMEOUT_SECONDS}s for the sync lock"
  cleanup_sync_runtime_locked
  cleanup_stale_fixed_temps
  case "${SYNC_METHOD,,}" in
    commits) perform_commits_sync "$phase" ;;
    releases) perform_releases_sync "$phase" ;;
    *) die "Unknown SYNC_METHOD='$SYNC_METHOD'" ;;
  esac
  cleanup_sync_runtime_locked
  flock -u "$sync_lock_fd"
  exec {sync_lock_fd}>&-
}

startup_restore_phase() {
  if ! is_true "$SYNC_FORCE_RESTORE" && ! db_is_empty; then
    log "Local DB is non-empty -> startup remote access/restore skipped"
    return 0
  fi
  # Empty databases may bootstrap when the remote has no advertised snapshot.
  # Transport failures and corrupt advertised state remain fatal; an explicit
  # force restore additionally requires a usable authenticated snapshot.
  sync_run restore
}

sync_is_writable() {
  if is_true "$SYNC_READ_ONLY"; then return 1; fi
  case "${SYNC_METHOD,,}" in
    releases) [[ -n "$SYNC_AUTH_TOKEN" ]] ;;
    commits)
      if [[ "$GH_REMOTE" =~ ^https:// ]]; then
        [[ -n "$SYNC_AUTH_TOKEN" ]]
      else
        [[ -n "$GH_SSH_PRIVATE_KEY" ]]
      fi
      ;;
  esac
}

sync_publish_best_effort() {
  local reason="$1"
  if (
    CLEANUP_FILES=()
    CLEANUP_DIRS=()
    trap cleanup EXIT
    sync_run publish
  ); then
    log "$reason sync completed"
    return 0
  fi
  log "WARN: $reason sync failed; the server remains available"
  return 1
}

SERVER_PID=""
SYNC_PID=""
SYNC_PGID=""
SHUTDOWN_REQUESTED=0

sync_worker_running() {
  local pid="$1"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  jobs -pr | grep -Fxq -- "$pid"
}

sync_group_alive() {
  local pgid="$1"
  [[ "$pgid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 -- "-$pgid" 2>/dev/null
}

signal_sync_group() {
  local signal="$1" pgid="$2"
  [[ "$pgid" =~ ^[1-9][0-9]*$ ]] || return 0
  kill -"$signal" -- "-$pgid" 2>/dev/null || true
}

launch_sync_worker() {
  local mode="$1" attempt pid
  [[ "$mode" == "__sync-publish-once" ]] || die "Invalid sync worker mode"
  [[ -x /entrypoint.sh && ! -L /entrypoint.sh ]] \
    || die "Unexpected or unsafe entrypoint path for sync worker"
  command -v setsid >/dev/null 2>&1 || die "setsid is required for isolated sync workers"
  MYSQL_PASSWORD="$MYSQL_PASSWORD" \
  SYNC_AUTH_TOKEN="$SYNC_AUTH_TOKEN" \
  SYNC_ENCRYPTION_PASSPHRASE="$SYNC_ENCRYPTION_PASSPHRASE" \
  GH_SSH_PRIVATE_KEY="$GH_SSH_PRIVATE_KEY" \
  GH_KNOWN_HOSTS="$GH_KNOWN_HOSTS" \
    setsid /entrypoint.sh "$mode" &
  pid=$!
  SYNC_PID="$pid"
  SYNC_PGID="$pid"
  for ((attempt=0; attempt<20; attempt++)); do
    sync_group_alive "$SYNC_PGID" && return 0
    sync_worker_running "$SYNC_PID" || break
    sleep 0.05
  done
  if sync_worker_running "$SYNC_PID"; then
    signal_sync_group KILL "$SYNC_PGID"
  fi
  wait "$SYNC_PID" 2>/dev/null || true
  SYNC_PID=""
  SYNC_PGID=""
  die "Failed to establish an isolated process group for the sync worker"
}

request_shutdown() {
  SHUTDOWN_REQUESTED=1
  log "Shutdown requested"
  [[ -z "$SERVER_PID" ]] || kill -TERM "$SERVER_PID" 2>/dev/null || true
  signal_sync_group TERM "$SYNC_PGID"
}

start_periodic_sync() {
  launch_sync_worker __sync-publish-once
  log "Periodic sync started (pid=${SYNC_PID}, pgid=${SYNC_PGID})"
}

stop_periodic_sync() {
  local deadline
  [[ -n "$SYNC_PID" ]] || return 0
  if sync_worker_running "$SYNC_PID"; then
    log "Stopping in-progress periodic sync"
    signal_sync_group TERM "$SYNC_PGID"
    deadline=$((SECONDS + 5))
    while sync_worker_running "$SYNC_PID" && (( SECONDS < deadline )); do
      sleep 1
    done
    if sync_worker_running "$SYNC_PID"; then
      log "WARN: periodic sync did not stop after TERM; killing its process group"
    fi
  fi
  # Also remove detached descendants if the leader exited before they did.
  signal_sync_group KILL "$SYNC_PGID"
  wait "$SYNC_PID" 2>/dev/null || true
  SYNC_PID=""
  SYNC_PGID=""
}

shutdown_sync_bounded() {
  local sync_pid sync_pgid deadline terminate_deadline status
  launch_sync_worker __sync-publish-once
  sync_pid="$SYNC_PID"
  sync_pgid="$SYNC_PGID"
  deadline=$((SECONDS + SYNC_FINAL_TIMEOUT_SECONDS))
  while sync_worker_running "$sync_pid"; do
    if (( SECONDS >= deadline )); then
      log "WARN: final sync exceeded ${SYNC_FINAL_TIMEOUT_SECONDS}s; terminating its process group"
      signal_sync_group TERM "$sync_pgid"
      terminate_deadline=$((SECONDS + 10))
      while sync_worker_running "$sync_pid" && (( SECONDS < terminate_deadline )); do
        sleep 1
      done
      signal_sync_group KILL "$sync_pgid"
      wait "$sync_pid" 2>/dev/null || true
      SYNC_PID=""
      SYNC_PGID=""
      return 1
    fi
    sleep 1
  done
  signal_sync_group KILL "$sync_pgid"
  if wait "$sync_pid"; then status=0; else status=$?; fi
  SYNC_PID=""
  SYNC_PGID=""
  return "$status"
}

supervise_server() {
  local config_file="${CONFIG_PATH}/lumina.conf"
  local server_status=0 next_sync=$((SECONDS + SYNC_INTERVAL_SECONDS)) server_deadline
  trap request_shutdown TERM INT

  log "Starting lumina_server as unprivileged user on :${LUMINA_PORT}"
  (
    exec env -i \
        -u MYSQL_PASSWORD \
        -u MYSQL_PWD \
        -u MYSQL_ROOT_PASSWORD \
        -u SYNC_AUTH_TOKEN \
        -u SYNC_ENCRYPTION_PASSPHRASE \
        -u GH_SSH_PRIVATE_KEY \
        -u GH_KNOWN_HOSTS \
        -u LUMINA_GIT_TOKEN_FILE \
        -u GIT_ASKPASS \
        -u GIT_SSH_COMMAND \
        -u SSH_AUTH_SOCK \
        -u GNUPGHOME \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/var/lib/lumina \
        XDG_DATA_HOME=/var/lib/lumina/.local/share \
        XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
        DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
        USER=lumina LOGNAME=lumina \
        gosu lumina:lumina "${INSTALL_PATH}/lumina_server" \
          -f "$config_file" \
          -p "$LUMINA_PORT" \
          -D "$DATA_PATH" \
          -l "$LUMINA_LOG_PATH" \
          -c "${CONFIG_PATH}/lumina.crt" \
          -k "${CONFIG_PATH}/lumina.key" \
          -L "${INSTALL_PATH}/lumina_server.hexlic"
  ) &
  SERVER_PID=$!

  while kill -0 "$SERVER_PID" 2>/dev/null; do
    if (( SHUTDOWN_REQUESTED == 1 )); then break; fi
    if [[ -n "$SYNC_PID" ]] \
        && ! sync_worker_running "$SYNC_PID"; then
      signal_sync_group KILL "$SYNC_PGID"
      if wait "$SYNC_PID"; then
        log "Periodic sync completed"
      else
        log "WARN: periodic sync failed; the server remains available"
      fi
      SYNC_PID=""
      SYNC_PGID=""
      next_sync=$((SECONDS + SYNC_INTERVAL_SECONDS))
    fi
    if is_true "$SYNC_ENABLED" && sync_is_writable \
        && [[ -z "$SYNC_PID" ]] \
        && (( SYNC_INTERVAL_SECONDS > 0 && SECONDS >= next_sync )); then
      start_periodic_sync
    fi
    sleep 2 &
    wait $! 2>/dev/null || true
  done

  if (( SHUTDOWN_REQUESTED == 1 )) && kill -0 "$SERVER_PID" 2>/dev/null; then
    server_deadline=$((SECONDS + 20))
    while kill -0 "$SERVER_PID" 2>/dev/null && (( SECONDS < server_deadline )); do
      sleep 1
    done
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      log "WARN: lumina_server did not stop after TERM; killing it before final sync"
      kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
  fi
  if wait "$SERVER_PID"; then server_status=0; else server_status=$?; fi
  SERVER_PID=""
  stop_periodic_sync
  if (( SHUTDOWN_REQUESTED == 1 )) && is_true "$SYNC_ENABLED" && sync_is_writable; then
    shutdown_sync_bounded || log "WARN: final shutdown sync did not complete"
  elif is_true "$SYNC_ENABLED" && sync_is_writable; then
    log "WARN: lumina_server exited without an explicit graceful signal; final sync skipped"
  fi
  (( SHUTDOWN_REQUESTED == 1 )) && return 0
  return "$server_status"
}

main() {
log "Bootstrap: validating configuration and creating directories"
validate_settings
[[ "$SYNC_RUNTIME_DIR" == "/run/lumina-sync" ]] \
  || die "Refusing to clean an unexpected sync runtime path"
rm -rf -- "$SYNC_RUNTIME_DIR"
ensure_real_directory "$INSTALL_PATH"
ensure_real_directory "$CA_PATH"
ensure_real_directory "$CONFIG_PATH"
ensure_real_directory "$LOGS_PATH"
ensure_real_directory "$DATA_PATH"
ensure_real_directory /var/lib/lumina
ensure_real_directory /var/lib/lumina/.local
ensure_real_directory /var/lib/lumina/.local/share
ensure_real_directory /var/lib/lumina/.local/share/keyrings
ensure_real_directory "$SYNC_RUNTIME_DIR"
ensure_real_directory /run/lumina-ca
chown root:lumina "$CONFIG_PATH"
chmod 750 "$CONFIG_PATH"
chown -R -h lumina:lumina "$LOGS_PATH" "$DATA_PATH" /var/lib/lumina
chown root:root /run/lumina-ca
chmod 700 "$SYNC_RUNTIME_DIR" /run/lumina-ca /var/lib/lumina /var/lib/lumina/.local/share/keyrings
prepare_gpg_home
cleanup_stale_fixed_temps
rm -f -- "$DUMP_PATH" "${INSTALL_PATH}/${PLAIN_ARCHIVE_NAME}" "$ARCHIVE_PATH"
cd "$INSTALL_PATH" || die "Failed to cd into $INSTALL_PATH"

recover_pending_tls_rotation
wait_for_db
validate_recovery_marker_exclusivity
recover_pending_remote_restore
recover_pending_schema_upgrade
recover_pending_schema_initialization
write_managed_config
ensure_secret_service_bus

log "Patching license"
env -u MYSQL_PASSWORD \
    -u MYSQL_PWD \
    -u MYSQL_ROOT_PASSWORD \
    -u SYNC_AUTH_TOKEN \
    -u SYNC_ENCRYPTION_PASSPHRASE \
    -u GH_SSH_PRIVATE_KEY \
    python3 "${INSTALL_PATH}/license_patch.py" lumina-940 \
    || die "Patch failed"
[[ -f "${INSTALL_PATH}/lumina_server" && ! -L "${INSTALL_PATH}/lumina_server" \
    && -x "${INSTALL_PATH}/lumina_server" ]] \
  || die "lumina_server is missing, non-executable, or unsafe after patching"
[[ -s "${INSTALL_PATH}/lumina_server.hexlic" ]] \
  || die "License patch did not produce lumina_server.hexlic"
[[ ! -L "${INSTALL_PATH}/lumina_server.hexlic" ]] \
  || die "Refusing symlinked license output"
chown root:lumina "${INSTALL_PATH}/lumina_server.hexlic" \
  || die "Failed to set license ownership"
chmod 640 "${INSTALL_PATH}/lumina_server.hexlic" \
  || die "Failed to set license permissions"
chown root:lumina "${INSTALL_PATH}/lumina_server" \
  || die "Failed to set server ownership"
chmod 750 "${INSTALL_PATH}/lumina_server" \
  || die "Failed to set server permissions"

if is_true "$SYNC_ENABLED"; then
  startup_restore_phase
else
  log "Sync disabled"
fi
RESTORE_PHASE_OPEN=0
# Force restore is a one-shot startup override and must never affect periodic or
# final publish-only workers.
SYNC_FORCE_RESTORE=false

if (( RESTORE_RECOVERY_PENDING == 1 )); then
  log "Validating/upgrading restored schema before committing the remote-restore transaction"
  if (
    CLEANUP_FILES=()
    CLEANUP_DIRS=()
    trap cleanup EXIT
    ensure_database_schema
  ); then
    schema_state_is_trusted "$(desired_schema_type)" \
      || die "Restored schema state failed final validation; rollback remains armed"
    clear_remote_restore_recovery \
      || die "Restored database committed, but durable rollback artifacts could not be finalized"
    log "Remote restore transaction committed after schema validation"
  else
    log "ERROR: restored schema initialization/upgrade failed; restoring original database and schema state"
    if restore_pending_remote_restore; then
      die "Remote restore was rolled back because schema validation/upgrade failed"
    fi
    die "Remote restore and automatic rollback both failed; durable recovery artifacts were retained"
  fi
else
  ensure_database_schema
fi
ensure_tls_certificate

# The first dump is intentionally after restore/schema initialization.
if is_true "$SYNC_ENABLED" && sync_is_writable; then
  sync_publish_best_effort "Initial" || true
fi

supervise_server
}

if [[ "${LUMINA_ENTRYPOINT_LIB_ONLY:-false}" != "true" ]]; then
  case "${1:-}" in
    __sync-publish-once)
      validate_settings
      sync_run publish
      ;;
    *) main "$@" ;;
  esac
fi
