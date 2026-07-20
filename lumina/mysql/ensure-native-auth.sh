#!/bin/bash

set -Eeuo pipefail
umask 077

MYSQL_SOCKET="${MYSQL_SOCKET:-/var/run/mysqld/mysqld.sock}"
MYSQL_USER="${MYSQL_USER:?MYSQL_USER is required}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:?MYSQL_PASSWORD is required}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD is required}"

# Keep both passwords as shell-only variables. The mysql client receives only
# the one-command MYSQL_PWD value required for its trusted socket connection.
export -n MYSQL_PASSWORD MYSQL_ROOT_PASSWORD 2>/dev/null || true

for required_tool in mysql od tr; do
  command -v "$required_tool" >/dev/null 2>&1 \
    || { printf 'Required helper tool is missing: %s\n' "$required_tool" >&2; exit 1; }
done

[[ "$MYSQL_SOCKET" == "/var/run/mysqld/mysqld.sock" && -S "$MYSQL_SOCKET" ]] \
  || { printf 'The trusted local MySQL socket is unavailable\n' >&2; exit 1; }
[[ "$MYSQL_USER" =~ ^[A-Za-z0-9_]{1,32}$ ]] \
  || { printf 'MYSQL_USER must contain 1-32 letters, digits, or underscores\n' >&2; exit 1; }
[[ "$MYSQL_PASSWORD" != *$'\n'* && "$MYSQL_PASSWORD" != *$'\r'* ]] \
  || { printf 'MYSQL_PASSWORD must not contain newlines\n' >&2; exit 1; }
[[ "$MYSQL_ROOT_PASSWORD" != *$'\n'* && "$MYSQL_ROOT_PASSWORD" != *$'\r'* ]] \
  || { printf 'MYSQL_ROOT_PASSWORD must not contain newlines\n' >&2; exit 1; }

to_hex() {
  od -An -v -tx1 | tr -d ' \n'
}

user_hex="$(printf '%s' "$MYSQL_USER" | to_hex)"
password_hex="$(printf '%s' "$MYSQL_PASSWORD" | to_hex)"
[[ -n "$user_hex" && -n "$password_hex" ]] \
  || { printf 'MYSQL_USER and MYSQL_PASSWORD must not be empty\n' >&2; exit 1; }

# Values reach mysql over stdin as hex literals: no password is placed in argv,
# logs, or a shell-generated SQL string literal.
sql="SET SESSION sql_mode=TRIM(BOTH ',' FROM REPLACE(CONCAT(',',@@SESSION.sql_mode,','),',NO_BACKSLASH_ESCAPES,',','));\n"
sql+="SET @app_user=CONVERT(0x${user_hex} USING utf8mb4);\n"
sql+="SET @app_password=CONVERT(0x${password_hex} USING utf8mb4);\n"
sql+="SET @alter_sql=CONCAT('ALTER USER ', QUOTE(@app_user), '@''%'' IDENTIFIED WITH mysql_native_password BY ', QUOTE(@app_password));\n"
sql+="PREPARE alter_user_stmt FROM @alter_sql;\nEXECUTE alter_user_stmt;\nDEALLOCATE PREPARE alter_user_stmt;\n"
sql+="SELECT IF(plugin='mysql_native_password','ok','wrong-plugin') FROM mysql.user WHERE user=@app_user AND host='%';\n"

result="$({ printf '%b' "$sql"; } | MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --no-defaults \
  --protocol=SOCKET --socket="$MYSQL_SOCKET" -u root \
  --batch --skip-column-names --silent)"

[[ "${result//$'\r'/}" == "ok" ]] \
  || { printf 'Failed to verify mysql_native_password for the Lumina database user\n' >&2; exit 1; }

unset MYSQL_PASSWORD MYSQL_ROOT_PASSWORD password_hex sql
printf 'Lumina MySQL authentication plugin is ready\n'
