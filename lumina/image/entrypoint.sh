#!/bin/bash

set -e

# Installation paths
INSTALL_PATH="/opt/lumina"
CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"
SCHEMA_LOCK="${CONFIG_PATH}/lumina_schema.lock"

# Database and Server Variables with Defaults
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-lumina}"
MYSQL_USER="${MYSQL_USER:-lumina}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-lumina}"
LUMINA_HOST="${LUMINA_HOST:-localhost}"
LUMINA_PORT="${LUMINA_PORT:-443}"

# Ensure directory structure
mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"

# Wait for database connection
wait_for_db() {
  until nc -z "$MYSQL_HOST" "$MYSQL_PORT"; do
    echo "Waiting for database connection on $MYSQL_HOST:$MYSQL_PORT..."
    sleep 5
  done
  echo "Database connection established."
}

wait_for_db

# Generate configuration file if it doesn't exist
CONFIG_FILE="${CONFIG_PATH}/lumina.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<-EOL
CONNSTR="mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD;"
EOL
    [[ -n "$VAULT_HOST" && -n "$VAULT_PORT" ]] && echo "VAULT_HOST=\"$VAULT_HOST:$VAULT_PORT\"" >> "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
fi

# Verify Certification Authority files
if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
    echo "ERROR: Certification Authority files are missing in $CA_PATH!"
    sleep 5
    exit 1
fi

# Apply patch and set permissions
python3 "${INSTALL_PATH}/main_patch.py" lumina || { echo "Patch main_patch script failed"; exit 1; }
python3 "${INSTALL_PATH}/version_patch.py" || { echo "Patch version_patch script failed"; exit 1; }
chown root:root "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc"
chmod 755 "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc"

# Recreate schema if necessary
if [[ ! -f "$SCHEMA_LOCK" ]]; then
    SCHEMA_TYPE="lumina"
    [[ -n "$VAULT_HOST" && -n "$VAULT_PORT" ]] && SCHEMA_TYPE="vault"
    "${INSTALL_PATH}/lumina_server" -f "$CONFIG_FILE" --recreate-schema "$SCHEMA_TYPE"
    touch "$SCHEMA_LOCK"
fi

# Generate TLS certificate chain
openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/lumina.key" \
    -out "${CONFIG_PATH}/lumina.csr" -nodes -subj "/CN=${LUMINA_HOST}" || {
        echo "Failed to create TLS certificate request"
        exit 1
    }

openssl x509 -req -in "${CONFIG_PATH}/lumina.csr" -CA "${CA_PATH}/CA.pem" \
    -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/lumina.crt" \
    -days 365 -sha512 -extfile <(cat <<-EOF
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
) || { echo "Failed to generate TLS certificate"; exit 1; }

# Clean up the certificate request file
rm -f "${CONFIG_PATH}/lumina.csr"

# Set ownership and permissions
chown lumina:lumina "$CONFIG_FILE" "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"
chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"

# Start the Lumina server
"${INSTALL_PATH}/lumina_server" -f "$CONFIG_FILE" \
    -p "$LUMINA_PORT" \
    -D "$DATA_PATH" \
    -l "${LOGS_PATH}/lumina_server.log" \
    -c "${CONFIG_PATH}/lumina.crt" \
    -k "${CONFIG_PATH}/lumina.key" \
    -L "${INSTALL_PATH}/lumina_server.hexlic"

sleep 30
