#!/bin/bash

# Installation and configuration paths
INSTALL_PATH="/opt/hexvault"
CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"
SCHEMA_LOCK="${CONFIG_PATH}/hexvault_schema.lock"

# Default Variables
VAULT_HOST="${VAULT_HOST:-localhost}"
VAULT_PORT="${VAULT_PORT:-65433}"

# Ensure directory structure
mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"

# Set working directory
cd "$INSTALL_PATH" || { echo "Failed to change directory to $INSTALL_PATH"; exit 1; }

# Generate configuration file if it doesn't exist
CONFIG_FILE="${CONFIG_PATH}/hexvault.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "sqlite3;Data Source=${DATA_PATH}/hexvault.sqlite3;" > "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
fi

# Check for Certification Authority files
if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
    echo "ERROR: Certification Authority files are missing in $CA_PATH!"
    sleep 5
    exit 1
fi

# Apply patch
python3 "${INSTALL_PATH}/patch.py" hexvault || { echo "Patch script failed"; exit 1; }
python3 "${INSTALL_PATH}/patch2.py" || { echo "Patch #2 script failed"; exit 1; }
chown root:root "${INSTALL_PATH}/vault_server"
chmod 755 "${INSTALL_PATH}/vault_server"

# Recreate schema if not already done
if [[ ! -f "$SCHEMA_LOCK" ]]; then
    "${INSTALL_PATH}/vault_server" -f "$CONFIG_FILE" -d "$DATA_PATH" --recreate-schema
    touch "$SCHEMA_LOCK"
fi

# Generate TLS certificate chain
openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/hexvault.key" \
    -out "${CONFIG_PATH}/hexvault.csr" -nodes -subj "/CN=${VAULT_HOST}" || {
        echo "Failed to create TLS certificate request"
        exit 1
    }

openssl x509 -req -in "${CONFIG_PATH}/hexvault.csr" -CA "${CA_PATH}/CA.pem" \
    -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/hexvault.crt" \
    -days 365 -sha512 -extfile <(cat <<-EOF
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
) || { echo "Failed to generate TLS certificate"; exit 1; }

# Clean up certificate request
rm -f "${CONFIG_PATH}/hexvault.csr"

# Set permissions
chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/hexvault.crt" "${CONFIG_PATH}/hexvault.key" "${INSTALL_PATH}/teams_server.hexlic"

# Start vault server
"${INSTALL_PATH}/vault_server" -f "$CONFIG_FILE" \
    -p "$VAULT_PORT" \
    -l "${LOGS_PATH}/vault_server.log" \
    -c "${CONFIG_PATH}/hexvault.crt" \
    -k "${CONFIG_PATH}/hexvault.key" \
    -L "${INSTALL_PATH}/teams_server.hexlic" \
    -d "$DATA_PATH"

sleep 30
