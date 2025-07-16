#!/bin/bash

set -e

# Installation and configuration paths
INSTALL_PATH="/opt/hexlicsrv"
CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"
SCHEMA_LOCK="${CONFIG_PATH}/hexlicsrv_schema.lock"

# Default Variables
LICENSE_HOST="${LICENSE_HOST:-localhost}"
LICENSE_PORT="${LICENSE_PORT:-65434}"

# Ensure directory structure
mkdir -p "$CA_PATH" "$CONFIG_PATH" "$LOGS_PATH" "$DATA_PATH"

# Change to installation directory
cd "$INSTALL_PATH" || { echo "Failed to change directory to $INSTALL_PATH"; exit 1; }

# Create configuration file if it doesn't exist
CONFIG_FILE="${CONFIG_PATH}/hexlicsrv.conf"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "sqlite3;Data Source=${DATA_PATH}/hexlicsrv.sqlite3;" > "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
fi

# Check for Certification Authority files
if [[ ! -f "${CA_PATH}/CA.pem" || ! -f "${CA_PATH}/CA.key" ]]; then
    echo "ERROR: Certification Authority files are missing in $CA_PATH!"
    sleep 5
    exit 1
fi

# Apply patch and set permissions
python3 "${INSTALL_PATH}/main_patch.py" hexlicsrv || { echo "Patch main_patch script failed"; exit 1; }
chown root:root "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"
chmod 755 "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"

# Recreate schema if not already done
if [[ ! -f "$SCHEMA_LOCK" ]]; then
    "${INSTALL_PATH}/license_server" -f "$CONFIG_FILE" --recreate-schema
    touch "$SCHEMA_LOCK"
fi

# Generate TLS certificate chain
openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/hexlicsrv.key" \
    -out "${CONFIG_PATH}/hexlicsrv.csr" -nodes -subj "/CN=${LICENSE_HOST}" || {
        echo "Failed to create TLS certificate request"
        exit 1
    }

openssl x509 -req -in "${CONFIG_PATH}/hexlicsrv.csr" -CA "${CA_PATH}/CA.pem" \
    -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/hexlicsrv.crt" \
    -days 365 -sha512 -extfile <(cat <<-EOF
[req]
distinguished_name=req_distinguished_name
[req_distinguished_name]
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = "$LICENSE_HOST"
EOF
) || { echo "Failed to generate TLS certificate"; exit 1; }

# Clean up certificate request file
rm -f "${CONFIG_PATH}/hexlicsrv.csr"

# Set permissions
chown hexlicsrv:hexlicsrv "$CONFIG_FILE" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"
chmod 640 "$CONFIG_FILE" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"

# Start the license server
"${INSTALL_PATH}/license_server" -f "$CONFIG_FILE" \
    -p "$LICENSE_PORT" \
    -l "${LOGS_PATH}/license_server.log" \
    -c "${CONFIG_PATH}/hexlicsrv.crt" \
    -k "${CONFIG_PATH}/hexlicsrv.key" \
    -L "${INSTALL_PATH}/license_server.hexlic"

sleep 30
