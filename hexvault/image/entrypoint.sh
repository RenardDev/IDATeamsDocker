#!/bin/bash

# Installation

INSTALL_PATH="/opt/hexvault"

# General definitions

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/hexvault_schema.lock"

# Vars

VAULT_HOST=${VAULT_HOST:-localhost}
VAULT_PORT=${VAULT_PORT:-65433}

cd "$INSTALL_PATH"

# ReSave config

if [[ ! -e "${CONFIG_PATH}/hexvault.conf" ]]; then
    cat > "${CONFIG_PATH}/hexvault.conf" <<EOL
sqlite3;Data Source=/opt/hexvault/data/hexvault.sqlite3;
EOL
fi

# Checking CA

if [ ! -f "${CA_PATH}/CA.pem" ] || [ ! -f "${CA_PATH}/CA.key" ]; then
    # openssl req -x509 -newkey rsa:4096 -sha512 -keyout "${CA_PATH}/CA.key" -out "${CA_PATH}/CA.pem" -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
    echo "ERROR: Unable to find certification authority!"
    sleep 5
    exit 1
fi

# Patching

python3 "${INSTALL_PATH}/patch.py" hexvault
chown root:root "${INSTALL_PATH}/vault_server"
chmod 755 "${INSTALL_PATH}/vault_server"

# ReCreate schema

if [ ! -f "$SCHEMA_LOCK" ]; then
    "${INSTALL_PATH}/vault_server" -f "${CONFIG_PATH}/hexvault.conf" -d "${DATA_PATH}/store" --recreate-schema

    touch "$SCHEMA_LOCK"
fi

# Generating TLS chain

openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/hexvault.key" -out "${CONFIG_PATH}/hexvault.csr" -nodes -subj "/CN=${VAULT_HOST}"
openssl x509 -req -in "${CONFIG_PATH}/hexvault.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/hexvault.crt" -days 365 -sha512 -extfile <(cat <<EOF
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
)

rm "${CONFIG_PATH}/hexvault.csr"

# Fixing owner and rights

# chown hexvault:hexvault "${CONFIG_PATH}/hexvault.crt" "${CONFIG_PATH}/hexvault.key" "${INSTALL_PATH}/teams_server.hexlic"
chmod 640 "${CONFIG_PATH}/hexvault.crt" "${CONFIG_PATH}/hexvault.key" "${INSTALL_PATH}/teams_server.hexlic"

# Run

"${INSTALL_PATH}/vault_server" -f "${CONFIG_PATH}/hexvault.conf" \
    -p "$VAULT_PORT" \
    -l "${LOGS_PATH}/vault_server.log" \
    -c "${CONFIG_PATH}/hexvault.crt" \
    -k "${CONFIG_PATH}/hexvault.key" \
    -L "${INSTALL_PATH}/teams_server.hexlic" \
    -d "$DATA_PATH"

sleep 30
