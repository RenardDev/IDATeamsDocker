#!/bin/bash

# Installation

INSTALL_PATH="/opt/hexlicsrv"

# General definitions

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/hexlicsrv_schema.lock"

# Vars

LICENSE_HOST=${LICENSE_HOST:-localhost}
LICENSE_PORT=${LICENSE_PORT:-65434}

cd "$INSTALL_PATH"

# ReSave config

if [[ ! -e "${CONFIG_PATH}/hexlicsrv.conf" ]]; then
    cat > "${CONFIG_PATH}/hexlicsrv.conf" <<EOL
sqlite3;Data Source=/opt/hexlicsrv/data/hexlicsrv.sqlite3;
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

python3 "${INSTALL_PATH}/patch.py" hexlicsrv
chown root:root "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"
chmod 755 "${INSTALL_PATH}/license_server" "${INSTALL_PATH}/lsadm"

# ReCreate schema

if [ ! -f "$SCHEMA_LOCK" ]; then
    "${INSTALL_PATH}/license_server" -f "${CONFIG_PATH}/hexlicsrv.conf" --recreate-schema

    touch "$SCHEMA_LOCK"
fi

# Generating TLS chain

openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/hexlicsrv.key" -out "${CONFIG_PATH}/hexlicsrv.csr" -nodes -subj "/CN=${LICENSE_HOST}"
openssl x509 -req -in "${CONFIG_PATH}/hexlicsrv.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/hexlicsrv.crt" -days 365 -sha512 -extfile <(cat <<EOF
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
)

rm "${CONFIG_PATH}/hexlicsrv.csr"

# Fixing owner and rights

# chown hexlicsrv:hexlicsrv "${CONFIG_PATH}/hexlicsrv.conf" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"
chmod 640 "${CONFIG_PATH}/hexlicsrv.conf" "${CONFIG_PATH}/hexlicsrv.crt" "${CONFIG_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"

# Run

"${INSTALL_PATH}/license_server" -f "${CONFIG_PATH}/hexlicsrv.conf" \
    -p "$LICENSE_PORT" \
    -l "${LOGS_PATH}/license_server.log" \
    -c "${CONFIG_PATH}/hexlicsrv.crt" \
    -k "${CONFIG_PATH}/hexlicsrv.key" \
    -L "${INSTALL_PATH}/license_server.hexlic"

sleep 30
