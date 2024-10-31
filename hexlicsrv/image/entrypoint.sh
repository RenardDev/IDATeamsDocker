#!/bin/bash

INSTALL_PATH="/opt/hexlicsrv"
SCHEMA_LOCK="${INSTALL_PATH}/files/schema.lock"

LICENSE_HOST=${LICENSE_HOST:-localhost}
LICENSE_PORT=${LICENSE_PORT:-65434}

cd "$INSTALL_PATH"

# Generating CA if not exist

if [ ! -f "${INSTALL_PATH}/CA/CA.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -sha512 -keyout "${INSTALL_PATH}/CA/CA.key" -out "${INSTALL_PATH}/CA/CA.pem" -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
fi

# Patching

python3 "${INSTALL_PATH}/patch.py" hexlicsrv
chown root:root "${INSTALL_PATH}/license_server"
chmod 755 "${INSTALL_PATH}/license_server"

# ReCreate schema

if [ ! -f "$SCHEMA_LOCK" ]; then
    "${INSTALL_PATH}/vault_server" -f "${INSTALL_PATH}/hexlicsrv.conf" -d "${INSTALL_PATH}/files/store" --recreate-schema
    touch "$SCHEMA_LOCK"
fi

# Generating TLS chain

openssl req -newkey rsa:2048 -keyout "${INSTALL_PATH}/server.key" -out "${INSTALL_PATH}/server.csr" -nodes -subj "/CN=${LICENSE_HOST}"
openssl x509 -req -in "${INSTALL_PATH}/server.csr" -CA "${INSTALL_PATH}/CA/CA.pem" -CAkey "${INSTALL_PATH}/CA/CA.key" -CAcreateserial -out "${INSTALL_PATH}/server.crt" -days 365 -sha512 -extfile <(cat <<EOF
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

rm "${INSTALL_PATH}/server.csr"

mv "${INSTALL_PATH}/server.crt" "${INSTALL_PATH}/hexlicsrv.crt"
mv "${INSTALL_PATH}/server.key" "${INSTALL_PATH}/hexlicsrv.key"

# Fixing owner and rights

chown hexlicsrv:hexlicsrv "${INSTALL_PATH}/hexlicsrv.crt" "${INSTALL_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"
chmod 640 "${INSTALL_PATH}/hexlicsrv.crt" "${INSTALL_PATH}/hexlicsrv.key" "${INSTALL_PATH}/license_server.hexlic"

# Run

"${INSTALL_PATH}/license_server" -f "${INSTALL_PATH}/hexlicsrv.conf" \
    -p "$LICENSE_PORT" \
    -l "${INSTALL_PATH}/logs/license_server.log" \
    -c "${INSTALL_PATH}/hexlicsrv.crt" \
    -k "${INSTALL_PATH}/hexlicsrv.key" \
    -L "${INSTALL_PATH}/license_server.hexlic"

sleep 30
