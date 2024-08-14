#!/bin/bash

INSTALL_PATH="/opt/hexvault"
LUMINA_CONF="${INSTALL_PATH}/hexvault.conf"
SCHEMA_FLAG="${INSTALL_PATH}/schema_created.flag"

VAULT_HOST=${VAULT_HOST:-localhost}

cd "$INSTALL_PATH"

if [ ! -f "$SCHEMA_FLAG" ]; then
    # Generating CA if not exist
    if [ ! -f "${INSTALL_PATH}/CA/CA.pem" ]; then
        openssl req -x509 -newkey rsa:4096 -sha512 -keyout "${INSTALL_PATH}/CA/CA.key" -out "${INSTALL_PATH}/CA/CA.pem" -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
    fi

    # Patching
    python3 "${INSTALL_PATH}/patch.py"
    mv "${INSTALL_PATH}/vault_server.patched" "${INSTALL_PATH}/vault_server"
    chown root:root "${INSTALL_PATH}/vault_server"
    chmod 755 "${INSTALL_PATH}/vault_server"

    "${INSTALL_PATH}/vault_server" -f "${INSTALL_PATH}/hexvault.conf" -d "${INSTALL_PATH}/files/store" --recreate-schema

    touch "$SCHEMA_FLAG"
fi

# Generating TLS chain
openssl req -newkey rsa:2048 -keyout "${INSTALL_PATH}/server.key" -out "${INSTALL_PATH}/server.csr" -nodes -subj "/CN=${VAULT_HOST}"
openssl x509 -req -in "${INSTALL_PATH}/server.csr" -CA "${INSTALL_PATH}/CA/CA.pem" -CAkey "${INSTALL_PATH}/CA/CA.key" -CAcreateserial -out "${INSTALL_PATH}/server.crt" -days 365 -sha512 -extfile <(cat <<EOF
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

cp "${INSTALL_PATH}/server.crt" "${INSTALL_PATH}/hexvault.crt"
cp "${INSTALL_PATH}/server.key" "${INSTALL_PATH}/hexvault.key"

# Fixing owner and rights
chown hexvault:hexvault "${INSTALL_PATH}/hexvault.crt" "${INSTALL_PATH}/hexvault.key" "${INSTALL_PATH}/teamssrv.hexlic"
chmod 640 "${INSTALL_PATH}/hexvault.crt" "${INSTALL_PATH}/hexvault.key" "${INSTALL_PATH}/teamssrv.hexlic"

"${INSTALL_PATH}/vault_server" -f "${INSTALL_PATH}/hexvault.conf" \
    -l "${INSTALL_PATH}/logs/vault_server.log" \
    -c "${INSTALL_PATH}/hexvault.crt" \
    -k "${INSTALL_PATH}/hexvault.key" \
    -L "${INSTALL_PATH}/teamssrv.hexlic" \
    -d "${INSTALL_PATH}/files"
