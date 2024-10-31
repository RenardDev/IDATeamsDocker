#!/bin/bash

# Installation

INSTALL_PATH="/opt/lumina"

# General definitions

CA_PATH="${INSTALL_PATH}/CA"
CONFIG_PATH="${INSTALL_PATH}/config"
LOGS_PATH="${INSTALL_PATH}/logs"
DATA_PATH="${INSTALL_PATH}/data"

SCHEMA_LOCK="${CONFIG_PATH}/lumina_schema.lock"

# Vars

MYSQL_HOST=${MYSQL_HOST:-localhost}
MYSQL_PORT=${MYSQL_PORT:-3306}
MYSQL_DATABASE=${MYSQL_DATABASE:-lumina}
MYSQL_USER=${MYSQL_USER:-lumina}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-lumina}
LUMINA_HOST=${LUMINA_HOST:-localhost}
LUMINA_PORT=${LUMINA_PORT:-443}

cd "$INSTALL_PATH"

# Checking database

wait_for_db() {
  until nc -z "$MYSQL_HOST" "$MYSQL_PORT"; do
    echo "Waiting for database connection on $MYSQL_HOST:$MYSQL_PORT..."
    sleep 5
  done
  echo "Database connection established."
}

wait_for_db

# ReSave config

if [[ ! -e "${CONFIG_PATH}/lumina.conf" ]]; then
    if [[ -n "${VAULT_HOST}" && -n "${VAULT_PORT}" ]]; then
        cat > "${CONFIG_PATH}/lumina.conf" <<EOL
CONNSTR="mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD;"
VAULT_HOST="$VAULT_HOST:$VAULT_PORT"
EOL
    else
        cat > "${CONFIG_PATH}/lumina.conf" <<EOL
CONNSTR="mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD;"
EOL
fi

chmod 640 "$LUMINA_CONF"

# Checking CA

if [ ! -f "${CA_PATH}/CA.pem" ] || [ ! -f "${CA_PATH}/CA.key" ]; then
    # openssl req -x509 -newkey rsa:4096 -sha512 -keyout "${CA_PATH}/CA.key" -out "${CA_PATH}/CA.pem" -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
    echo "ERROR: Unable to find certification authority!"
    sleep 5
    exit 1
fi

# Patching

python3 "${INSTALL_PATH}/patch.py" lumina
chown root:root "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" 
chmod 755 "${INSTALL_PATH}/lumina_server" "${INSTALL_PATH}/lc" 

# ReCreate schema

if [ ! -f "$SCHEMA_LOCK" ]; then
    if [[ -n "${VAULT_HOST}" && -n "${VAULT_PORT}" ]]; then
        "${INSTALL_PATH}/lumina_server" -f "$LUMINA_CONF" --recreate-schema vault
    else
        "${INSTALL_PATH}/lumina_server" -f "$LUMINA_CONF" --recreate-schema lumina
    fi

    touch "$SCHEMA_LOCK"
fi

# Generating TLS chain

openssl req -newkey rsa:2048 -keyout "${CONFIG_PATH}/lumina.key" -out "${CONFIG_PATH}/lumina.csr" -nodes -subj "/CN=${LUMINA_HOST}"
openssl x509 -req -in "${CONFIG_PATH}/lumina.csr" -CA "${CA_PATH}/CA.pem" -CAkey "${CA_PATH}/CA.key" -CAcreateserial -out "${CONFIG_PATH}/lumina.crt" -days 365 -sha512 -extfile <(cat <<EOF
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
)

rm "${CONFIG_PATH}/server.csr"

# Fixing Owner and Rights

chown lumina:lumina "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"
chmod 640 "${CONFIG_PATH}/lumina.crt" "${CONFIG_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"

# Run

"${INSTALL_PATH}/lumina_server" -f "${CONFIG_PATH}/lumina.conf" \
    -p "$LUMINA_PORT" \
    -D "${DATA_PATH}" \
    -l "${LOGS_PATH}/lumina_server.log" \
    -c "${CONFIG_PATH}/lumina.crt" \
    -k "${CONFIG_PATH}/lumina.key" \
    -L "${INSTALL_PATH}/lumina_server.hexlic"

sleep 30
