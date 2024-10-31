#!/bin/bash

INSTALL_PATH="/opt/lumina"
LUMINA_CONF="${INSTALL_PATH}/lumina.conf"
SCHEMA_LOCK="${INSTALL_PATH}/schema.lock"

SKIP_RECREATE_SCHEMA=${SKIP_RECREATE_SCHEMA:-N}
MYSQL_HOST=${MYSQL_HOST:-localhost}
MYSQL_PORT=${MYSQL_PORT:-3306}
MYSQL_DATABASE=${MYSQL_DATABASE:-lumina}
MYSQL_USER=${MYSQL_USER:-lumina}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-lumina}
LUMINA_HOST=${LUMINA_HOST:-localhost}
LUMINA_PORT=${LUMINA_PORT:-443}
VAULT_HOST=${VAULT_HOST:-localhost}
VAULT_PORT=${VAULT_PORT:-65433}

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

# Save database

cat > "$LUMINA_CONF" <<EOL
CONNSTR="mysql;Server=$MYSQL_HOST;Port=$MYSQL_PORT;Database=$MYSQL_DATABASE;Uid=$MYSQL_USER;Pwd=$MYSQL_PASSWORD"
VAULT_HOST="$VAULT_HOST:$VAULT_PORT"
EOL

chmod 640 "$LUMINA_CONF"

# Checking CA

if [ ! -f "${INSTALL_PATH}/CA/CA.pem" ] || [ ! -f "${INSTALL_PATH}/CA/CA.key" ]; then
    # openssl req -x509 -newkey rsa:4096 -sha512 -keyout "${INSTALL_PATH}/CA/CA.key" -out "${INSTALL_PATH}/CA/CA.pem" -days 365 -nodes -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
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

    if [ ! "$SKIP_RECREATE_SCHEMA" = "y" ] && [ ! "$SKIP_RECREATE_SCHEMA" = "Y" ]; then
        "${INSTALL_PATH}/lumina_server" -f "$LUMINA_CONF" --recreate-schema
    fi

    touch "$SCHEMA_LOCK"
fi

# Generating TLS chain

openssl req -newkey rsa:2048 -keyout "${INSTALL_PATH}/server.key" -out "${INSTALL_PATH}/server.csr" -nodes -subj "/CN=${LUMINA_HOST}"
openssl x509 -req -in "${INSTALL_PATH}/server.csr" -CA "${INSTALL_PATH}/CA/CA.pem" -CAkey "${INSTALL_PATH}/CA/CA.key" -CAcreateserial -out "${INSTALL_PATH}/server.crt" -days 365 -sha512 -extfile <(cat <<EOF
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

rm "${INSTALL_PATH}/server.csr"

mv "${INSTALL_PATH}/server.crt" "${INSTALL_PATH}/lumina.crt"
mv "${INSTALL_PATH}/server.key" "${INSTALL_PATH}/lumina.key"

# Fixing Owner and Rights

chown lumina:lumina "${INSTALL_PATH}/lumina.crt" "${INSTALL_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"
chmod 640 "${INSTALL_PATH}/lumina.crt" "${INSTALL_PATH}/lumina.key" "${INSTALL_PATH}/lumina_server.hexlic"

# Run

"${INSTALL_PATH}/lumina_server" -f "$LUMINA_CONF" \
    -p "$LUMINA_PORT" \
    -D "${INSTALL_PATH}/badreqs" \
    -l "${INSTALL_PATH}/logs/lumina_server.log" \
    -c "${INSTALL_PATH}/lumina.crt" \
    -k "${INSTALL_PATH}/lumina.key" \
    -L "${INSTALL_PATH}/lumina_server.hexlic"

sleep 30
