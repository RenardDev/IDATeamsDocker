FROM debian:12

EXPOSE 443

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y netcat-openbsd curl python3 git openssh-client zstd jq tar ca-certificates default-mysql-client openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY lumina_x64linux.run /tmp/lumina_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/lumina/license_patch.py

RUN chmod +x /entrypoint.sh && \
    /tmp/lumina_x64linux.run --mode unattended && \
    rm /tmp/lumina_x64linux.run && \
    mkdir -p /opt/lumina/{CA,config,data,logs}

ENTRYPOINT ["/entrypoint.sh"]
