FROM debian:12

EXPOSE 65434

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl python3 git openssh-client zstd jq tar ca-certificates openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexlicsrv_x64linux.run /tmp/hexlicsrv_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/hexlicsrv/license_patch.py

RUN chmod +x /entrypoint.sh && \
    /tmp/hexlicsrv_x64linux.run --mode unattended && \
    rm /tmp/hexlicsrv_x64linux.run && \
    mkdir -p /opt/hexlicsrv/{CA,config,data,logs}

ENTRYPOINT ["/entrypoint.sh"]
