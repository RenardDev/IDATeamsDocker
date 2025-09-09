FROM debian:12

EXPOSE 65434

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl python3 git openssh-client zstd jq tar ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexlicsrv_x64linux.run /tmp/hexlicsrv_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/hexlicsrv/license_patch.py

RUN chmod +x /entrypoint.sh && \
    echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /tmp/hexlicsrv_x64linux.run --mode text && \
    rm /tmp/hexlicsrv_x64linux.run && \
    mkdir -p /opt/hexlicsrv/{CA,config,data,logs}

ENTRYPOINT ["/entrypoint.sh"]
