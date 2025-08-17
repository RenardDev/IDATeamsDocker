FROM debian:12

EXPOSE 65433

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 git openssh-client zstd jq tar ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexvault90_x64linux.run /tmp/hexvault90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/hexvault/license_patch.py

RUN chmod +x /entrypoint.sh && \
    echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /tmp/hexvault90_x64linux.run --mode text && \
    rm /tmp/hexvault90_x64linux.run && \
    mkdir -p /opt/hexvault/{CA,config,data,logs}

ENTRYPOINT ["/entrypoint.sh"]
