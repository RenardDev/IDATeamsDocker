FROM debian:12

EXPOSE 65433

RUN apt-get update && \
    apt-get install -y python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexvault90_x64linux.run /tmp/hexvault90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY sigmak_search.py /opt/hexvault/sigmak_search.py
COPY patch_version_mismatch.py /opt/hexvault/patch_version_mismatch.py

RUN chmod +x /entrypoint.sh && \
    echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /tmp/hexvault90_x64linux.run --mode text && \
    rm /tmp/hexvault90_x64linux.run && \
    mkdir -p /opt/hexvault/{CA,config,data}

ENTRYPOINT ["/entrypoint.sh"]
