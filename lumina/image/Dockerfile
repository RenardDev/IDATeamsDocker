FROM debian:12

EXPOSE 443

RUN apt-get update && \
    apt-get install -y netcat-openbsd python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY lumina90_x64linux.run /tmp/lumina90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY patch.py /opt/lumina/patch.py

RUN chmod +x /entrypoint.sh && \
    echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\n\n\n\n\n\ny\n\n\nn\ny\n\n' | /tmp/lumina90_x64linux.run --mode text && \
    rm /tmp/lumina90_x64linux.run && \
    mkdir -p /opt/lumina/{CA,config,data}

ENTRYPOINT ["/entrypoint.sh"]
