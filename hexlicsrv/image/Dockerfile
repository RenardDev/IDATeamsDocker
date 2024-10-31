FROM debian:12

EXPOSE 65434

RUN apt-get update && \
    apt-get install -y python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexlicsrv90_x64linux.run /tmp/hexlicsrv90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY patch.py /opt/hexlicsrv/patch.py

RUN chmod +x /entrypoint.sh && \
    echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /tmp/hexlicsrv90_x64linux.run --mode text && \
    rm /tmp/hexlicsrv90_x64linux.run && \
    mkdir -p /opt/hexlicsrv/{CA,config,data}

ENTRYPOINT ["/entrypoint.sh"]
