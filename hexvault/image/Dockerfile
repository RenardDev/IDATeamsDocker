
FROM debian:12
EXPOSE 65433
RUN apt-get update && apt-get install -y python3
COPY hexvault90_x64linux.run /hexvault90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
RUN echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /hexvault90_x64linux.run --mode text && \
    rm /hexvault90_x64linux.run && \
    cp /opt/hexvault/hexvault.conf.example /opt/hexvault/hexvault.conf && \
    chmod 640 /opt/hexvault/hexvault.conf && \
    mkdir /opt/hexvault/CA
COPY patch.py /opt/hexvault/patch.py
ENTRYPOINT [ "/entrypoint.sh" ]
