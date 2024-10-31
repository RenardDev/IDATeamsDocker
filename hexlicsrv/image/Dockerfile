
FROM debian:12
EXPOSE 65434
RUN apt-get update && apt-get install -y python3
COPY hexlicsrv90_x64linux.run /hexlicsrv90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
RUN echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\nn\ny\n\n' | /hexlicsrv90_x64linux.run --mode text && \
    rm /hexlicsrv90_x64linux.run && \
    cp /opt/hexlicsrv/hexlicsrv.conf.example /opt/hexlicsrv/hexlicsrv.conf && \
    chmod 640 /opt/hexlicsrv/hexlicsrv.conf && \
    mkdir /opt/hexlicsrv/CA
COPY patch.py /opt/hexlicsrv/patch.py
ENTRYPOINT [ "/entrypoint.sh" ]
