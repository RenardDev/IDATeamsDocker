
FROM debian:12
EXPOSE 443
RUN apt-get update && apt-get install -y netcat-openbsd python3
COPY lumina90_x64linux.run /lumina90_x64linux.run
COPY entrypoint.sh /entrypoint.sh
RUN echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ny\n\ny\n\n\n\n\n\n\ny\n\n\nn\ny\n\n' | /lumina90_x64linux.run --mode text && \
    rm /lumina90_x64linux.run && \
    mkdir /opt/lumina/CA
COPY patch.py /opt/lumina/patch.py
ENTRYPOINT [ "/entrypoint.sh" ]
