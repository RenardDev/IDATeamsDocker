FROM debian:12

EXPOSE 443

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates \
        curl \
        dbus-x11 \
        default-mysql-client \
        git \
        gnome-keyring \
        jq \
        libglib2.0-0 \
        libsecret-1-0 \
        netcat-openbsd \
        openssh-client \
        openssl \
        python3 \
        tar \
        zstd && \
    ldconfig -p | grep -Fq 'libglib-2.0.so.0' && \
    ldconfig -p | grep -Fq 'libsecret-1.so.0' && \
    command -v dbus-daemon >/dev/null && \
    command -v dbus-send >/dev/null && \
    command -v dbus-uuidgen >/dev/null && \
    command -v gnome-keyring-daemon >/dev/null && \
    test -f /usr/share/dbus-1/services/org.freedesktop.secrets.service && \
    rm -f /etc/machine-id /var/lib/dbus/machine-id && \
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
