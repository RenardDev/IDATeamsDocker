FROM debian:12-slim

EXPOSE 65434

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dbus-bin \
        dbus-daemon \
        git \
        gnome-keyring \
        gnupg \
        jq \
        libglib2.0-0 \
        libsecret-1-0 \
        libsecret-tools \
        openssh-client \
        openssl \
        passwd \
        python3 \
        sqlite3 \
        tar \
        util-linux \
        zstd && \
    ldconfig -p | grep -Fq 'libglib-2.0.so.0' && \
    ldconfig -p | grep -Fq 'libsecret-1.so.0' && \
    command -v dbus-daemon >/dev/null && \
    command -v dbus-send >/dev/null && \
    command -v dbus-uuidgen >/dev/null && \
    command -v gnome-keyring-daemon >/dev/null && \
    command -v secret-tool >/dev/null && \
    command -v gpg >/dev/null && \
    command -v flock >/dev/null && \
    command -v runuser >/dev/null && \
    command -v setpriv >/dev/null && \
    command -v setsid >/dev/null && \
    command -v sqlite3 >/dev/null && \
    command -v timeout >/dev/null && \
    test -f /usr/share/dbus-1/services/org.freedesktop.secrets.service && \
    rm -f /etc/machine-id /var/lib/dbus/machine-id && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexlicsrv_x64linux.run /tmp/hexlicsrv_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/hexlicsrv/license_patch.py

RUN chmod +x /entrypoint.sh /tmp/hexlicsrv_x64linux.run && \
    /tmp/hexlicsrv_x64linux.run --mode unattended && \
    rm /tmp/hexlicsrv_x64linux.run && \
    { getent group hexlicsrv >/dev/null || groupadd --system --gid 10001 hexlicsrv; } && \
    { getent passwd hexlicsrv >/dev/null || useradd --system --uid 10001 --gid hexlicsrv \
        --home-dir /var/lib/hexlicsrv --create-home --shell /usr/sbin/nologin hexlicsrv; } && \
    test "$(id -u hexlicsrv)" = 10001 && \
    test "$(id -g hexlicsrv)" = 10001 && \
    mkdir -p \
        /opt/hexlicsrv/CA \
        /opt/hexlicsrv/config \
        /opt/hexlicsrv/data \
        /opt/hexlicsrv/logs \
        /opt/hexlicsrv/recovery \
        /run/hexlicsrv-ca-key \
        /var/lib/hexlicsrv/.config \
        /var/lib/hexlicsrv/.local/share/keyrings && \
    chmod 700 /run/hexlicsrv-ca-key && \
    chown -R hexlicsrv:hexlicsrv \
        /opt/hexlicsrv/config \
        /opt/hexlicsrv/data \
        /opt/hexlicsrv/logs \
        /var/lib/hexlicsrv && \
    chown root:root /opt/hexlicsrv/recovery && \
    chmod 700 /opt/hexlicsrv/recovery

ENTRYPOINT ["/entrypoint.sh"]
