FROM debian:12-slim

EXPOSE 65433

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

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
    command -v runuser >/dev/null && \
    command -v setpriv >/dev/null && \
    command -v setsid >/dev/null && \
    command -v mountpoint >/dev/null && \
    command -v flock >/dev/null && \
    command -v timeout >/dev/null && \
    command -v sqlite3 >/dev/null && \
    test -f /usr/share/dbus-1/services/org.freedesktop.secrets.service && \
    rm -f /etc/machine-id /var/lib/dbus/machine-id && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY hexvault_x64linux.run /tmp/hexvault_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/hexvault/license_patch.py

RUN chmod +x /entrypoint.sh /tmp/hexvault_x64linux.run && \
    /tmp/hexvault_x64linux.run --mode unattended && \
    rm /tmp/hexvault_x64linux.run && \
    { getent group hexvault >/dev/null || groupadd --system --gid 10001 hexvault; } && \
    { getent passwd hexvault >/dev/null || useradd --system --uid 10001 --gid hexvault \
        --home-dir /var/lib/hexvault --create-home --shell /usr/sbin/nologin hexvault; } && \
    test "$(id -u hexvault)" = 10001 && \
    test "$(id -g hexvault)" = 10001 && \
    mkdir -p /opt/hexvault/CA /opt/hexvault/config /opt/hexvault/data \
        /opt/hexvault/logs /opt/hexvault/recovery /run/hexvault-ca-key \
        /var/lib/hexvault/.config /var/lib/hexvault/.local/share/keyrings && \
    chmod 700 /run/hexvault-ca-key /opt/hexvault/recovery && \
    chown -R hexvault:hexvault /opt/hexvault/config /opt/hexvault/data \
        /opt/hexvault/logs /var/lib/hexvault

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${VAULT_PORT:-65433}"]

ENTRYPOINT ["/entrypoint.sh"]
