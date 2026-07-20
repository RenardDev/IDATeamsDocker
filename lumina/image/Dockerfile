FROM debian:12-slim

EXPOSE 443

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        curl \
        dbus-bin \
        dbus-daemon \
        default-mysql-client \
        diffutils \
        git \
        gnupg \
        gnome-keyring \
        gosu \
        jq \
        libglib2.0-0 \
        libsecret-1-0 \
        libsecret-tools \
        netcat-openbsd \
        openssh-client \
        openssl \
        passwd \
        python3 \
        tar \
        util-linux \
        zstd && \
    ldconfig -p | grep -Fq 'libglib-2.0.so.0' && \
    ldconfig -p | grep -Fq 'libsecret-1.so.0' && \
    command -v dbus-daemon >/dev/null && \
    command -v dbus-send >/dev/null && \
    command -v dbus-uuidgen >/dev/null && \
    command -v gnome-keyring-daemon >/dev/null && \
    for required_command in setsid flock timeout secret-tool gpg zstd mysql mariadb-dump; do \
        command -v "$required_command" >/dev/null || exit 1; \
    done && \
    test -f /usr/share/dbus-1/services/org.freedesktop.secrets.service && \
    rm -f /etc/machine-id /var/lib/dbus/machine-id && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY lumina_x64linux.run /tmp/lumina_x64linux.run
COPY entrypoint.sh /entrypoint.sh
COPY license_patch.py /opt/lumina/license_patch.py

RUN chmod +x /entrypoint.sh /tmp/lumina_x64linux.run && \
    /tmp/lumina_x64linux.run --mode unattended && \
    rm /tmp/lumina_x64linux.run && \
    { getent group lumina >/dev/null || groupadd --system --gid 10001 lumina; } && \
    { getent passwd lumina >/dev/null || useradd --system --uid 10001 --gid lumina \
        --home-dir /var/lib/lumina --shell /usr/sbin/nologin lumina; } && \
    test "$(id -u lumina)" = 10001 && \
    test "$(id -g lumina)" = 10001 && \
    install -d -m 0750 /opt/lumina/CA && \
    install -d -o lumina -g lumina -m 0750 \
        /opt/lumina/config \
        /opt/lumina/data \
        /opt/lumina/logs \
        /var/lib/lumina \
        /var/lib/lumina/.local \
        /var/lib/lumina/.local/share \
        /var/lib/lumina/.local/share/keyrings

ENTRYPOINT ["/entrypoint.sh"]
