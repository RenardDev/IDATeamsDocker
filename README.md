# IDATeamsDocker

Simple Docker setup for:
- HexLicSrv
- HexVault
- Lumina (with MySQL)

Installers are not included in this repository. Put each installer into the matching `image/` folder.

Supported installer versions:
- [IDA 9.4](https://docs.hex-rays.com/release-notes/9_4)

## Repository Layout

- `hexlicsrv/` - HexLicSrv image, config, data, recovery, keyrings, logs, CA
- `hexvault/` - HexVault image, config, data, recovery, keyrings, logs, CA
- `lumina/` - Lumina image, config, data, keyrings, logs, CA, and MySQL volume
- `ida/` - helper `license_patch.py` for local IDA client patching
- `shell.9.4.reg` - Windows context-menu shortcuts

## Requirements

- Docker + Docker Compose with `linux/amd64` support (native or through emulation; the proprietary server installers are x64)
- A CA pair: `CA.pem` and `CA.key`
- Installers:
  - `hexlicsrv/image/hexlicsrv_x64linux.run`
  - `hexvault/image/hexvault_x64linux.run`
  - `lumina/image/lumina_x64linux.run`

## Quick Start

1. Create a CA (once):

```bash
umask 077
openssl req -x509 \
  -newkey rsa:4096 -sha512 -keyout CA.key -out CA.pem -days 3650 -nodes \
  -subj "/C=BE/L=Liege/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```

2. Copy `CA.pem` and `CA.key` into:

   - `hexlicsrv/CA/`
   - `hexvault/CA/`
   - `lumina/CA/`

3. Copy `.env.example` to `.env` and set `LICENSE_HOST`, `VAULT_HOST` and `LUMINA_HOST` for your deployment.

4. Configure service secrets:

   - Set `VAULT_PASSWORD` for the fixed HexVault admin user `hexvault`. It is applied immediately after the initial schema recreation.
   - Set strong values for `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD`.

5. Start services (from repository root):

```bash
docker compose --env-file .env -f hexlicsrv/docker-compose.yml up -d --build
docker compose --env-file .env -f hexvault/docker-compose.yml up -d --build
docker compose --env-file .env -f lumina/docker-compose.yml up -d --build
```

6. Default ports:

   - HexLicSrv: `65434`
   - HexVault: `65433`
   - Lumina: `443`

## IDA Client Setup (Windows)

1. Create `C:\Program Files\IDA Professional <version>\CA`
2. Put only `CA.pem` there
3. Copy `ida/license_patch.py` into your IDA install directory
4. Run as Administrator:

```bash
python3 license_patch.py ida-pro
```

## Schema Initialization and Upgrades

- Existing databases are validated and are never passed to `--recreate-schema`.
- A fresh database is recreated only when it has no application schema.
- A non-empty database without a trusted schema identity is rejected; automatic schema inference and blind upgrades are disabled.
- Existing schemas are backed up and upgraded with the vendor `--upgrade-schema` command once per image schema version. A failed or interrupted upgrade is rolled back on the next start.
- HexVault uses the fixed account `hexvault`. `VAULT_PASSWORD` is required only for a fresh schema, and `--set-admin hexvault:PASSWORD` runs immediately after that schema recreation. There is no independent password-reset lock.
- Lumina uses its regular schema by default. Set `VAULT_ENABLED=true` only when the Vault-backed schema flavor is required.
- Lumina performs a one-shot local-socket check before startup so that its MySQL account uses `mysql_native_password`, as required by the server.

## Optional Encrypted GitHub Data Sync

The Compose files expose sync variables from the root `.env` file. The lifecycle is:

1. Before the server starts, restore only when local state is empty or `SYNC_FORCE_RESTORE=true` was explicitly requested.
2. Create or upgrade the database schema.
3. Publish an encrypted post-schema snapshot.
4. While running, publish at `SYNC_INTERVAL_SECONDS`; publish once more after a graceful shutdown.

Periodic and shutdown jobs are publish-only: they never restore over a running database. A GitHub outage does not stop a service that already has a valid local database. Filesystem snapshots use SQLite online backup; Lumina uses a transactional MySQL dump.

Publishing or restoring requires `SYNC_ENCRYPTION_PASSPHRASE` with at least 20 characters. Snapshots use GPG AES-256 plus authenticated metadata, including their schema identity. A wrong passphrase or unauthenticated remote metadata fails closed before any remote snapshot is replaced. Release snapshots are namespaced, generation-based and made visible by uploading their manifest last. Completed snapshots are retained according to `SYNC_RELEASE_KEEP`.

Remote sync covers HexLicSrv/HexVault data and the Lumina MySQL database. Persistent `config/`, `keyrings/` and service recovery state are deliberately separate operational data; include them in the host's normal encrypted filesystem backup. Recovery state keeps the original data until automatic recovery succeeds; if automatic rollback also fails, the emergency copy is preserved for manual recovery. `CA.key` is never included in GitHub snapshots.

### Common variables

```dotenv
SYNC_ENABLED=true
SYNC_READ_ONLY=false
SYNC_METHOD=commits
GH_REMOTE=https://github.com/yourorg/yourrepo.git
SYNC_AUTH_TOKEN=github_pat_token_here
SYNC_ENCRYPTION_PASSPHRASE=use-a-unique-long-random-secret
SYNC_INTERVAL_SECONDS=3600
SYNC_NETWORK_TIMEOUT_SECONDS=300
SYNC_LOCK_TIMEOUT_SECONDS=30
SYNC_FINAL_TIMEOUT_SECONDS=300
SYNC_RELEASE_KEEP=3
SYNC_CHUNK_SIZE_MB=49
SYNC_MAX_RESTORE_MB=10240
SYNC_MAX_EXTRACT_MB=20480
```

- `SYNC_HOST_ID` defaults to a different value in every service. If overridden, keep it unique per service and environment. Do not set one global value for several services sharing commits mode.
- `SYNC_READ_ONLY=true` permits authenticated restore-only access and is the only mode that allows anonymous downloads from a public repository. With `SYNC_READ_ONLY=false`, Releases and HTTPS commits require `SYNC_AUTH_TOKEN`; SSH commits require both `GH_SSH_PRIVATE_KEY` and pinned `GH_KNOWN_HOSTS`.
- HTTPS credentials are supplied through `SYNC_AUTH_TOKEN`; credentials embedded in `GH_REMOTE` are rejected.
- SSH remotes require both `GH_SSH_PRIVATE_KEY` and pinned `GH_KNOWN_HOSTS`. Automatic host-key acceptance is disabled.
- Commits mode requires a Git protocol-v2 server that advertises partial-clone blob filtering; blobless branch metadata is limited to 64 MiB before the target namespace is inspected.
- `SYNC_CHUNK_SIZE_MB` must remain between 1 and 49. Release publication checks GitHub's 1000-asset limit before uploading.
- `SYNC_MAX_RESTORE_MB` and `SYNC_MAX_EXTRACT_MB` bound untrusted remote input.
- `SYNC_NETWORK_TIMEOUT_SECONDS`, `SYNC_LOCK_TIMEOUT_SECONDS` and `SYNC_FINAL_TIMEOUT_SECONDS` bound network calls, lock acquisition and the final graceful-shutdown publication.

### Commits mode

```dotenv
SYNC_ENABLED=true
SYNC_METHOD=commits
GH_REMOTE=https://github.com/yourorg/yourrepo.git
SYNC_AUTH_TOKEN=github_pat_token_here
SYNC_ENCRYPTION_PASSPHRASE=use-a-unique-long-random-secret
```

Snapshots are committed under `backups/<SYNC_HOST_ID>/` on `GH_BRANCH` (default `main`). `GH_COMMIT_NAME` and `GH_COMMIT_EMAIL` control the commit identity.

### Releases mode

```dotenv
SYNC_ENABLED=true
SYNC_METHOD=releases
GH_REMOTE=https://github.com/yourorg/yourrepo.git
SYNC_AUTH_TOKEN=github_pat_token_here
SYNC_ENCRYPTION_PASSPHRASE=use-a-unique-long-random-secret
GH_RELEASE_TAG=production-snapshots
```

`GH_RELEASE_NAME`, `GH_API` and `GH_UPLOAD` are optional. Use different `SYNC_HOST_ID` values when several nodes share one release.

### Recovery

- Set `SYNC_FORCE_RESTORE=true` only for one controlled startup when meaningful local data must be replaced. Remove it from `.env` immediately after a successful restore.
- Only the current encrypted and authenticated snapshot format is supported.
- A matching remote manifest is not trusted by itself: referenced chunks, sizes, checksum and authentication are verified before a no-op decision.

## Troubleshooting

- Missing CA files: check `CA/CA.pem` and `CA/CA.key`. Both should be regular files before Compose starts.
- HexVault first start: set `VAULT_PASSWORD`; the required username is always `hexvault`.
- Secret storage: check logs for the D-Bus and writable Secret Service health probes, and preserve the service's `keyrings/` volume.
- Permission errors: generated config, leaf keys and license files must not be world-readable.
- Sync errors: verify `GH_REMOTE`, repository permissions, encryption passphrase and pinned SSH host keys.
- Preserved rollback copies: inspect `recovery/` for HexLicSrv/HexVault and `config/` for Lumina; remove an artifact only after manual recovery is complete.
- A full runtime verification requires the proprietary installers and Docker; the repository cannot provide those artifacts.

## Security Notes

- Never commit `.env`, tokens, SSH private keys, CA private keys, generated leaf keys, databases or proprietary installers. Repository ignore rules cover the expected paths as a second line of defense.
- Do not copy `CA.key` to clients. It is mounted read-only behind a root-only path; network-facing server processes run as unprivileged users and cannot traverse that path.
- The current automatic leaf-certificate setup requires `CA.key` on the Docker host. It is mounted read-only at a root-only path and is not exposed to the network-facing process.
- Remote snapshots are encrypted, but GitHub availability and deletion remain external risks. Keep an independent host-level backup of `config/`, `keyrings/`, each service's recovery state (`recovery/` where present), and CA material.
