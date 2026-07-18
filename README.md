# IDATeamsDocker

Simple Docker setup for:
- HexLicSrv
- HexVault
- Lumina (with MySQL)

Installers are not included in this repository. Put each installer into the matching `image/` folder.

Supported installer versions:
- [IDA 9.4](https://docs.hex-rays.com/release-notes/9_4)

## Repository Layout

- `hexlicsrv/` - HexLicSrv image, config, data, logs, CA
- `hexvault/` - HexVault image, config, data, logs, CA
- `lumina/` - Lumina image, config, data, logs, CA, and MySQL volume
- `ida/` - helper `license_patch.py` for local IDA client patching
- `shell.9.4.reg` - Windows context-menu shortcuts

## Requirements

- Linux host with Docker + Docker Compose
- A CA pair: `CA.pem` and `CA.key`
- Installers:
  - `hexlicsrv/image/hexlicsrv_x64linux.run`
  - `hexvault/image/hexvault_x64linux.run`
  - `lumina/image/lumina_x64linux.run`

## Quick Start

1. Create a CA (once):

```bash
openssl req -x509 \
  -newkey rsa:4096 -sha512 -keyout CA.key -out CA.pem -days 3650 -nodes \
  -subj "/C=BE/L=Liege/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```

2. Copy `CA.pem` and `CA.key` into:
- `hexlicsrv/CA/`
- `hexvault/CA/`
- `lumina/CA/`

3. Adjust hostnames in compose files:
- `hexlicsrv/docker-compose.yml`: `LICENSE_HOST`
- `hexvault/docker-compose.yml`: `VAULT_HOST`
- `lumina/docker-compose.yml`: `LUMINA_HOST`

4. Configure MySQL secrets for Lumina:
- Copy `.env.example` to `.env` (for example: `cp .env.example .env`)
- Set strong values for `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD`

5. Start services (from repository root):

```bash
docker compose -f hexlicsrv/docker-compose.yml up -d --build
docker compose -f hexvault/docker-compose.yml up -d --build
docker compose -f lumina/docker-compose.yml up -d --build
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

## Optional GitHub Sync

Each service can backup/restore state to GitHub on container start.

How it works:
- If local state is empty and a remote snapshot exists, the service restores from GitHub.
- If local state is not empty, the service creates a new snapshot and uploads only when data changed.
- `hexlicsrv` and `hexvault` sync filesystem data.
- `lumina` syncs MySQL dump.

Where to configure:
- Add sync variables to the `environment:` block of the needed service in:
  - `hexlicsrv/docker-compose.yml`
  - `hexvault/docker-compose.yml`
  - `lumina/docker-compose.yml`

### 1) Common variables (for any service)

```yaml
environment:
  SYNC_ENABLED: "true"
  SYNC_METHOD: "commits" # or "releases"
  GH_REMOTE: "https://github.com/yourorg/yourrepo.git"
  SYNC_HOST_ID: "hexvault-prod-01"   # unique node id
  SYNC_CHUNK_SIZE_MB: "49"           # keep <= 49 for GitHub limits
```

Notes:
- `SYNC_HOST_ID` should be unique per node/environment.
- For private repos and uploads, provide auth (token or SSH key).
- For HTTPS remotes without `SYNC_AUTH_TOKEN`, sync works in read-only mode (restore only, no upload).

### 2) Commits mode (store chunks in branch files)

Required:
- `SYNC_METHOD=commits`
- `GH_REMOTE`
- `SYNC_HOST_ID`

Optional:
- `GH_BRANCH` (default `main`)
- `GH_COMMIT_NAME`, `GH_COMMIT_EMAIL`
- `SYNC_AUTH_TOKEN` for HTTPS write access
- `GH_SSH_PRIVATE_KEY` (+ optionally `GH_KNOWN_HOSTS`) for SSH

Example:

```yaml
environment:
  SYNC_ENABLED: "true"
  SYNC_METHOD: "commits"
  GH_REMOTE: "https://github.com/yourorg/yourrepo.git"
  GH_BRANCH: "main"
  SYNC_HOST_ID: "hexlicsrv-prod-01"
  SYNC_AUTH_TOKEN: "${SYNC_AUTH_TOKEN}"
```

### 3) Releases mode (store chunks as release assets)

Required:
- `SYNC_METHOD=releases`
- `GH_REMOTE`
- `SYNC_HOST_ID`

Optional:
- `GH_RELEASE_TAG` (default service name)
- `GH_RELEASE_NAME`
- `GH_API` and `GH_UPLOAD` for GitHub Enterprise
- `SYNC_AUTH_TOKEN` for creating/updating release assets

Example:

```yaml
environment:
  SYNC_ENABLED: "true"
  SYNC_METHOD: "releases"
  GH_REMOTE: "https://github.com/yourorg/yourrepo.git"
  GH_RELEASE_TAG: "lumina-prod"
  GH_RELEASE_NAME: "Lumina Prod Snapshot"
  SYNC_HOST_ID: "lumina-prod-01"
  SYNC_AUTH_TOKEN: "${SYNC_AUTH_TOKEN}"
```

### 4) Quick check after start

- Read container logs and find lines about `restore`, `checksum`, `uploaded`, or `nothing to upload`.
- If nothing is uploaded, usually it means data hash is unchanged (this is normal).
- In `commits` mode, snapshots are stored in repo files under `backups/<SYNC_HOST_ID>/`.
- In `releases` mode, snapshots are stored as release assets under `GH_RELEASE_TAG`.

## Troubleshooting

- Missing CA files: container exits early. Check `CA/CA.pem` and `CA/CA.key`.
- Permission errors on config: set strict permissions (for example `chmod 600` on config files).
- Sync issues: verify `GH_REMOTE`, token/key, and repository permissions.

## Security Notes

- Never commit tokens, SSH private keys, or CA private keys.
- Do not copy `CA.key` to client workstations.
- Restrict permissions for all secrets and config files.
