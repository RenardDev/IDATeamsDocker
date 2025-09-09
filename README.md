# IDATeamsDocker

Docker configuration for hosting **HexVault**, **Lumina**, and **HexLicSrv**.  
Installer files go into each service’s `./<service>/image` folder.

Supported version:

- [IDA 9.0.240925 - September 30, 2024](https://docs.hex-rays.com/release-notes/9_0)
- [IDA 9.1.250226 - February 28, 2025](https://docs.hex-rays.com/release-notes/9_1)
- [IDA 9.2.250908 - September 8, 2025](https://docs.hex-rays.com/release-notes/9_2)

---

## Repository layout

```
.
├─ docker-compose.yml              # runs all services (hexlicsrv, hexvault, lumina + mysql)
├─ hexlicsrv/
│  ├─ image/                       # put hexlicsrv installer here (e.g., hexlicsrv_x64linux.run)
│  ├─ CA/                          # CA.pem + CA.key
│  ├─ config/                      # persistent config (mounted)
│  ├─ data/                        # persistent data (mounted)
│  └─ logs/                        # persistent logs (mounted)
├─ hexvault/
│  ├─ image/                       # put hexvault installer here (e.g., hexvault_x64linux.run)
│  ├─ CA/  config/  data/  logs/
└─ lumina/
   ├─ image/                       # put lumina installer here (e.g., lumina_x64linux.run)
   ├─ CA/  config/  data/  logs/
   └─ mysql/                       # MySQL persistent volume
```

---

## Prerequisites

- Linux host with Docker and Docker Compose
- Your own internal Certificate Authority (CA) pair: `CA.pem` (cert) and `CA.key` (private key)
- For **Lumina**: MySQL 8 (provided by the included `mysql` service)

---

## Generate your CA (required)

Create a CA once and place it **into every service’s `CA/` folder**:

```bash
openssl req -x509 \
    -newkey rsa:4096 -sha512 -keyout CA.key -out CA.pem -days 3650 -nodes \
    -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```

> The containers refuse to start if `CA/CA.pem` or `CA/CA.key` is missing.

---

## Prepare your IDA client

1. Create `C:\Program Files\IDA Professional 9.0\CA`
2. Copy your `CA.key` and `CA.pem` into that folder
3. Copy `license_patch.py` into the IDA install root
4. Run as Administrator:
   ```bash
   python3 license_patch.py ida-pro
   ```
5. Start IDA

---

## Running with Docker Compose (recommended)

The provided top-level `docker-compose.yml` brings up all services:

- **hexlicsrv** --> port **65434**
- **hexvault** --> port **65433**
- **mysql** for **lumina**
- **lumina** --> port **443**

### 1) Put installers into image folders

- `hexlicsrv/image/hexlicsrv_x64linux.run`
- `hexvault/image/hexvault_x64linux.run`
- `lumina/image/lumina_x64linux.run`

### 2) Put CA into each service

Copy `CA.key` and `CA.pem` into:

- `hexlicsrv/CA/`
- `hexvault/CA/`
- `lumina/CA/`

### 3) Adjust hostnames (TLS SAN)

Edit environment in `docker-compose.yml`:

- `LICENSE_HOST` for **hexlicsrv**
- `VAULT_HOST` for **hexvault**
- `LUMINA_HOST` for **lumina**

These become the **CN/SAN** in the auto-issued service certificates.

### 4) Bring everything up

```bash
docker compose up -d --build
```

> The entrypoints run `license_patch.py` inside each container automatically.

---

## Service-specific notes

### HexLicSrv
- Mounts: `./hexlicsrv/{CA,config,data,logs}` --> `/opt/hexlicsrv/...`
- Config file auto-generated at first start: `config/hexlicsrv.conf`

### HexVault
- Mounts: `./hexvault/{CA,config,data,logs}` --> `/opt/hexvault/...`
- Config file auto-generated at first start: `config/hexvault.conf`

### Lumina
- Depends on the `mysql` service (health-checked)
- DB env must match `mysql` service:
  - `MYSQL_HOST=mysql`, `MYSQL_PORT=3306`, `MYSQL_DATABASE=lumina`, `MYSQL_USER=lumina`, `MYSQL_PASSWORD=lumina`
- Mounts: `./lumina/{CA,config,data,logs}` --> `/opt/lumina/...`
- Config file auto-generated at first start: `config/lumina.conf`

---

## Unified GitHub Sync (optional but recommended)

All three services can **backup/restore** their state to GitHub in one of two modes:

- **commits**: push chunks + `manifest.json` into a branch under `backups/<SYNC_HOST_ID>/`
- **releases**: upload chunks + `manifest.json` as **release assets** of a tag

### How it works (on container start)

- If local data is **empty** and a remote snapshot exists --> **restore**
- Else package local state and **push only if changed** (SHA-256 compare)

### Packaging

- **HexLicSrv / HexVault:** `tar` --> `zstd -19` --> `data.tar.zst` --> split --> `data.tar.zst.part_000`, `...001`, ...
- **Lumina:** `mysqldump` --> `zstd -19` --> `dump.sql.zst` --> split --> `dump.sql.zst.part_000`, ...

`manifest.json` stores (among others): `archive_sha256`, `chunk_count`, `chunk_size_mb`, `timestamp_utc`.

> Keep `SYNC_CHUNK_SIZE_MB ≤ 49` for GitHub’s 50 MB file limit in repos (default is `49`).

### Enable sync

In `docker-compose.yml`, per service set:

```yaml
environment:
  SYNC_ENABLED: "true"                 # enable sync
  SYNC_METHOD: "releases"              # or "commits"
  GH_REMOTE: https://github.com/yourorg/yourrepo.git  # or SSH: git@github.com:yourorg/yourrepo.git
  SYNC_HOST_ID: "hexvault"             # logical node id, used in path under commits mode
  SYNC_CHUNK_SIZE_MB: "49"

  # For write access / private repos or releases:
  # SYNC_AUTH_TOKEN: github_pat_token_here

  # Commits mode (optional identity)
  # GH_BRANCH: main
  # GH_COMMIT_NAME: HexVault CI
  # GH_COMMIT_EMAIL: hexvault@example.com
  # GH_SSH_PRIVATE_KEY: |-
  #   -----BEGIN OPENSSH PRIVATE KEY-----
  #   ...
  # GH_KNOWN_HOSTS: |-
  #   github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...

  # Releases mode
  # GH_RELEASE_TAG: hexvault
  # GH_RELEASE_NAME: HexVault
  # GH_API: https://ghe.example.com/api/v3         # for GHE
  # GH_UPLOAD: https://ghe.example.com/api/uploads # for GHE
```

> **PAT vs SSH**: For HTTPS URLs set `SYNC_AUTH_TOKEN` (Bearer for releases, x-access-token for commits). For SSH, provide `GH_SSH_PRIVATE_KEY` and optionally `GH_KNOWN_HOSTS`.

---

## Schema lock files

A `*_schema.lock` file prevents schema recreation on subsequent boots.  
Delete the lock if you intentionally want the service to run `--recreate-schema` again.

---

## Troubleshooting

- **World-accessible config (HexLicSrv)**  
  **Symptom:**  
  `File "/opt/hexlicsrv/config/hexlicsrv.conf" is world-accessible; exiting`  
  **Fix:**  
  ```bash
  chmod 600 config/hexlicsrv.conf
  ```

- **World-accessible config (HexVault)**  
  **Symptom:**  
  `File "/opt/hexvault/config/hexvault.conf" is world-accessible; exiting`  
  **Fix:**  
  ```bash
  chmod 600 config/hexvault.conf
  ```

- **Missing tools**  
  Images must include: `git`, `ssh-keyscan`, `curl`, `tar`, `zstd`, `jq`, `sha256sum`, `split`, `openssl`, and for Lumina also `mysql`, `mysqldump`, `nc`.

- **Auth / permissions fail**  
  Verify `GH_REMOTE`, token/SSH key validity, and repo access. For SSH, either supply `GH_KNOWN_HOSTS` or the entrypoint will disable strict host checking (less secure).

- **Checksum mismatch on restore**  
  Means the assembled archive’s SHA-256 differs from `manifest.json`.  
  Fix by republishing a clean snapshot (run with `SYNC_AUTH_TOKEN` so the container uploads a fresh manifest and parts), or remove release/branch assets and let the container recreate them.

- **No changes to commit**  
  Normal when the computed SHA-256 equals the remote manifest; nothing is pushed.

---

## Windows `shell.reg`

Adds a context-menu entry to open files with IDA on Windows.

--- 

## Security notes

- Never commit tokens or private keys. Use Docker secrets, env injection in CI, or a secrets manager.
- Your CA private key is sensitive; restrict filesystem permissions and repo access accordingly.
