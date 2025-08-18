# IDATeamsDocker
Docker configuration (and only docker configuration) files for hosting self-hosted Hexvault, Lumina and Hexlicsrv. The installation files should be in `./image` folders.

Supported version:
1. [IDA 9.0.240925 September 30, 2024](https://docs.hex-rays.com/release-notes/9_0)

---

## CA (NOTE)
Before you start doing anything, you need to generate your own CA certificate. This can be done like this:
```bash
openssl req -x509 \
    -newkey rsa:4096 -sha512 -keyout CA.key -out CA.pem -days 3650 -nodes \
    -subj "/C=BE/L=Liège/O=Hex-Rays SA./CN=Hex-Rays SA. Root CA"
```
Now you have two files (the key and the certificate itself), you need to place these two files in the CA folders (`./CA`). Also you need to replace the CA in IDA itself, which is done in another step below.

---

## IDA preparing
1. Create a CA folder in the root (`C:\Program Files\IDA Professional 9.0\CA`)
2. Copy `CA.key` and `CA.pem` to the previously created folder
3. Copy the Python script (`license_patch.py`) to the root
4. Run script as administrator (`python3 license_patch.py ida-pro`)
5. Enjoy

---

## Hexvault hosting
1. `cd ./hexvault`
2. Copy `hexvault90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `VAULT_HOST` for TLS)
5. `sudo docker-compose up -d --build`
6. Enjoy

> **Optional**: see the **GitHub Sync** section below to enable automatic backup/restore of `./data` to a Git repository.

---

## Lumina hosting
1. `cd ./lumina`
2. Copy `lumina90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `LUMINA_HOST` for TLS)
5. `sudo docker-compose up -d --build`
6. Enjoy

> **Optional**: see the **GitHub Sync** section below to enable automatic backup/restore of `./data` to a Git repository.

---

## Hexlicsrv hosting
1. `cd ./hexlicsrv`
2. Copy `hexlicsrv90_x64linux.run` into `./image`
3. Copy `CA.key` and `CA.pem` to the CA folder (`./CA`)
4. Edit `docker-compose.yml`. (You need to edit `LICENSE_HOST` for TLS)
5. `sudo docker-compose up -d --build`
6. Enjoy

> **Optional**: see the **GitHub Sync** section below to enable automatic backup/restore of `./data` to a Git repository.

---

## GitHub Sync (optional, recommended)

The containers can optionally back up and restore their **data directory** from a Git repository.  
This is especially useful to bootstrap a new node (restore when empty) and to keep an off-site history of data snapshots.

### What it does
- On container start:
  - If the local `data/` is **empty** and the remote repo contains a snapshot, the container **restores** from Git.
  - If the local `data/` is **not empty**, the container **packages** it, **splits** into ≤ *N* MB parts, and **pushes** to Git **only if changed** (by SHA-256).
- Packaging format: `tar` → `zstd -19` → `data.tar.zst` → `split` into `data.tar.zst.part_000`, `..._001`, etc.
- Metadata is saved in `manifest.json` with fields like `archive_sha256`, `chunk_count`, `timestamp_utc`, etc.
- Remote layout: `backups/<GIT_HOST_ID>/data.tar.zst.part_***` + `manifest.json`.

> **GitHub’s file size limit** is 50 MB. By default we use `GIT_CHUNK_SIZE_MB=49`.

### Enable it (Hexvault example)
Uncomment and set the environment variables in `./hexvault/docker-compose.yml`:

```yaml
services:
  hexvault:
    environment:
      # App
      VAULT_HOST: reversing.example.com
      VAULT_PORT: "65433"

      # --- Git sync ---
      GIT_SYNC_ENABLED: "true"
      GIT_REMOTE: https://github.com/<USERNAME>/<REPO>.git # or SSH form: git@github.com:<USERNAME>/<REPO>.git
      GIT_BRANCH: main
      GIT_HOST_ID: hexvault # logical node id for backups/<GIT_HOST_ID>
      GIT_CHUNK_SIZE_MB: "49"

      # Commit identity
      GIT_COMMIT_NAME: HexVault CI
      GIT_COMMIT_EMAIL: hexvault@example.com

      # (Option A) HTTPS with fine-grained Personal Access Token (PAT)
      # GIT_AUTH_TOKEN: github_pat_...

      # (Option B) SSH
      # GIT_SSH_PRIVATE_KEY: |-
      #   -----BEGIN OPENSSH PRIVATE KEY-----
      #   ...
      #   -----END OPENSSH PRIVATE KEY-----
      # GIT_KNOWN_HOSTS: github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

Then:
```bash
cd ./hexvault
sudo docker-compose up -d --build
```

> **Security tips**
> - Do **not** commit your PAT or private key to the repo. Prefer Docker secrets or environment injection in CI/ops.
> - For SSH, either provide `GIT_KNOWN_HOSTS` (strict) or the entrypoint will use `StrictHostKeyChecking=no`.

### PAT vs SSH quick start

**HTTPS + PAT**
1. Create a private repo (recommended).
2. Create a fine-grained PAT with **Contents: Read and Write** for that repo.
3. Set:
   - `GIT_REMOTE=https://github.com/<USER>/<REPO>.git`
   - `GIT_AUTH_TOKEN=github_pat_...`
4. Bring the container up.

**SSH**
1. Generate a deploy key (`ssh-keygen -t ed25519 -C "hexvault-ci"`), add the **public** key as a deploy key with write access.
2. Set:
   - `GIT_REMOTE=git@github.com:<USER>/<REPO>.git`
   - `GIT_SSH_PRIVATE_KEY=<your private key content>`
   - (Optionally) `GIT_KNOWN_HOSTS="github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."`
3. Bring the container up.

### How to verify it works
- On first start with **empty** `./hexvault/data` and a **remote snapshot** present:
  - The container will **assemble** parts from `backups/<GIT_HOST_ID>/` and extract into `/opt/hexvault/data`.
- With **non-empty** local data:
  - The container will create `data.tar.zst`, split into `*.part_***`, compute `SHA-256`, write `manifest.json`, commit and push **only if** the hash differs from the remote manifest.

You can confirm by checking your Git repo:
```
backups/
  hexvault/                     # GIT_HOST_ID
    data.tar.zst.part_000
    data.tar.zst.part_001
    ...
    manifest.json
```

### Forcing behaviors
- **Force a fresh push**: delete `backups/<GIT_HOST_ID>/` in the repo (or bump `GIT_HOST_ID`), then restart the container.
- **Force restore**: ensure the local `./hexvault/data` is empty and that the remote snapshot exists.
- **Change chunk size**: tweak `GIT_CHUNK_SIZE_MB` (stay ≤ 49 for GitHub).

---

## NOTE on schema lock files
The `*_schema.lock` flag file is an indicator to the container when it is time to run a schema recreate using `--recreate-schema`. As long as this file exists, the container will not run a schema recreate.

---

## Troubleshooting Git FS Sync

- **Missing tool: <name>**  
  The entrypoint requires: `git`, `ssh-keyscan`, `tar`, `zstd`, `jq`, `sha256sum`, `split`, `openssl`. Install them in the image.

- **Auth failed / permission denied**  
  Check `GIT_REMOTE`, token/SSH key validity, and that the repo exists and is writable. For SSH, verify `GIT_KNOWN_HOSTS` or disable strict checking (less secure).

- **Checksum mismatch on restore**  
  The assembled archive’s `sha256` doesn’t match `manifest.json`. Re-push a clean snapshot: remove remote parts + manifest, restart to re-create from local data.

- **No changes to commit**  
  This is normal if `archive_sha256` matches the remote; the entrypoint skips pushing identical snapshots.

- **Hitting GitHub 50 MB limit**  
  Keep `GIT_CHUNK_SIZE_MB` ≤ 49 (default). The packer always splits; do not commit `data.tar.zst` directly to the repo root.

---

## `shell.reg`
This file adds support for opening IDA with the right mouse button in Windows.
