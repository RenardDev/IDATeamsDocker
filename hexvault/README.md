# HexVault container

Place `hexvault_x64linux.run` in `image/`, and place the CA certificate and
private key in `CA/CA.pem` and `CA/CA.key`. The CA key is mounted into a
root-only runtime directory; `vault_server` itself runs as the unprivileged
`hexvault` user. Secret Service keyrings persist in the host-side `keyrings/`
directory and are not kept in the container's writable layer. The stock
Compose configuration requires both CA files on every start so it can renew
the leaf certificate. Leaf key/certificate rotation is staged, validated, and
protected by a persistent recovery marker before either final file is replaced.

On a genuinely empty SQLite database, `VAULT_PASSWORD` is required. The
schema is recreated first, the presence of user `hexvault` is verified, and
that user is promoted with `--set-admin` immediately afterward. Existing or
restored valid databases are never recreated and their admin password is not
reset. The canonical version plus deterministic live-schema fingerprint is
root-owned in `recovery/`; the service user cannot rewrite it. On an
image schema upgrade, HexVault first creates an SQLite online backup, runs the
vendor `--upgrade-schema` command, validates the result, and rolls the database
back if the upgrade fails. Both an interrupted upgrade and an interrupted
fresh schema recreation are recovered before startup sync is allowed to run.
Newer schema versions are rejected before an older image can mutate them.

The host-side `recovery/` directory is deliberately separate from synced
application data. Before restore mutates the bind mount, it durably records a
transaction marker and a copy of both the original data and canonical schema
identity. The rollback remains until restored-schema compatibility succeeds.
An interrupted restore is rolled back before schema handling or network sync;
failed emergency recovery preserves its marker and data for manual repair.

## Sync

Set `SYNC_ENABLED=true`, `GH_REMOTE`, and a random
`SYNC_ENCRYPTION_PASSPHRASE` of at least 20 characters. Write mode also
requires a token for Releases/HTTPS commits or a private key plus pinned host
keys for SSH commits. Anonymous public downloads are accepted only with
`SYNC_READ_ONLY=true`. Snapshots use
authenticated AES-256 GPG encryption plus an
authenticated manifest containing schema version/fingerprint. Live snapshots
copy the object store only between two identical online SQLite backups; a
concurrent DB commit causes a bounded retry instead of an inconsistent publish.

Startup sync is restore-only. Schema initialization/upgrade runs next, followed
by the first publish. Periodic snapshots use `SYNC_INTERVAL_SECONDS` (default:
3600; set to `0` to disable them). A bounded final snapshot is attempted only
after an explicit graceful shutdown. `SYNC_LOCK_TIMEOUT_SECONDS` and
`SYNC_FINAL_TIMEOUT_SECONDS` bound shutdown work.

GitHub Release snapshots are host-namespaced and versioned; chunks are uploaded
before the manifest, so an interrupted upload does not replace the last valid
snapshot. Restore tries authenticated generations newest-to-oldest when a
manifest is valid but its payload is incomplete/corrupt. Authentication,
future-schema, and transport failures remain fatal to that sync attempt. A
no-op is accepted only after downloading and authenticating all chunks.
`SYNC_RELEASE_KEEP` controls retention.

Set `SYNC_READ_ONLY=true` for restore-only operation. A PAT or deploy key can
still authenticate reads from a private remote, but release creation, commits,
uploads, periodic sync, and shutdown sync are disabled.

For SSH remotes, `GH_KNOWN_HOSTS` is mandatory; automatic host-key acceptance
is intentionally disabled. `SYNC_FORCE_RESTORE` is a one-start override and
should normally remain `false`.
