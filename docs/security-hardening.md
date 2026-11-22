# Local security hardening

These changes are local to `codex/security-hardening`, based on `077a54c`.
They do not change Linux WeChat version compatibility or implement V2 image keys.

## Privileges and storage

- Initialization scans with elevated read access, clears supplementary groups,
  then drops GID and UID before saving user data. It never recursively changes
  ownership of a user-controlled directory. Direct root sessions without a valid
  sudo caller are refused when saving keys.
- Other Unix commands and the daemon refuse root execution.
- Unix application directories are restricted to 0700. Keys, configuration,
  new decrypted caches, logs and exports use 0600. Existing key/cache files are
  tightened through no-follow file descriptors; linked or foreign-owned files
  are rejected before changing their permissions.
- Keys and exports are written through private temporary files and atomic
  replacement. Existing symlinks are rejected; replacement never modifies a
  hard-link target. Attachment extraction without `--overwrite` uses an atomic
  no-clobber operation instead of relying on a prior existence check.
- The cache index cannot redirect validation or deletion outside the expected
  cache file. Decompression limits each message and its zstd window to 16 MiB;
  oversized compressed data follows the existing decoding-failure fallback.
- macOS LLDB hook files use a randomly named RAII temporary directory instead
  of a predictable PID-based path.

Legacy root-owned state is no longer automatically repaired. Inspect its
ownership manually before migrating it; do not run recursive privileged
ownership changes on untrusted paths. Symlinked application directories are
not supported by this hardening.

These controls protect against other local users and unsafe filesystem links.
Keys and decrypted caches remain plaintext, accessible to the same user and
root. Keep them out of shared directories, repositories and cloud sync.
Windows continues to rely on the account's filesystem ACLs; POSIX mode guarantees
apply only to Unix.

## Dependencies

The lockfile updates rusqlite/SQLCipher (SQLite 3.54.1), OpenSSL, Tokio, anyhow
and zstd to patched releases. Runtime tests check that the linked SQLite is at
least 3.54.0, still provides SQLCipher, and reads a synthetic raw-key encrypted
WAL database in read-only mode.

The OSV version lookup on 2026-11-22 leaves two maintenance notices:

- chrono: RUSTSEC-2026-0543 (unmaintained).
- unsafe-libyaml, via serde_yaml: RUSTSEC-2024-0449 (unmaintained).

These are not claimed to be fixed; migrating date/time and YAML libraries is
separate maintenance work. The YAML library is used for serialization only.
An advisory version match is not proof of reachability, and no version matches
is not proof that software has no vulnerabilities.

## Validation

Use `.build-tools/cargo-local` in this checkout for its isolated Rust toolchain:

```sh
./.build-tools/cargo-local check --locked
./.build-tools/cargo-local test --locked
./.build-tools/cargo-local check --locked --target x86_64-unknown-linux-gnu
./.build-tools/cargo-local build --release --locked
```

All data used by regression tests is synthetic and stored in temporary folders.
Live WeChat initialization is not part of these tests. Full Windows cross-checks
on this Linux host require an MSVC native toolchain (`lib.exe`); checking the
new storage module alone does not replace a full Windows build.
