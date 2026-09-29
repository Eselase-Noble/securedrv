# Changelog

All notable changes to Cipherjet are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] — 2026-09-29

### Changed
- Release binaries are now **self-contained on every platform**: libsodium is
  linked statically (built from source for Linux/macOS; static vcpkg triplet on
  Windows), and the Linux build also folds in libstdc++/libgcc. Downloaded
  binaries run with no dependencies to install.

### Added
- `cipherjet-send` reads defaults from `<data-dir>/client.conf`
  (`host` / `port` / `server_key`), so routine use is just
  `cipherjet-send <file>`. A `CIPHERJET_SODIUM_ROOT` CMake option selects a
  static libsodium for self-contained builds.

## [1.1.0] — 2026-09-29

### Added
- **Secure networked printing** (`cipherjet-send` → `cipherjet-server`). Clients
  encrypt jobs end to end, sealed to the server's X25519 public key
  (`crypto_box_seal`), and stream them over TCP to a server that decrypts and
  releases to the printer. Works across different networks — the printer lives
  with the server; clients only need to reach the server's address.
  - Confidentiality is end-to-end (safe even over a plain socket / the internet);
    clients hold no key that can decrypt.
  - Clients authenticate with an Ed25519 signature over a per-connection
    challenge, checked against a server allowlist.
  - Job metadata travels inside the encrypted stream; the session challenge is
    bound as AEAD data to prevent replay.
  - New key commands: `cipherjet-keygen net-server | net-client | net-allow`.
  - Cross-platform TCP layer (BSD sockets / Winsock).

## [1.0.1] — 2026-09-29

### Added
- Windows support: cross-platform libsodium discovery (pkg-config / vcpkg
  `unofficial-sodium` / manual), MSVC-appropriate hardening flags, a Windows CI
  job, and a prebuilt `cipherjet-windows-x86_64.zip` (statically linked, no DLLs)
  attached to releases and offered on the website.

### Fixed
- Mobile navigation: header links were hidden on narrow screens; the masthead
  now stacks so every link stays visible.
- Audit-log tamper test made line-ending safe so it passes on Windows.

## [1.0.0] — 2026-09-28

### Added
- Streaming envelope-encryption engine (`crypto_engine`): per-job 256-bit Data
  Encryption Key wrapped by a Master Key; payload encrypted with
  XChaCha20-Poly1305 in authenticated 64 KiB chunks; job metadata bound as AAD.
- Master-key management (`cipherjet-keygen`): Argon2id-wrapped key file with
  create, load, and passphrase rotation.
- Guarded key memory (`SecureBuffer`): libsodium `sodium_malloc` + `mlock`,
  wiped on free.
- Tamper-evident, BLAKE2b hash-chained append-only audit log.
- Concurrency-safe encrypted job spool (atomic write + rename, random temp names).
- `cipherjet` driver / CUPS backend with device discovery.
- `cipherjet-release`: decrypt/release, list, and audit verification.
- Cross-platform OS abstraction (Linux, macOS, Windows) in a single seam.
- CUPS printer registration scripts (`install/`) exposing
  **Cipherjet (Encrypted)** in the system Print dialog; admin-only release.
- One-command installer (`install.sh`), `Makefile`, and the `cipherjet-print`
  convenience wrapper.
- `--version` on every executable.
- GitHub Actions: CI (build + test on Linux & macOS) and tag-driven Release
  packaging of prebuilt binaries.
- Project website (`docs/`).
- Dependency-free unit test suite (58 checks).

[Unreleased]: https://github.com/Eselase-Noble/securedrv/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/Eselase-Noble/securedrv/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Eselase-Noble/securedrv/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Eselase-Noble/securedrv/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Eselase-Noble/securedrv/releases/tag/v1.0.0
