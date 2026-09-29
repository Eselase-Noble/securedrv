# Changelog

All notable changes to Cipherjet are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Windows support: cross-platform libsodium discovery (pkg-config / vcpkg
  `unofficial-sodium` / manual), MSVC-appropriate hardening flags, a Windows CI
  job, and a prebuilt `cipherjet-windows-x86_64.zip` (statically linked, no DLLs)
  attached to releases and offered on the website.

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

[Unreleased]: https://github.com/Eselase-Noble/securedrv/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Eselase-Noble/securedrv/releases/tag/v1.0.0
