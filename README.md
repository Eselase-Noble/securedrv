# SecureDrv — Enterprise Encrypting Printer Driver

SecureDrv is a cross-platform, C++17 printer driver that **encrypts every print
job the moment it leaves the application** and only ever decrypts it at the
point of release to the physical device. Plaintext documents are never written
to disk. It is built on [libsodium](https://libsodium.org) and uses modern
authenticated, streaming encryption throughout.

> Threat model in one line: *if an attacker steals the spool, the disk, or a
> backup, they get ciphertext and nothing else — and any tampering is detected.*

---

## Why this design

Printing is a classic data-leak vector: jobs sit in spool directories as
plaintext, often world-readable, sometimes for a long time. SecureDrv closes
that gap with **envelope encryption**, the same pattern used by cloud KMS
systems:

```
  Application
      │  (raw print data on stdin)
      ▼
┌───────────────┐   fresh random DEK per job      ┌──────────────────────┐
│  securedrv    │ ───────────────────────────────▶│  secure spool        │
│  (the driver) │   payload: XChaCha20-Poly1305    │  <job-id>.spjob      │
└───────────────┘   DEK wrapped by Master Key      │  (ciphertext only)   │
                                                    └──────────┬───────────┘
                                                               │
                                              ┌────────────────▼─────────────┐
                                              │  securedrv-release           │
                                              │  decrypt → real printer      │
                                              └──────────────────────────────┘
```

* **Per-job Data Encryption Key (DEK)** — a fresh 256-bit key for every job, so
  jobs are cryptographically isolated.
* **Master Key (MK)** — the root secret. It only ever *wraps* small DEKs, never
  bulk data. At rest it is protected by an Argon2id-derived key (memory-hard KDF)
  in a `0600` key file.
* **Streaming AEAD** (`crypto_secretstream_xchacha20poly1305`) — jobs of any size
  are encrypted in authenticated 64 KiB chunks, so nothing is held whole in
  memory and any truncation, reordering, or bit-flip is detected on release.
* **Metadata binding** — the job id, timestamp and title are authenticated as
  AAD, so they cannot be altered without breaking decryption.
* **Tamper-evident audit log** — a hash-chained, append-only record of every
  encrypt/release event (metadata only, never content).

---

## Cross-platform

The engine is portable C++17 + libsodium and runs on **Linux, macOS and
Windows**. Every OS-specific concern is isolated in a single file
(`src/platform.cpp`): binary stdio mode, owner-only file permissions
(POSIX `chmod` / Windows ACLs), and the per-user data directory. The rest of the
codebase contains no `#ifdef`s.

| Platform | How the driver is wired in |
|----------|----------------------------|
| Linux / macOS | As a **CUPS filter/backend** — CUPS invokes `securedrv job-id user title copies options [file]`. |
| Windows | As a redirected **printer port / port monitor** program that receives the spooled stream on stdin. |

The same binary works in all three roles; only the surrounding print-system glue
differs.

---

## Project layout

```
include/securedrv/     Public headers (heavily documented)
  errors.hpp             Typed exception hierarchy
  util.hpp               Endian-stable serialization + hex
  secure_buffer.hpp      RAII guarded/locked key memory
  platform.hpp           OS abstraction (the only portable/impl seam)
  crypto_engine.hpp      Envelope + streaming AEAD (the security core)
  key_manager.hpp        Master-key file: create / load / rotate
  audit_log.hpp          Hash-chained tamper-evident log
  spool.hpp              Encrypted job storage
  config.hpp             Path + environment resolution
src/                   Implementations of the above
src/driver_filter.cpp    `securedrv`         — the driver entry point
tools/keygen_main.cpp    `securedrv-keygen`  — master-key management
tools/release_main.cpp   `securedrv-release` — decrypt / release / audit
tests/test_main.cpp      Dependency-free unit tests
```

---

## Build

Requires a C++17 compiler, CMake ≥ 3.16, and libsodium.

```bash
# macOS:   brew install libsodium cmake pkg-config
# Debian:  sudo apt install libsodium-dev cmake pkg-config g++
# Windows: vcpkg install libsodium   (then configure with the vcpkg toolchain)

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Produces `securedrv`, `securedrv-release`, `securedrv-keygen`.

---

## Usage

All tools read configuration from the environment so they deploy identically
everywhere:

| Variable | Meaning |
|----------|---------|
| `SECUREDRV_PASSPHRASE` | Master-key passphrase (**required**) |
| `SECUREDRV_NEW_PASSPHRASE` | New passphrase for `keygen change` |
| `SECUREDRV_HOME` | Optional override of the data directory |

```bash
export SECUREDRV_PASSPHRASE='a-strong-passphrase'

# 1. One-time: create the master key (Argon2id-wrapped, 0600).
securedrv-keygen init --strength moderate

# 2. Encrypt a print job (this is what the print system calls).
cat report.ps | securedrv job-1 alice "Q3 Report" 1 ""

# 3. See what is spooled (authenticated metadata only).
securedrv-release list

# 4. Release a job: decrypt to stdout → pipe to the real device.
securedrv-release release <job-id> | lp -d physical_printer

# 5. Prove the audit trail has not been tampered with.
securedrv-release verify-audit
```

Default data directory:
* Linux/macOS: `$XDG_DATA_HOME/securedrv` or `~/.local/share/securedrv`
* Windows: `%APPDATA%\SecureDrv`

---

## Security properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality at rest | XChaCha20-Poly1305 payload; DEK wrapped by MK |
| Integrity / tamper detection | Poly1305 tags per chunk; release fails and **preserves** a tampered job |
| Key isolation | Unique random DEK per job |
| Master-key protection at rest | Argon2id (memory-hard) + secretbox; `0600` / owner-only ACL |
| Keys protected in memory | `sodium_malloc` guarded pages, `mlock` (no swap), wiped on free |
| Metadata authenticity | Header bound as AEAD additional data |
| Auditability | BLAKE2b hash-chained append-only log |
| Safe writes | Atomic temp-file + rename; random temp names (concurrency-safe) |

### Hardening notes / production roadmap
* Replace the passphrase-wrapped key file with an **HSM / OS keystore**
  (macOS Keychain, Windows DPAPI, PKCS#11) — the `KeyManager` interface is
  deliberately small so a backend can be dropped in.
* Add **role separation**: the release tool is the trusted decryptor and should
  run under a dedicated service account with sole access to the master key.
* For network printing, wrap transport in TLS and authenticate the release side.
* Secure erase is best-effort on copy-on-write/flash media; confidentiality
  rests primarily on encryption, not on overwrite.

---

## Container format (`.spjob`)

All integers little-endian.

```
MAGIC "SPJB" | ver(1) | header_len(4) | header | secretstream_header(24) | chunks…
header  = job_id(16) created(8) orig_size(8) title_len(2) title
          dek_nonce(24) dek_wrapped(48)
chunk   = clen(4) ciphertext(clen)      # final chunk carries the FINAL tag
AAD     = MAGIC | ver | job_id | created | title   # bound to the payload
```

See `src/crypto_engine.cpp` for the authoritative, commented implementation.
