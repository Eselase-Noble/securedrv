<h1 align="center">Cipherjet</h1>
<p align="center"><em>Encrypted printing, end to end.</em></p>

<p align="center">
  <a href="#build">Build</a> ·
  <a href="#install-as-a-real-printer">Install as a printer</a> ·
  <a href="#command-line-usage">CLI usage</a> ·
  <a href="#security-model">Security</a> ·
  <a href="#architecture">Architecture</a>
</p>

---

**Cipherjet** is a cross-platform, C++17 printer driver that **encrypts every
print job the instant it leaves the application** and only decrypts it at the
point of release to the physical device. Plaintext documents are never written
to disk. It is built on [libsodium](https://libsodium.org) using modern
authenticated, streaming encryption.

> **Threat model in one line:** if an attacker steals the spool, the disk, or a
> backup, they get ciphertext and nothing else — and any tampering is detected.

Cipherjet ships as three small binaries and installs as a normal printer, so
end users just press **⌘P / Ctrl-P** and pick *Cipherjet (Encrypted)*.

| Binary | Role |
|--------|------|
| `cipherjet` | The driver / CUPS backend — encrypts each job into the secure spool |
| `cipherjet-release` | The trusted side — decrypts & releases jobs, lists them, verifies the audit log |
| `cipherjet-keygen` | Master-key management (create / rotate) |

---

## Quick install

**One command** (fetches, builds, installs, and registers the printer):

```bash
curl -fsSL https://raw.githubusercontent.com/Eselase-Noble/securedrv/main/install.sh | bash
```

It installs the build dependencies for your OS (Homebrew / apt / dnf / pacman /
zypper), compiles in Release mode, installs the binaries to `/usr/local/bin`,
and registers **Cipherjet (Encrypted)** as a printer. Add `--no-printer` to skip
the queue, or `--uninstall` to remove everything.

**From a clone**, using `make`:

```bash
git clone https://github.com/Eselase-Noble/securedrv.git && cd securedrv
make            # build
make test       # run the 58-check test suite
make printer    # register the printer (sudo)   — or `make install` for binaries only
```

**Prebuilt binaries:** download a tarball for your platform from the
[Releases](https://github.com/Eselase-Noble/securedrv/releases) page (produced by
CI), unpack, and run `sudo ./install/install-cups-printer.sh`.

---

## Why this design

Printing is a classic data-leak vector: jobs sit in spool directories as
plaintext, often readable by other users, sometimes for a long time. Cipherjet
closes that gap with **envelope encryption**, the pattern used by cloud KMS
systems:

```
  Application
      │  (raw print data on stdin)
      ▼
┌───────────────┐   fresh random DEK per job       ┌──────────────────────┐
│   cipherjet   │ ────────────────────────────────▶│  secure spool        │
│  (the driver) │   payload: XChaCha20-Poly1305     │  <job-id>.spjob      │
└───────────────┘   DEK wrapped by Master Key       │  (ciphertext only)   │
                                                     └──────────┬───────────┘
                                                                │
                                            ┌───────────────────▼───────────────┐
                                            │  cipherjet-release  (admin only)   │
                                            │  decrypt → real printer            │
                                            └────────────────────────────────────┘
```

* **Per-job Data Encryption Key (DEK)** — a fresh 256-bit key for every job, so
  jobs are cryptographically isolated.
* **Master Key (MK)** — the root secret. It only ever *wraps* small DEKs, never
  bulk data. At rest it is protected by an Argon2id-derived key (a memory-hard
  KDF) in an owner-only key file.
* **Streaming AEAD** (`crypto_secretstream_xchacha20poly1305`) — jobs of any
  size are encrypted in authenticated 64 KiB chunks, so nothing is held whole in
  memory and any truncation, reordering, or bit-flip is detected on release.
* **Metadata binding** — the job id, timestamp and title are authenticated as
  Additional Authenticated Data (AAD); they cannot be altered without breaking
  decryption.
* **Tamper-evident audit log** — a BLAKE2b hash-chained, append-only record of
  every encrypt/release event (metadata only, never content).

---

## Cross-platform

The engine is portable C++17 + libsodium and runs on **Linux, macOS and
Windows**. Every OS-specific concern is isolated in one file
(`src/platform.cpp`): binary stdio, owner-only permissions (POSIX `chmod` /
Windows ACLs), and the per-user data directory. The rest of the code has no
`#ifdef`s.

| Platform | How it plugs in |
|----------|-----------------|
| Linux / macOS | A **CUPS backend** — appears in the Print dialog. See below. |
| Windows | A redirected **printer port / port monitor** receiving the job on stdin. |

The same encrypted spool format is used everywhere, so a job encrypted on one
machine can be released on another.

---

## Build

Requires a C++17 compiler, CMake ≥ 3.16, and libsodium.

```bash
# macOS:   brew install libsodium cmake pkg-config
# Debian:  sudo apt install libsodium-dev cmake pkg-config g++
# Windows: vcpkg install libsodium   (configure with the vcpkg toolchain)

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Produces `build/cipherjet`, `build/cipherjet-release`, `build/cipherjet-keygen`.

---

## Install as a real printer

This registers **Cipherjet (Encrypted)** as a printer you can select in any app
(macOS & Linux, via CUPS). The backend runs as root and encrypts into a
root-owned system spool, so **decryption/release is an admin-only operation** —
matching the enterprise model where a trusted operator releases jobs.

```bash
sudo ./install/install-cups-printer.sh
```

Then print from anywhere:

```
⌘P  →  Printer: Cipherjet (Encrypted)  →  Print
# or:
lp -d Cipherjet myfile.pdf
```

Release the encrypted jobs to a real printer (admin):

```bash
sudo cipherjet-admin list
sudo cipherjet-admin release <job-id> | lp -d <your-printer>
sudo cipherjet-admin verify-audit
```

Remove it again:

```bash
sudo ./install/uninstall-cups-printer.sh          # keeps keys/spool
sudo ./install/uninstall-cups-printer.sh --purge  # also deletes them
```

---

## Command-line usage

For power users, scripts, or servers — no installation required. A convenience
wrapper, `bin/cipherjet-print`, ties the tools together with a per-user data
directory and passphrase:

```bash
./bin/cipherjet-print setup                 # one-time: create master key + passphrase
./bin/cipherjet-print print report.pdf      # encrypt into the secure spool
./bin/cipherjet-print list                  # list encrypted jobs
./bin/cipherjet-print release-all           # decrypt + send to default printer
./bin/cipherjet-print audit                 # verify the audit chain
```

Or drive the binaries directly:

```bash
export CIPHERJET_PASSPHRASE='a-strong-passphrase'
cipherjet-keygen init --strength moderate
cat report.ps | cipherjet job-1 alice "Q3 Report" 1 ""
cipherjet-release list
cipherjet-release release <job-id> | lp -d physical_printer
```

### Configuration (environment)

| Variable | Meaning |
|----------|---------|
| `CIPHERJET_PASSPHRASE` | Master-key passphrase (highest priority) |
| `CIPHERJET_PASSPHRASE_FILE` | Path to a file holding the passphrase |
| `CIPHERJET_NEW_PASSPHRASE` | New passphrase for `cipherjet-keygen change` |
| `CIPHERJET_HOME` | Override the data directory |

If none of the first three is set, the passphrase is read from
`~/.config/cipherjet/passphrase` (POSIX) or `%APPDATA%\Cipherjet\passphrase`.

Default data directory:
* Linux/macOS: `$XDG_DATA_HOME/cipherjet` or `~/.local/share/cipherjet`
* Windows: `%APPDATA%\Cipherjet`

---

## Security model

| Property | Mechanism |
|----------|-----------|
| Confidentiality at rest | XChaCha20-Poly1305 payload; DEK wrapped by MK |
| Integrity / tamper detection | Poly1305 tags per chunk; a tampered job fails release and is **preserved** for investigation |
| Key isolation | Unique random DEK per job |
| Master-key protection at rest | Argon2id (memory-hard) + secretbox; owner-only file |
| Keys protected in memory | `sodium_malloc` guarded pages, `mlock` (no swap), wiped on free |
| Metadata authenticity | Header bound as AEAD additional data |
| Auditability | BLAKE2b hash-chained append-only log |
| Safe writes | Atomic temp-file + rename; random temp names (concurrency-safe) |

### Hardening notes / production roadmap
* Replace the passphrase-wrapped key file with an **HSM / OS keystore**
  (macOS Keychain, Windows DPAPI, PKCS#11) — the `KeyManager` interface is
  intentionally small so a backend can drop in.
* **Role separation:** the release tool is the trusted decryptor and should run
  under a dedicated service account with sole access to the master key. The CUPS
  installer already enforces this (release is admin-only).
* For network printing, wrap transport in TLS and authenticate the release side.
* Secure erase is best-effort on copy-on-write / flash media; confidentiality
  rests primarily on encryption, not on overwrite.

---

## Architecture

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
  driver_filter.cpp      `cipherjet`          — driver / CUPS backend
tools/
  release_main.cpp       `cipherjet-release`  — decrypt / release / audit
  keygen_main.cpp        `cipherjet-keygen`   — master-key management
tests/test_main.cpp    Dependency-free unit tests (58 checks)
bin/cipherjet-print    Everyday CLI wrapper
install/               CUPS printer install / uninstall scripts
```

> The internal C++ namespace and include path are `securedrv` (matching this
> repository's name); the product and its binaries are branded **Cipherjet**.

### Container format (`.spjob`)

All integers little-endian.

```
MAGIC "SPJB" | ver(1) | header_len(4) | header | secretstream_header(24) | chunks…
header  = job_id(16) created(8) orig_size(8) title_len(2) title
          dek_nonce(24) dek_wrapped(48)
chunk   = clen(4) ciphertext(clen)      # final chunk carries the FINAL tag
AAD     = MAGIC | ver | job_id | created | title   # bound to the payload
```

See `src/crypto_engine.cpp` for the authoritative, commented implementation.

---

## License

[MIT](LICENSE) © 2026 Eselase-Noble
