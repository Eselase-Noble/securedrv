// =============================================================================
//  key_manager.cpp — Master Key file (.spmk) implementation.
//
//  Key-file layout (all integers little-endian):
//
//    Offset  Size  Field
//    ------  ----  ---------------------------------------------------------
//    0       4     MAGIC = "SPMK"
//    4       1     version (1)
//    5       16    Argon2id salt
//    21      8     opslimit (KDF iterations)
//    29      8     memlimit (KDF memory, bytes)
//    37      24    secretbox nonce
//    61      48    secretbox(MK, KEK) = 32-byte key + 16-byte MAC
//    total   109 bytes
// =============================================================================
#include "securedrv/key_manager.hpp"

#include <sodium.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <vector>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/util.hpp"

namespace securedrv {

namespace {

constexpr std::array<std::uint8_t, 4> kMagic   = {'S', 'P', 'M', 'K'};
constexpr std::uint8_t kVersion                = 1;
constexpr std::size_t  kMkLen                  = crypto_secretbox_KEYBYTES;  // 32
constexpr std::size_t  kWrappedLen             = kMkLen + crypto_secretbox_MACBYTES;

void ensure_sodium() {
    if (sodium_init() < 0) {
        throw CryptoError("sodium_init() failed");
    }
}

/// Map a strength preset onto libsodium's calibrated (opslimit, memlimit) pairs.
void kdf_params(KeyManager::KdfStrength s,
                unsigned long long& ops, std::size_t& mem) {
    switch (s) {
        case KeyManager::KdfStrength::kInteractive:
            ops = crypto_pwhash_OPSLIMIT_INTERACTIVE;
            mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
            break;
        case KeyManager::KdfStrength::kSensitive:
            ops = crypto_pwhash_OPSLIMIT_SENSITIVE;
            mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
            break;
        case KeyManager::KdfStrength::kModerate:
        default:
            ops = crypto_pwhash_OPSLIMIT_MODERATE;
            mem = crypto_pwhash_MEMLIMIT_MODERATE;
            break;
    }
}

/// Derive the Key Encryption Key from a passphrase using Argon2id. The derived
/// key lands in guarded memory so it, too, is protected from swap/dumps.
SecureBuffer derive_kek(const std::string& passphrase,
                        const std::uint8_t* salt,
                        unsigned long long ops, std::size_t mem) {
    SecureBuffer kek(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(kek.data(), kek.size(),
                      passphrase.c_str(), passphrase.size(),
                      salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        // Non-zero here means libsodium could not allocate the required memory.
        throw CryptoError("Argon2id key derivation failed (insufficient memory?)");
    }
    return kek;
}

/// Atomically write `bytes` to `path` and lock it down to owner-only. We write
/// to a temporary file in the same directory then rename, so a crash never
/// leaves a half-written key file in place.
void write_locked_file(const std::string& path,
                       const std::vector<std::uint8_t>& bytes) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw IoError("cannot open key file for writing: " + tmp);
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        if (!f) throw IoError("failed writing key file: " + tmp);
    }
    platform::restrict_to_owner(tmp);  // 0600 before it holds the real name
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) throw IoError("cannot finalise key file: " + ec.message());
    platform::restrict_to_owner(path);
}

/// Serialize a key file from its parts.
std::vector<std::uint8_t> serialize_keyfile(const std::uint8_t* salt,
                                            unsigned long long ops,
                                            std::size_t mem,
                                            const std::uint8_t* nonce,
                                            const std::uint8_t* wrapped) {
    std::vector<std::uint8_t> out;
    util::put_bytes(out, kMagic.data(), kMagic.size());
    out.push_back(kVersion);
    util::put_bytes(out, salt, crypto_pwhash_SALTBYTES);
    util::put_u64(out, ops);
    util::put_u64(out, static_cast<std::uint64_t>(mem));
    util::put_bytes(out, nonce, crypto_secretbox_NONCEBYTES);
    util::put_bytes(out, wrapped, kWrappedLen);
    return out;
}

/// Read and unwrap a key file, returning the Master Key in guarded memory.
SecureBuffer load_keyfile(const std::string& key_path,
                          const std::string& passphrase) {
    std::ifstream f(key_path, std::ios::binary);
    if (!f) throw ConfigError("cannot open master key file: " + key_path);
    std::vector<std::uint8_t> buf((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());

    const std::size_t expected =
        5 + crypto_pwhash_SALTBYTES + 8 + 8 + crypto_secretbox_NONCEBYTES + kWrappedLen;
    if (buf.size() != expected) {
        throw FormatError("master key file has unexpected size");
    }

    std::size_t off = 0;
    std::array<std::uint8_t, 5> prefix{};
    util::get_bytes(buf.data(), buf.size(), off, prefix.data(), prefix.size());
    if (prefix[0] != kMagic[0] || prefix[1] != kMagic[1] ||
        prefix[2] != kMagic[2] || prefix[3] != kMagic[3]) {
        throw FormatError("not a SecureDrv master key file");
    }
    if (prefix[4] != kVersion) {
        throw FormatError("unsupported key file version");
    }

    std::array<std::uint8_t, crypto_pwhash_SALTBYTES> salt{};
    util::get_bytes(buf.data(), buf.size(), off, salt.data(), salt.size());
    unsigned long long ops = util::get_u64(buf.data(), buf.size(), off);
    std::size_t mem = static_cast<std::size_t>(util::get_u64(buf.data(), buf.size(), off));
    std::array<std::uint8_t, crypto_secretbox_NONCEBYTES> nonce{};
    util::get_bytes(buf.data(), buf.size(), off, nonce.data(), nonce.size());
    std::array<std::uint8_t, kWrappedLen> wrapped{};
    util::get_bytes(buf.data(), buf.size(), off, wrapped.data(), wrapped.size());

    SecureBuffer kek = derive_kek(passphrase, salt.data(), ops, mem);
    SecureBuffer mk(kMkLen);
    if (crypto_secretbox_open_easy(mk.data(), wrapped.data(), wrapped.size(),
                                   nonce.data(), kek.data()) != 0) {
        throw IntegrityError("wrong passphrase or corrupted master key file");
    }
    return mk;
}

/// Wrap `mk` under `passphrase` with a fresh salt+nonce and write the key file.
void store_keyfile(const std::string& key_path, const SecureBuffer& mk,
                   const std::string& passphrase, KeyManager::KdfStrength strength) {
    unsigned long long ops = 0;
    std::size_t mem = 0;
    kdf_params(strength, ops, mem);

    std::array<std::uint8_t, crypto_pwhash_SALTBYTES> salt{};
    randombytes_buf(salt.data(), salt.size());
    SecureBuffer kek = derive_kek(passphrase, salt.data(), ops, mem);

    std::array<std::uint8_t, crypto_secretbox_NONCEBYTES> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    std::array<std::uint8_t, kWrappedLen> wrapped{};
    crypto_secretbox_easy(wrapped.data(), mk.data(), mk.size(),
                          nonce.data(), kek.data());

    write_locked_file(key_path,
                      serialize_keyfile(salt.data(), ops, mem, nonce.data(),
                                        wrapped.data()));
}

}  // namespace

bool KeyManager::exists(const std::string& key_path) {
    std::error_code ec;
    return std::filesystem::exists(key_path, ec);
}

void KeyManager::create_master_key(const std::string& key_path,
                                   const std::string& passphrase,
                                   KdfStrength strength) {
    ensure_sodium();
    if (passphrase.empty()) {
        throw ConfigError("refusing to create a master key with an empty passphrase");
    }
    if (exists(key_path)) {
        throw ConfigError("master key already exists: " + key_path +
                          " (refusing to overwrite)");
    }
    // Generate the root secret directly in guarded memory.
    SecureBuffer mk(kMkLen);
    randombytes_buf(mk.data(), mk.size());
    store_keyfile(key_path, mk, passphrase, strength);
}

SecureBuffer KeyManager::load_master_key(const std::string& key_path,
                                         const std::string& passphrase) {
    ensure_sodium();
    return load_keyfile(key_path, passphrase);
}

void KeyManager::change_passphrase(const std::string& key_path,
                                   const std::string& old_passphrase,
                                   const std::string& new_passphrase,
                                   KdfStrength strength) {
    ensure_sodium();
    if (new_passphrase.empty()) {
        throw ConfigError("refusing to set an empty passphrase");
    }
    SecureBuffer mk = load_keyfile(key_path, old_passphrase);  // authenticates old
    store_keyfile(key_path, mk, new_passphrase, strength);     // re-wrap in place
}

}  // namespace securedrv
