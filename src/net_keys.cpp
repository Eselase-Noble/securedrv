// =============================================================================
//  net_keys.cpp — Networking key material (server box key, client identity).
// =============================================================================
#include "securedrv/net_keys.hpp"

#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/util.hpp"

namespace fs = std::filesystem;

namespace securedrv::net {

namespace {

void ensure_sodium() {
    if (sodium_init() < 0) throw CryptoError("sodium_init() failed");
}

/// Atomically write raw bytes to `path` and lock it to owner-only.
void write_secret(const std::string& path, const std::uint8_t* data, std::size_t len) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw IoError("cannot write key file: " + tmp);
        f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
        if (!f) throw IoError("failed writing key file: " + tmp);
    }
    platform::restrict_to_owner(tmp);
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) throw IoError("cannot finalise key file: " + ec.message());
    platform::restrict_to_owner(path);
}

void write_text(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw IoError("cannot write file: " + path);
    f << text;
}

/// Read exactly `len` bytes of a raw secret directly into guarded memory.
void read_secret(const std::string& path, std::uint8_t* dst, std::size_t len) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw ConfigError("cannot open key file: " + path);
    f.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
    if (static_cast<std::size_t>(f.gcount()) != len) {
        throw FormatError("key file has unexpected size: " + path);
    }
}

std::string p(const std::string& dir, const char* name) {
    return platform::path_join(dir, name);
}

}  // namespace

PublicKey parse_pubkey_hex(const std::string& hex) {
    // Trim surrounding whitespace/newlines.
    std::size_t b = 0, e = hex.size();
    while (b < e && std::isspace(static_cast<unsigned char>(hex[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(hex[e - 1]))) --e;
    std::string h = hex.substr(b, e - b);

    PublicKey pk{};
    std::size_t bin_len = 0;
    if (sodium_hex2bin(pk.data(), pk.size(), h.c_str(), h.size(), nullptr,
                       &bin_len, nullptr) != 0 || bin_len != pk.size()) {
        throw FormatError("invalid 32-byte public key hex");
    }
    return pk;
}

std::string create_server_box_key(const std::string& dir) {
    ensure_sodium();
    const std::string sk_path = p(dir, "server_box.key");
    const std::string pk_path = p(dir, "server_box.pub");
    if (fs::exists(sk_path)) {
        throw ConfigError("server box key already exists: " + sk_path);
    }
    SecureBuffer sk(crypto_box_SECRETKEYBYTES);
    PublicKey pk{};
    crypto_box_keypair(pk.data(), sk.data());
    write_secret(sk_path, sk.data(), sk.size());
    std::string hex = util::to_hex(pk.data(), pk.size());
    write_text(pk_path, hex + "\n");
    return hex;
}

std::string create_client_identity(const std::string& dir) {
    ensure_sodium();
    const std::string sk_path = p(dir, "client_sign.key");
    const std::string pk_path = p(dir, "client_sign.pub");
    if (fs::exists(sk_path)) {
        throw ConfigError("client identity already exists: " + sk_path);
    }
    SecureBuffer sk(crypto_sign_SECRETKEYBYTES);  // 64
    PublicKey pk{};
    crypto_sign_keypair(pk.data(), sk.data());
    write_secret(sk_path, sk.data(), sk.size());
    std::string hex = util::to_hex(pk.data(), pk.size());
    write_text(pk_path, hex + "\n");
    return hex;
}

ServerBoxKey load_server_box_key(const std::string& dir) {
    ensure_sodium();
    ServerBoxKey k;
    read_secret(p(dir, "server_box.key"), k.sk.data(), k.sk.size());
    // Derive the public key from the secret (X25519), so the .pub file is only
    // for distribution and never a source of truth.
    if (crypto_scalarmult_base(k.pk.data(), k.sk.data()) != 0) {
        throw CryptoError("failed to derive server public key");
    }
    return k;
}

ClientIdentity load_client_identity(const std::string& dir) {
    ensure_sodium();
    ClientIdentity id;
    read_secret(p(dir, "client_sign.key"), id.sk.data(), id.sk.size());
    if (crypto_sign_ed25519_sk_to_pk(id.pk.data(), id.sk.data()) != 0) {
        throw CryptoError("failed to derive client public key");
    }
    return id;
}

std::vector<PublicKey> load_authorized_clients(const std::string& dir) {
    std::vector<PublicKey> out;
    std::ifstream f(p(dir, "authorized_clients"), std::ios::binary);
    if (!f) return out;  // No allowlist yet.
    std::string line;
    while (std::getline(f, line)) {
        // Skip blank lines and '#' comments.
        std::size_t b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos || line[b] == '#') continue;
        out.push_back(parse_pubkey_hex(line));
    }
    return out;
}

bool is_authorized(const std::vector<PublicKey>& allow, const PublicKey& pk) {
    for (const auto& a : allow) {
        if (sodium_memcmp(a.data(), pk.data(), pk.size()) == 0) return true;
    }
    return false;
}

}  // namespace securedrv::net
