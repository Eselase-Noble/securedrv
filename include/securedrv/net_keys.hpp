// =============================================================================
//  net_keys.hpp — Key material for secure networked printing.
//
//  Two long-term key types are involved:
//
//    * Server box keypair (X25519) — clients seal each job's data key to the
//      server's PUBLIC key; only the server, holding the SECRET key, can open
//      it. This is what makes delivery end-to-end confidential: nothing on the
//      wire, and no client, can decrypt a job.
//
//    * Client identity keypair (Ed25519) — each client signs the server's
//      per-connection challenge to prove who it is. The server accepts a client
//      only if its public key is on an allowlist.
//
//  Secret keys are held in guarded memory (SecureBuffer) and stored in
//  owner-only files. Public keys are stored/exchanged as hex.
// =============================================================================
#ifndef SECUREDRV_NET_KEYS_HPP
#define SECUREDRV_NET_KEYS_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "securedrv/secure_buffer.hpp"

namespace securedrv::net {

using PublicKey = std::array<std::uint8_t, 32>;  // X25519 or Ed25519 public key

/// A loaded server box keypair (X25519). `sk` is guarded; `pk` is public.
struct ServerBoxKey {
    SecureBuffer sk;   // 32 bytes (crypto_box secret key)
    PublicKey    pk{}; // 32 bytes (crypto_box public key)
    ServerBoxKey() : sk(32) {}
};

/// A loaded client identity keypair (Ed25519). `sk` is guarded (64 bytes).
struct ClientIdentity {
    SecureBuffer sk;   // 64 bytes (crypto_sign secret key)
    PublicKey    pk{}; // 32 bytes (crypto_sign public key)
    ClientIdentity() : sk(64) {}
};

// ---- Generation (writes owner-only key files; returns the public key hex) ----

/// Create the server box keypair at <dir>/server_box.key (0600) and
/// <dir>/server_box.pub (hex). Throws if a key already exists.
std::string create_server_box_key(const std::string& dir);

/// Create the client identity keypair at <dir>/client_sign.key (0600) and
/// <dir>/client_sign.pub (hex). Throws if a key already exists.
std::string create_client_identity(const std::string& dir);

// ---- Loading ----------------------------------------------------------------

ServerBoxKey   load_server_box_key(const std::string& dir);
ClientIdentity load_client_identity(const std::string& dir);

/// Parse a 64-char hex string into a 32-byte public key. Throws on bad input.
PublicKey parse_pubkey_hex(const std::string& hex);

/// Load the newline-separated hex allowlist at <dir>/authorized_clients.
/// Missing file yields an empty list. Blank lines and '#' comments are ignored.
std::vector<PublicKey> load_authorized_clients(const std::string& dir);

/// True if `pk` is present in `allow` (constant-time compare per entry).
bool is_authorized(const std::vector<PublicKey>& allow, const PublicKey& pk);

}  // namespace securedrv::net

#endif  // SECUREDRV_NET_KEYS_HPP
