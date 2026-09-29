// =============================================================================
//  net_crypto.hpp — End-to-end sealed print jobs for network delivery.
//
//  A "sealed job" (.spnj) is the on-the-wire form of a print job. Unlike the
//  local .spjob (whose data key is wrapped with the symmetric master key), the
//  network form seals the per-job data key to the SERVER'S public key with
//  crypto_box_seal. Only the server, holding the matching secret key, can open
//  it — so the job is confidential end to end, even over a plain socket, and no
//  client ever holds a key that can decrypt.
//
//  All metadata (title, timestamp) travels INSIDE the encrypted stream, so the
//  wire exposes only a random job id and the ciphertext sizes. A caller-supplied
//  32-byte context (the server's per-connection challenge) is bound to the first
//  chunk as authenticated data, so a captured job cannot be replayed into a
//  different session.
//
//  I/O is expressed as simple source/sink callbacks so the same code streams
//  over a socket or to/from a file without buffering the whole job.
// =============================================================================
#ifndef SECUREDRV_NET_CRYPTO_HPP
#define SECUREDRV_NET_CRYPTO_HPP

#include <cstdint>
#include <functional>
#include <string>

#include "securedrv/net_keys.hpp"

namespace securedrv::net {

/// Writes exactly `len` bytes; must consume them all (throws on failure).
using ByteSink = std::function<void(const std::uint8_t* data, std::size_t len)>;

/// Fills up to `len` bytes into `buf`; returns the count read. A return of 0
/// means end-of-input. A partial (0 < n < len) read is allowed only when more
/// data may still follow — implementations MUST return 0 solely at true EOF.
using ByteSource = std::function<std::size_t(std::uint8_t* buf, std::size_t len)>;

/// Parsed, authenticated metadata recovered by open_job().
struct SealedJobMeta {
    std::uint8_t job_id[16] = {};
    std::int64_t created_unix = 0;
    std::string  title;
    std::uint64_t plaintext_bytes = 0;  ///< Total decrypted payload size.
    std::string id_hex() const;
};

/// Size of the per-connection replay-binding context.
inline constexpr std::size_t kContextBytes = 32;

/// Read plaintext from `in`, seal it to `server_pk`, and write the .spnj
/// container to `out`. `context` (kContextBytes) binds the job to a session.
/// The generated job id is returned via `job_id_out`. Returns plaintext bytes.
std::uint64_t seal_job(ByteSource in, ByteSink out,
                       const PublicKey& server_pk,
                       const std::uint8_t context[kContextBytes],
                       const std::string& title, std::int64_t created_unix,
                       std::uint8_t job_id_out[16]);

/// Read a .spnj container from `in`, open it with the server keypair, and write
/// the recovered plaintext to `out`. `context` must match the value used when
/// sealing. Throws IntegrityError on any authentication failure (wrong server,
/// tampering, or a replay under a different context).
void open_job(ByteSource in, ByteSink out, const ServerBoxKey& server,
              const std::uint8_t context[kContextBytes], SealedJobMeta& meta_out);

}  // namespace securedrv::net

#endif  // SECUREDRV_NET_CRYPTO_HPP
