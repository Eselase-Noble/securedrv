// =============================================================================
//  crypto_engine.hpp — Authenticated, streaming envelope encryption for jobs.
//
//  This is the security core of SecureDrv. It transforms an arbitrary,
//  unbounded print-job byte stream into a self-describing, tamper-evident
//  ".spjob" container and back again.
//
//  Cryptographic design (envelope / hybrid encryption)
//  ---------------------------------------------------
//    * Every job gets a fresh, random 256-bit Data Encryption Key (DEK).
//    * The payload is encrypted under the DEK with libsodium's
//      crypto_secretstream_xchacha20poly1305 — an AEAD *stream* cipher that
//      splits data into authenticated chunks, so we never hold the whole job
//      in memory and any truncation/reordering/bit-flip is detected.
//    * The DEK is then "wrapped" (encrypted) under the long-lived Master Key
//      (MK) with crypto_secretbox. Only the wrapped DEK is stored in the file.
//    * The immutable header fields (magic, version, job id, timestamp, title)
//      are bound into the payload as Additional Authenticated Data (AAD), so
//      the metadata cannot be altered without breaking decryption.
//
//  Why envelope encryption: the expensive-to-protect Master Key never touches
//  bulk data, key rotation only needs to re-wrap small DEKs, and each job is
//  cryptographically isolated from every other job.
// =============================================================================
#ifndef SECUREDRV_CRYPTO_ENGINE_HPP
#define SECUREDRV_CRYPTO_ENGINE_HPP

#include <cstdint>
#include <istream>
#include <ostream>
#include <string>

#include "securedrv/secure_buffer.hpp"

namespace securedrv {

/// Metadata describing a single print job. Stored (authenticated) in the header.
struct JobMetadata {
    std::uint8_t  job_id[16] = {};  ///< Random 128-bit identifier (also the file name).
    std::int64_t  created_unix = 0; ///< Wall-clock creation time (seconds since epoch).
    std::uint64_t original_size = 0;///< Plaintext byte count (informational; 0 if unknown).
    std::string   title;            ///< Human-readable job title / document name.

    /// Return job_id rendered as a 32-character lowercase hex string.
    std::string id_hex() const;
};

/// Stateless engine that encrypts/decrypts job streams under a caller-supplied
/// Master Key. One instance can be reused for many jobs and is thread-compatible
/// (no shared mutable state between calls).
class CryptoEngine {
public:
    /// Plaintext chunk size fed to the stream cipher. 64 KiB balances throughput
    /// against memory use and bounds how much data shares a single AEAD tag.
    static constexpr std::size_t kChunkSize = 64 * 1024;

    CryptoEngine();

    /// Encrypt everything readable from `in` into a complete .spjob container
    /// written to `out`, using `master_key` (must be kMasterKeyBytes long).
    /// `meta` supplies the header; its `original_size` is patched into the
    /// output afterwards when `out` is seekable. Returns the number of plaintext
    /// bytes processed.
    std::uint64_t encrypt_stream(std::istream& in, std::ostream& out,
                                 const SecureBuffer& master_key,
                                 JobMetadata& meta) const;

    /// Decrypt a .spjob container read from `in`, writing recovered plaintext to
    /// `out`. The parsed, authenticated metadata is returned via `meta_out`.
    /// Throws IntegrityError if authentication fails anywhere in the stream.
    void decrypt_stream(std::istream& in, std::ostream& out,
                        const SecureBuffer& master_key,
                        JobMetadata& meta_out) const;

    /// Inspect only the header of a container (no payload decryption) so tools
    /// can list spooled jobs. Still authenticates the wrapped DEK.
    JobMetadata read_metadata(std::istream& in,
                             const SecureBuffer& master_key) const;

    /// Required length, in bytes, of a Master Key (256-bit).
    static std::size_t master_key_bytes();
};

}  // namespace securedrv

#endif  // SECUREDRV_CRYPTO_ENGINE_HPP
