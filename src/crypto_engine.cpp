// =============================================================================
//  crypto_engine.cpp — Implementation of streaming envelope encryption.
//
//  On-disk ".spjob" container layout (all integers little-endian):
//
//    Offset  Size  Field
//    ------  ----  ---------------------------------------------------------
//    0       4     MAGIC = "SPJB"
//    4       1     format version (currently 1)
//    5       4     header_len = byte length of the header block below
//    9       H     header block:
//                     job_id            16 bytes
//                     created_unix       8 bytes
//                     original_size      8 bytes   (patched after streaming)
//                     title_len          2 bytes
//                     title              title_len bytes (UTF-8)
//                     dek_wrap_nonce    24 bytes   (secretbox nonce)
//                     dek_wrapped       48 bytes   (secretbox(DEK) = 32+16 MAC)
//    9+H     24    secretstream header
//    ...           payload chunks, each: { u32 clen; clen ciphertext bytes }
//                  The final chunk carries the stream's FINAL tag.
//
//  The tuple (MAGIC, version, job_id, created_unix, title) is passed as AAD to
//  the first secretstream chunk, cryptographically binding the metadata to the
//  payload. original_size is intentionally excluded from the AAD because it is
//  back-patched once the full plaintext length is known.
// =============================================================================
#include "securedrv/crypto_engine.hpp"

#include <sodium.h>

#include <array>
#include <vector>

#include "securedrv/errors.hpp"
#include "securedrv/util.hpp"

namespace securedrv {

namespace {

// --- Container constants ------------------------------------------------------
constexpr std::array<std::uint8_t, 4> kMagic = {'S', 'P', 'J', 'B'};
constexpr std::uint8_t  kVersion            = 1;
constexpr std::size_t   kDekWrappedLen      = crypto_secretbox_KEYBYTES +
                                              crypto_secretbox_MACBYTES;  // 48
// Absolute file offset of the 8-byte original_size field (see layout table).
constexpr std::streamoff kOriginalSizeOffset = 4 + 1 + 4 + 16 + 8;        // 33

/// Initialise libsodium exactly once per process. Safe to call repeatedly and
/// from multiple threads; sodium_init() is idempotent and returns 1 if already
/// initialised, 0 on first success, and a negative value on failure.
void ensure_sodium() {
    if (sodium_init() < 0) {
        throw CryptoError("sodium_init() failed to initialise the library");
    }
}

/// Build the Additional Authenticated Data that binds header metadata to the
/// encrypted payload. Must be reconstructed identically on decrypt.
std::vector<std::uint8_t> build_aad(const JobMetadata& meta) {
    std::vector<std::uint8_t> aad;
    util::put_bytes(aad, kMagic.data(), kMagic.size());
    aad.push_back(kVersion);
    util::put_bytes(aad, meta.job_id, sizeof(meta.job_id));
    util::put_u64(aad, static_cast<std::uint64_t>(meta.created_unix));
    util::put_u16(aad, static_cast<std::uint16_t>(meta.title.size()));
    util::put_bytes(aad,
                    reinterpret_cast<const std::uint8_t*>(meta.title.data()),
                    meta.title.size());
    return aad;
}

/// Serialize the header block (everything counted by header_len).
std::vector<std::uint8_t> serialize_header(const JobMetadata& meta,
                                           const std::uint8_t* dek_nonce,
                                           const std::uint8_t* dek_wrapped) {
    if (meta.title.size() > 0xFFFF) {
        throw FormatError("job title exceeds 65535 bytes");
    }
    std::vector<std::uint8_t> h;
    util::put_bytes(h, meta.job_id, sizeof(meta.job_id));
    util::put_u64(h, static_cast<std::uint64_t>(meta.created_unix));
    util::put_u64(h, meta.original_size);
    util::put_u16(h, static_cast<std::uint16_t>(meta.title.size()));
    util::put_bytes(h,
                    reinterpret_cast<const std::uint8_t*>(meta.title.data()),
                    meta.title.size());
    util::put_bytes(h, dek_nonce, crypto_secretbox_NONCEBYTES);
    util::put_bytes(h, dek_wrapped, kDekWrappedLen);
    return h;
}

/// Read a fixed number of bytes or throw. istream::read is all-or-nothing here:
/// a short read means a truncated/corrupt container.
void read_exact(std::istream& in, std::uint8_t* dst, std::size_t len) {
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
    if (static_cast<std::size_t>(in.gcount()) != len) {
        throw FormatError("unexpected end of container (truncated)");
    }
}

/// Parse magic + version + header block from `in`. Returns the metadata plus the
/// wrapped-DEK material needed to derive the payload key. `master_key` is used
/// to unwrap (and thereby authenticate) the DEK, which is returned via `dek`.
JobMetadata parse_and_unwrap(std::istream& in, const SecureBuffer& master_key,
                             SecureBuffer& dek) {
    // Magic + version.
    std::array<std::uint8_t, 5> prefix{};
    read_exact(in, prefix.data(), prefix.size());
    if (prefix[0] != kMagic[0] || prefix[1] != kMagic[1] ||
        prefix[2] != kMagic[2] || prefix[3] != kMagic[3]) {
        throw FormatError("bad magic — not a SecureDrv job container");
    }
    if (prefix[4] != kVersion) {
        throw FormatError("unsupported container version " +
                          std::to_string(prefix[4]));
    }

    // Header block.
    std::array<std::uint8_t, 4> hlen_bytes{};
    read_exact(in, hlen_bytes.data(), 4);
    std::size_t off = 0;
    std::uint32_t header_len = util::get_u32(hlen_bytes.data(), 4, off);
    // Guard against absurd allocations from a malformed length field.
    if (header_len < sizeof(JobMetadata::job_id) + 8 + 8 + 2 +
                         crypto_secretbox_NONCEBYTES + kDekWrappedLen ||
        header_len > (1u << 20)) {
        throw FormatError("implausible header length");
    }
    std::vector<std::uint8_t> hbuf(header_len);
    read_exact(in, hbuf.data(), header_len);

    // Deserialize header fields.
    JobMetadata meta;
    off = 0;
    util::get_bytes(hbuf.data(), header_len, off, meta.job_id, sizeof(meta.job_id));
    meta.created_unix  = static_cast<std::int64_t>(util::get_u64(hbuf.data(), header_len, off));
    meta.original_size = util::get_u64(hbuf.data(), header_len, off);
    std::uint16_t title_len = util::get_u16(hbuf.data(), header_len, off);
    if (off + title_len > header_len) throw FormatError("title overruns header");
    meta.title.assign(reinterpret_cast<const char*>(hbuf.data() + off), title_len);
    off += title_len;

    std::array<std::uint8_t, crypto_secretbox_NONCEBYTES> dek_nonce{};
    std::array<std::uint8_t, kDekWrappedLen> dek_wrapped{};
    util::get_bytes(hbuf.data(), header_len, off, dek_nonce.data(), dek_nonce.size());
    util::get_bytes(hbuf.data(), header_len, off, dek_wrapped.data(), dek_wrapped.size());

    // Unwrap the DEK. A failure here means the master key is wrong OR the
    // wrapped key was tampered with — either way the job cannot be trusted.
    if (crypto_secretbox_open_easy(dek.data(), dek_wrapped.data(),
                                   dek_wrapped.size(), dek_nonce.data(),
                                   master_key.data()) != 0) {
        throw IntegrityError("cannot unwrap job key (wrong master key or tampering)");
    }
    return meta;
}

}  // namespace

std::string JobMetadata::id_hex() const {
    return util::to_hex(job_id, sizeof(job_id));
}

CryptoEngine::CryptoEngine() { ensure_sodium(); }

std::size_t CryptoEngine::master_key_bytes() { return crypto_secretbox_KEYBYTES; }

std::uint64_t CryptoEngine::encrypt_stream(std::istream& in, std::ostream& out,
                                           const SecureBuffer& master_key,
                                           JobMetadata& meta) const {
    if (master_key.size() != master_key_bytes()) {
        throw CryptoError("master key has wrong length");
    }

    // 1) Generate a fresh random job identifier and Data Encryption Key.
    randombytes_buf(meta.job_id, sizeof(meta.job_id));
    SecureBuffer dek(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_secretstream_xchacha20poly1305_keygen(dek.data());

    // 2) Wrap (encrypt) the DEK under the Master Key with a random nonce.
    std::array<std::uint8_t, crypto_secretbox_NONCEBYTES> dek_nonce{};
    randombytes_buf(dek_nonce.data(), dek_nonce.size());
    std::array<std::uint8_t, kDekWrappedLen> dek_wrapped{};
    crypto_secretbox_easy(dek_wrapped.data(), dek.data(), dek.size(),
                          dek_nonce.data(), master_key.data());

    // 3) Emit MAGIC, version, header. original_size starts at 0 and is patched
    //    once we know the true plaintext length.
    meta.original_size = 0;
    std::vector<std::uint8_t> header =
        serialize_header(meta, dek_nonce.data(), dek_wrapped.data());

    std::vector<std::uint8_t> lead;
    util::put_bytes(lead, kMagic.data(), kMagic.size());
    lead.push_back(kVersion);
    util::put_u32(lead, static_cast<std::uint32_t>(header.size()));
    out.write(reinterpret_cast<const char*>(lead.data()),
              static_cast<std::streamsize>(lead.size()));
    out.write(reinterpret_cast<const char*>(header.data()),
              static_cast<std::streamsize>(header.size()));
    if (!out) throw IoError("failed writing job header");

    // 4) Initialise the secretstream and emit its 24-byte header.
    crypto_secretstream_xchacha20poly1305_state st;
    std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> ss_header{};
    if (crypto_secretstream_xchacha20poly1305_init_push(
            &st, ss_header.data(), dek.data()) != 0) {
        throw CryptoError("secretstream init_push failed");
    }
    out.write(reinterpret_cast<const char*>(ss_header.data()),
              static_cast<std::streamsize>(ss_header.size()));

    // 5) Stream the payload chunk by chunk. The metadata AAD is attached to the
    //    first chunk only; that single binding protects the whole stream.
    std::vector<std::uint8_t> aad = build_aad(meta);
    std::vector<std::uint8_t> pbuf(kChunkSize);
    std::vector<std::uint8_t> cbuf(kChunkSize +
                                   crypto_secretstream_xchacha20poly1305_ABYTES);
    std::uint64_t total = 0;
    bool first = true;

    while (true) {
        in.read(reinterpret_cast<char*>(pbuf.data()),
                static_cast<std::streamsize>(kChunkSize));
        std::streamsize got = in.gcount();
        if (in.bad()) throw IoError("error reading plaintext input");
        const bool last = in.eof();  // set once read hits end-of-input
        const unsigned char tag =
            last ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                 : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long clen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st, cbuf.data(), &clen, pbuf.data(),
            static_cast<unsigned long long>(got),
            first ? aad.data() : nullptr,
            first ? aad.size() : 0, tag);

        std::vector<std::uint8_t> framing;
        util::put_u32(framing, static_cast<std::uint32_t>(clen));
        out.write(reinterpret_cast<const char*>(framing.data()), 4);
        out.write(reinterpret_cast<const char*>(cbuf.data()),
                  static_cast<std::streamsize>(clen));
        if (!out) throw IoError("failed writing ciphertext chunk");

        total += static_cast<std::uint64_t>(got);
        first = false;
        if (last) break;
    }

    // 6) Back-patch original_size if the sink supports seeking (regular files
    //    do; pipes do not — in which case the field simply stays 0).
    out.flush();
    std::streampos resume = out.tellp();
    if (resume != std::streampos(-1)) {
        out.seekp(kOriginalSizeOffset);
        if (out) {
            std::vector<std::uint8_t> sz;
            util::put_u64(sz, total);
            out.write(reinterpret_cast<const char*>(sz.data()), 8);
            out.seekp(resume);  // restore, so the stream is left consistent
        } else {
            out.clear();  // non-seekable sink: not an error, keep size = 0
        }
    }
    meta.original_size = total;
    return total;
}

void CryptoEngine::decrypt_stream(std::istream& in, std::ostream& out,
                                  const SecureBuffer& master_key,
                                  JobMetadata& meta_out) const {
    if (master_key.size() != master_key_bytes()) {
        throw CryptoError("master key has wrong length");
    }

    SecureBuffer dek(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    meta_out = parse_and_unwrap(in, master_key, dek);

    // secretstream header, then initialise the pull side.
    std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> ss_header{};
    read_exact(in, ss_header.data(), ss_header.size());

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &st, ss_header.data(), dek.data()) != 0) {
        throw FormatError("invalid secretstream header");
    }

    std::vector<std::uint8_t> aad = build_aad(meta_out);
    const std::size_t max_clen =
        kChunkSize + crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<std::uint8_t> cbuf(max_clen);
    std::vector<std::uint8_t> pbuf(kChunkSize);

    bool first = true;
    bool saw_final = false;
    while (!saw_final) {
        std::array<std::uint8_t, 4> lb{};
        read_exact(in, lb.data(), 4);
        std::size_t off = 0;
        std::uint32_t clen = util::get_u32(lb.data(), 4, off);
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES || clen > max_clen) {
            throw FormatError("ciphertext chunk length out of range");
        }
        read_exact(in, cbuf.data(), clen);

        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, pbuf.data(), &plen, &tag, cbuf.data(), clen,
                first ? aad.data() : nullptr,
                first ? aad.size() : 0) != 0) {
            // Wrong key, corrupted chunk, reordering, or tampered metadata.
            throw IntegrityError("payload authentication failed");
        }
        out.write(reinterpret_cast<const char*>(pbuf.data()),
                  static_cast<std::streamsize>(plen));
        if (!out) throw IoError("failed writing decrypted output");

        first = false;
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            saw_final = true;
        }
    }
    out.flush();
}

JobMetadata CryptoEngine::read_metadata(std::istream& in,
                                        const SecureBuffer& master_key) const {
    if (master_key.size() != master_key_bytes()) {
        throw CryptoError("master key has wrong length");
    }
    SecureBuffer dek(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    return parse_and_unwrap(in, master_key, dek);
}

}  // namespace securedrv
