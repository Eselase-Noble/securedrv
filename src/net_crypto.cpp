// =============================================================================
//  net_crypto.cpp — Sealed job (.spnj) implementation.
//
//  Container layout (all integers little-endian):
//     MAGIC "SPNJ"(4) | ver(1)=1 | job_id(16) | sealed_dek(80) | ss_header(24)
//     | chunks…
//  where sealed_dek = crypto_box_seal(DEK, server_pk)  [32-byte key + 48 overhead]
//  and each chunk is { u32 clen; clen ciphertext bytes }. The first chunk is the
//  metadata (title, timestamp) with the session context as AEAD data; the
//  remaining chunks are payload. The final chunk carries the stream FINAL tag.
// =============================================================================
#include "securedrv/net_crypto.hpp"

#include <sodium.h>

#include <array>
#include <vector>

#include "securedrv/errors.hpp"
#include "securedrv/util.hpp"

namespace securedrv::net {

namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'S', 'P', 'N', 'J'};
constexpr std::uint8_t  kVersion   = 1;
constexpr std::size_t   kSealedDek = crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES;  // 48+32=80
constexpr std::size_t   kChunk     = 64 * 1024;

void ensure_sodium() {
    if (sodium_init() < 0) throw CryptoError("sodium_init() failed");
}

/// Pull from `src` until `buf` holds `n` bytes; throws if EOF arrives first.
void source_exact(const ByteSource& src, std::uint8_t* buf, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        std::size_t r = src(buf + got, n - got);
        if (r == 0) throw FormatError("unexpected end of sealed job (truncated)");
        got += r;
    }
}

/// Fill up to `n` bytes; returns the count (0 only at true EOF).
std::size_t source_fill(const ByteSource& src, std::uint8_t* buf, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        std::size_t r = src(buf + got, n - got);
        if (r == 0) break;
        got += r;
    }
    return got;
}

void sink_u32(const ByteSink& out, std::uint32_t v) {
    std::vector<std::uint8_t> b;
    util::put_u32(b, v);
    out(b.data(), b.size());
}

/// Frame and write one secretstream chunk: [u32 clen][clen bytes].
void write_chunk(const ByteSink& out, const std::uint8_t* ct, unsigned long long clen) {
    sink_u32(out, static_cast<std::uint32_t>(clen));
    out(ct, static_cast<std::size_t>(clen));
}

}  // namespace

std::string SealedJobMeta::id_hex() const {
    return util::to_hex(job_id, sizeof(job_id));
}

std::uint64_t seal_job(ByteSource in, ByteSink out, const PublicKey& server_pk,
                       const std::uint8_t context[kContextBytes],
                       const std::string& title, std::int64_t created_unix,
                       std::uint8_t job_id_out[16]) {
    ensure_sodium();
    if (title.size() > 0xFFFF) throw FormatError("job title exceeds 65535 bytes");

    // 1) Random job id + fresh data key.
    randombytes_buf(job_id_out, 16);
    SecureBuffer dek(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_secretstream_xchacha20poly1305_keygen(dek.data());

    // 2) Seal the data key to the server's public key (anonymous sealed box).
    std::array<std::uint8_t, kSealedDek> sealed{};
    if (crypto_box_seal(sealed.data(), dek.data(), dek.size(), server_pk.data()) != 0) {
        throw CryptoError("crypto_box_seal failed");
    }

    // 3) Header.
    std::vector<std::uint8_t> head;
    util::put_bytes(head, kMagic.data(), kMagic.size());
    head.push_back(kVersion);
    util::put_bytes(head, job_id_out, 16);
    util::put_bytes(head, sealed.data(), sealed.size());
    out(head.data(), head.size());

    // 4) Start the stream; emit its header.
    crypto_secretstream_xchacha20poly1305_state st;
    std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> ss_header{};
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, ss_header.data(), dek.data()) != 0) {
        throw CryptoError("secretstream init_push failed");
    }
    out(ss_header.data(), ss_header.size());

    std::vector<std::uint8_t> cbuf(kChunk + crypto_secretstream_xchacha20poly1305_ABYTES);

    // 5) First chunk: metadata, bound to the session context as AEAD data.
    std::vector<std::uint8_t> meta;
    util::put_u16(meta, static_cast<std::uint16_t>(title.size()));
    util::put_bytes(meta, reinterpret_cast<const std::uint8_t*>(title.data()), title.size());
    util::put_u64(meta, static_cast<std::uint64_t>(created_unix));
    {
        unsigned long long clen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st, cbuf.data(), &clen, meta.data(), meta.size(),
            context, kContextBytes, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        write_chunk(out, cbuf.data(), clen);
    }

    // 6) Payload chunks, with one-chunk read-ahead so the last is tagged FINAL.
    std::uint64_t total = 0;
    std::vector<std::uint8_t> cur(kChunk), nxt(kChunk);
    std::size_t curlen = source_fill(in, cur.data(), kChunk);
    if (curlen == 0) {
        unsigned long long clen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st, cbuf.data(), &clen, nullptr, 0, nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        write_chunk(out, cbuf.data(), clen);
        return 0;
    }
    while (true) {
        std::size_t nxtlen = source_fill(in, nxt.data(), kChunk);
        unsigned char tag = (nxtlen == 0)
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        unsigned long long clen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st, cbuf.data(), &clen, cur.data(), curlen, nullptr, 0, tag);
        write_chunk(out, cbuf.data(), clen);
        total += curlen;
        if (nxtlen == 0) break;
        std::swap(cur, nxt);
        curlen = nxtlen;
    }
    return total;
}

void open_job(ByteSource in, ByteSink out, const ServerBoxKey& server,
              const std::uint8_t context[kContextBytes], SealedJobMeta& meta_out) {
    ensure_sodium();

    // Header.
    std::array<std::uint8_t, 5> prefix{};
    source_exact(in, prefix.data(), prefix.size());
    if (prefix[0] != kMagic[0] || prefix[1] != kMagic[1] ||
        prefix[2] != kMagic[2] || prefix[3] != kMagic[3]) {
        throw FormatError("bad magic — not a sealed Cipherjet job");
    }
    if (prefix[4] != kVersion) throw FormatError("unsupported sealed-job version");

    source_exact(in, meta_out.job_id, 16);
    std::array<std::uint8_t, kSealedDek> sealed{};
    source_exact(in, sealed.data(), sealed.size());

    // Open the sealed data key with the server keypair.
    SecureBuffer dek(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    if (crypto_box_seal_open(dek.data(), sealed.data(), sealed.size(),
                             server.pk.data(), server.sk.data()) != 0) {
        throw IntegrityError("cannot open sealed job (not sealed to this server, or tampered)");
    }

    std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES> ss_header{};
    source_exact(in, ss_header.data(), ss_header.size());
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, ss_header.data(), dek.data()) != 0) {
        throw FormatError("invalid sealed-job stream header");
    }

    const std::size_t max_clen = kChunk + crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<std::uint8_t> cbuf(max_clen), pbuf(kChunk);

    // First chunk: metadata (context is authenticated here).
    {
        std::array<std::uint8_t, 4> lb{};
        source_exact(in, lb.data(), 4);
        std::size_t off = 0;
        std::uint32_t clen = util::get_u32(lb.data(), 4, off);
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES || clen > max_clen) {
            throw FormatError("metadata chunk length out of range");
        }
        source_exact(in, cbuf.data(), clen);
        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, pbuf.data(), &plen, &tag, cbuf.data(), clen,
                context, kContextBytes) != 0) {
            throw IntegrityError("metadata authentication failed (wrong session or tampered)");
        }
        std::size_t o = 0;
        std::uint16_t tlen = util::get_u16(pbuf.data(), static_cast<std::size_t>(plen), o);
        if (o + tlen + 8 > static_cast<std::size_t>(plen)) throw FormatError("bad metadata");
        meta_out.title.assign(reinterpret_cast<const char*>(pbuf.data() + o), tlen);
        o += tlen;
        meta_out.created_unix = static_cast<std::int64_t>(
            util::get_u64(pbuf.data(), static_cast<std::size_t>(plen), o));
    }

    // Payload chunks until FINAL.
    std::uint64_t total = 0;
    bool final_seen = false;
    while (!final_seen) {
        std::array<std::uint8_t, 4> lb{};
        source_exact(in, lb.data(), 4);
        std::size_t off = 0;
        std::uint32_t clen = util::get_u32(lb.data(), 4, off);
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES || clen > max_clen) {
            throw FormatError("payload chunk length out of range");
        }
        source_exact(in, cbuf.data(), clen);
        unsigned long long plen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, pbuf.data(), &plen, &tag, cbuf.data(), clen, nullptr, 0) != 0) {
            throw IntegrityError("payload authentication failed");
        }
        if (plen) out(pbuf.data(), static_cast<std::size_t>(plen));
        total += plen;
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) final_seen = true;
    }
    meta_out.plaintext_bytes = total;
}

}  // namespace securedrv::net
