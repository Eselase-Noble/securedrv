// =============================================================================
//  util.hpp — Small, dependency-free helpers shared across the engine.
//
//  Kept header-only and inline: endian-stable (little-endian) serialization of
//  fixed-width integers, plus hex encoding for logs and job identifiers. All
//  on-disk integers use an explicit byte order so that a spooled job produced
//  on one machine can always be decrypted on another.
// =============================================================================
#ifndef SECUREDRV_UTIL_HPP
#define SECUREDRV_UTIL_HPP

#include <cstdint>
#include <cstddef>
#include <ostream>
#include <istream>
#include <string>
#include <vector>

#include "errors.hpp"

namespace securedrv::util {

// ---- Little-endian integer writers ------------------------------------------
// We deliberately serialize byte-by-byte rather than memcpy'ing native integers
// so the format is identical regardless of the host's endianness.

inline void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

inline void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

inline void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

// ---- Little-endian integer readers ------------------------------------------
// Each reader validates that enough bytes remain, throwing FormatError on a
// truncated buffer so we never read past the end of an attacker-supplied file.

inline std::uint16_t get_u16(const std::uint8_t* p, std::size_t n, std::size_t& off) {
    if (off + 2 > n) throw FormatError("truncated u16");
    std::uint16_t v = static_cast<std::uint16_t>(p[off]) |
                      (static_cast<std::uint16_t>(p[off + 1]) << 8);
    off += 2;
    return v;
}

inline std::uint32_t get_u32(const std::uint8_t* p, std::size_t n, std::size_t& off) {
    if (off + 4 > n) throw FormatError("truncated u32");
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<std::uint32_t>(p[off + static_cast<std::size_t>(i)]) << (8 * i);
    off += 4;
    return v;
}

inline std::uint64_t get_u64(const std::uint8_t* p, std::size_t n, std::size_t& off) {
    if (off + 8 > n) throw FormatError("truncated u64");
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(p[off + static_cast<std::size_t>(i)]) << (8 * i);
    off += 8;
    return v;
}

// ---- Raw byte block helpers -------------------------------------------------

inline void put_bytes(std::vector<std::uint8_t>& out,
                      const std::uint8_t* data, std::size_t len) {
    out.insert(out.end(), data, data + len);
}

inline void get_bytes(const std::uint8_t* p, std::size_t n, std::size_t& off,
                     std::uint8_t* dst, std::size_t len) {
    if (off + len > n) throw FormatError("truncated fixed-size field");
    for (std::size_t i = 0; i < len; ++i) dst[i] = p[off + i];
    off += len;
}

// ---- Hex encoding (for job IDs and audit-log fingerprints) ------------------

inline std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        s.push_back(kHex[(data[i] >> 4) & 0xF]);
        s.push_back(kHex[data[i] & 0xF]);
    }
    return s;
}

}  // namespace securedrv::util

#endif  // SECUREDRV_UTIL_HPP
