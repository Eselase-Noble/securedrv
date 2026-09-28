// =============================================================================
//  audit_log.cpp — Hash-chained append-only audit log.
//
//  Line format (fields separated by '|'):
//      seq | unix_time | event | job_id | detail | line_hash
//
//  where
//      payload   = seq|unix_time|event|job_id|detail
//      line_hash = hex( BLAKE2b( prev_line_hash + "\n" + payload ) )
//
//  The genesis link (before the first line) is the empty string. Because every
//  line_hash depends on the previous line_hash, editing or deleting any line
//  breaks the chain from that point onward, which verify() detects.
// =============================================================================
#include "securedrv/audit_log.hpp"

#include <sodium.h>

#include <ctime>
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/util.hpp"

namespace securedrv {

namespace {

/// Replace field-breaking characters so a single logical record always occupies
/// exactly one line with a fixed number of '|'-separated fields.
std::string sanitize(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c == '|' || c == '\n' || c == '\r') c = ' ';
    }
    return out;
}

/// Return the last non-empty line of a file, or "" if the file is empty/absent.
std::string last_line(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::string line, last;
    while (std::getline(f, line)) {
        if (!line.empty()) last = line;
    }
    return last;
}

/// Extract the trailing hash field (everything after the final '|').
std::string trailing_hash(const std::string& line) {
    auto pos = line.find_last_of('|');
    if (pos == std::string::npos) return "";
    return line.substr(pos + 1);
}

/// Everything before the final '|' — i.e. the payload the hash was computed over.
std::string leading_payload(const std::string& line) {
    auto pos = line.find_last_of('|');
    if (pos == std::string::npos) return line;
    return line.substr(0, pos);
}

}  // namespace

AuditLog::AuditLog(std::string path) : path_(std::move(path)) {
    if (sodium_init() < 0) throw CryptoError("sodium_init() failed");
    // Touch the file so it exists with owner-only permissions from the outset.
    {
        std::ofstream f(path_, std::ios::binary | std::ios::app);
        if (!f) throw IoError("cannot open audit log: " + path_);
    }
    platform::restrict_to_owner(path_);
}

std::string AuditLog::chain_hash(const std::string& prev_hex,
                                 const std::string& payload) {
    // Domain-separate the previous hash from the payload with a newline.
    std::string input = prev_hex + "\n" + payload;
    std::vector<unsigned char> h(crypto_generichash_BYTES);  // 32-byte BLAKE2b
    crypto_generichash(h.data(), h.size(),
                       reinterpret_cast<const unsigned char*>(input.data()),
                       input.size(), nullptr, 0);
    return util::to_hex(h.data(), h.size());
}

void AuditLog::record(const std::string& event, const std::string& job_id_hex,
                      const std::string& detail) {
    // Determine this record's sequence number and the previous chain hash.
    std::string prev = last_line(path_);
    std::string prev_hash = prev.empty() ? "" : trailing_hash(prev);
    std::uint64_t seq = 1;
    if (!prev.empty()) {
        std::istringstream ss(prev);
        std::string seq_field;
        std::getline(ss, seq_field, '|');
        try {
            seq = std::stoull(seq_field) + 1;
        } catch (...) {
            seq = 1;  // Corrupt header field: restart numbering rather than crash.
        }
    }

    std::ostringstream payload;
    payload << seq << '|' << static_cast<long long>(std::time(nullptr)) << '|'
            << sanitize(event) << '|' << sanitize(job_id_hex) << '|'
            << sanitize(detail);

    std::string line_hash = chain_hash(prev_hash, payload.str());

    std::ofstream f(path_, std::ios::binary | std::ios::app);
    if (!f) throw IoError("cannot append to audit log: " + path_);
    f << payload.str() << '|' << line_hash << '\n';
    f.flush();
    if (!f) throw IoError("failed writing audit record");
}

bool AuditLog::verify(std::size_t* error_line) const {
    std::ifstream f(path_, std::ios::binary);
    if (!f) return true;  // No log yet is trivially consistent.

    std::string line;
    std::string prev_hash;
    std::size_t n = 0;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        ++n;
        std::string payload = leading_payload(line);
        std::string stored  = trailing_hash(line);
        if (chain_hash(prev_hash, payload) != stored) {
            if (error_line) *error_line = n;
            return false;
        }
        prev_hash = stored;
    }
    return true;
}

}  // namespace securedrv
