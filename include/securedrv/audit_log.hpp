// =============================================================================
//  audit_log.hpp — Append-only, tamper-evident operations log.
//
//  Enterprise deployments must be able to prove *what happened*: which jobs were
//  encrypted, released, or rejected, and when. This log is hash-chained: each
//  entry embeds the BLAKE2b hash of the previous entry, so removing or editing
//  any line invalidates every hash after it. An auditor can detect tampering by
//  re-walking the chain with verify().
//
//  The log records only non-sensitive metadata (job id, event, size, status) —
//  never document content or keys.
// =============================================================================
#ifndef SECUREDRV_AUDIT_LOG_HPP
#define SECUREDRV_AUDIT_LOG_HPP

#include <string>

namespace securedrv {

class AuditLog {
public:
    /// Open (creating if needed) the append-only log at `path`. The file is
    /// locked to owner-only permissions.
    explicit AuditLog(std::string path);

    /// Append one event. `event` is a short verb ("encrypt", "release",
    /// "reject"); `job_id_hex` and `detail` are free-form metadata. The line is
    /// flushed immediately so it survives a crash right after the operation.
    void record(const std::string& event, const std::string& job_id_hex,
                const std::string& detail);

    /// Re-walk the entire chain and confirm every embedded previous-hash link is
    /// intact. Returns true if the log is consistent, false if tampering or
    /// truncation is detected. `error_line` (1-based) reports the first bad line.
    bool verify(std::size_t* error_line = nullptr) const;

private:
    std::string path_;

    /// Compute the chained hash for a line given the previous line's hash.
    static std::string chain_hash(const std::string& prev_hex,
                                  const std::string& payload);
};

}  // namespace securedrv

#endif  // SECUREDRV_AUDIT_LOG_HPP
