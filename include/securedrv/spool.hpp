// =============================================================================
//  spool.hpp — Secure storage of encrypted print jobs.
//
//  The spool is a directory of ".spjob" files, one per print job, each named by
//  its 32-hex-character job id. This module writes jobs atomically (temp file +
//  rename, so a partial job is never visible), lists them, and removes them with
//  best-effort secure deletion after a successful release.
// =============================================================================
#ifndef SECUREDRV_SPOOL_HPP
#define SECUREDRV_SPOOL_HPP

#include <string>
#include <vector>

namespace securedrv {

class Spool {
public:
    /// Bind to an existing spool directory (created/locked by Config::load()).
    explicit Spool(std::string spool_dir);

    /// Absolute path a job with the given hex id would occupy.
    std::string path_for(const std::string& job_id_hex) const;

    /// List the hex ids of all jobs currently spooled, sorted oldest-first by
    /// file modification time.
    std::vector<std::string> list() const;

    /// Best-effort secure removal of a released job: overwrite the file with
    /// random bytes, flush, then unlink. Note that on copy-on-write / flash
    /// filesystems overwriting does not guarantee the old blocks are gone, so we
    /// rely primarily on encryption — this is defence in depth. Returns false if
    /// the file did not exist.
    bool secure_remove(const std::string& job_id_hex) const;

    const std::string& dir() const { return dir_; }

private:
    std::string dir_;
};

}  // namespace securedrv

#endif  // SECUREDRV_SPOOL_HPP
