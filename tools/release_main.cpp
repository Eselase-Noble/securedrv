// =============================================================================
//  release_main.cpp — "cipherjet-release": decrypt and release spooled jobs.
//
//  This is the trusted side of the pipeline. It decrypts a spooled job back to
//  plaintext and streams it to stdout, from where it can be piped to the real
//  printer/device. By default the job is securely removed after a successful,
//  fully authenticated release.
//
//  Subcommands:
//    list                       Show spooled jobs (id, time, size, title).
//    release <job-id> [--keep]  Decrypt <job-id> to stdout; remove unless --keep.
//    verify-audit               Re-walk the audit chain and report tampering.
//
//  Environment: CIPHERJET_PASSPHRASE (required), CIPHERJET_HOME (optional).
// =============================================================================
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

#include "securedrv/config.hpp"
#include "securedrv/crypto_engine.hpp"
#include "securedrv/key_manager.hpp"
#include "securedrv/audit_log.hpp"
#include "securedrv/spool.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/errors.hpp"

using namespace securedrv;

namespace {

void usage() {
    std::cerr <<
        "cipherjet-release — decrypt and release spooled print jobs\n"
        "Usage:\n"
        "  cipherjet-release list\n"
        "  cipherjet-release release <job-id> [--keep]\n"
        "  cipherjet-release verify-audit\n\n"
        "Environment: CIPHERJET_PASSPHRASE (required), CIPHERJET_HOME (optional)\n";
}

/// Render a unix timestamp as local ISO-8601-ish text for the listing.
std::string fmt_time(std::int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t);
    char buf[32];
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &tt);
#else
    localtime_r(&tt, &tmv);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
}

int do_list(const Config& cfg, const SecureBuffer& mk) {
    Spool spool(cfg.spool_dir);
    CryptoEngine engine;
    auto ids = spool.list();
    if (ids.empty()) {
        std::cerr << "(no spooled jobs)\n";
        return 0;
    }
    std::cerr << "JOB-ID                            CREATED              "
                 "SIZE       TITLE\n";
    for (const auto& id : ids) {
        std::ifstream f(spool.path_for(id), std::ios::binary);
        if (!f) continue;
        try {
            JobMetadata m = engine.read_metadata(f, mk);
            std::cerr << m.id_hex() << "  " << fmt_time(m.created_unix) << "  ";
            std::cerr.width(9);
            std::cerr << m.original_size << "  " << m.title << "\n";
        } catch (const Error& e) {
            std::cerr << id << "  <unreadable: " << e.what() << ">\n";
        }
    }
    return 0;
}

int do_release(const Config& cfg, const SecureBuffer& mk,
               const std::string& job_id, bool keep) {
    Spool spool(cfg.spool_dir);
    const std::string path = spool.path_for(job_id);
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cipherjet-release: no such job: " << job_id << "\n";
        return 2;
    }

    CryptoEngine engine;
    JobMetadata meta;
    // Decrypt straight to stdout. If authentication fails, decrypt_stream throws
    // before we would ever remove the job, so a tampered job is preserved for
    // investigation rather than destroyed.
    engine.decrypt_stream(in, std::cout, mk, meta);
    std::cout.flush();
    in.close();

    AuditLog audit(cfg.audit_path);
    if (!keep) {
        spool.secure_remove(job_id);
        audit.record("release", meta.id_hex(),
                     "title=\"" + meta.title + "\" bytes=" +
                         std::to_string(meta.original_size) + " removed=yes");
    } else {
        audit.record("release", meta.id_hex(),
                     "title=\"" + meta.title + "\" bytes=" +
                         std::to_string(meta.original_size) + " removed=no");
    }
    std::cerr << "cipherjet-release: released job " << meta.id_hex() << "\n";
    return 0;
}

int do_verify_audit(const Config& cfg) {
    AuditLog audit(cfg.audit_path);
    std::size_t bad = 0;
    if (audit.verify(&bad)) {
        std::cerr << "audit log OK — hash chain intact\n";
        return 0;
    }
    std::cerr << "AUDIT LOG TAMPERING DETECTED at line " << bad << "\n";
    return 3;
}

}  // namespace

int main(int argc, char** argv) try {
    platform::set_standard_streams_binary();
    if (argc < 2) { usage(); return 2; }
    const std::string cmd = argv[1];

    Config cfg = Config::load();

    // verify-audit needs no key material.
    if (cmd == "verify-audit") return do_verify_audit(cfg);

    if (!KeyManager::exists(cfg.key_path)) {
        std::cerr << "cipherjet-release: no master key at " << cfg.key_path << "\n";
        return 2;
    }
    std::string passphrase = Config::passphrase_from_env();
    SecureBuffer mk = KeyManager::load_master_key(cfg.key_path, passphrase);

    if (cmd == "list") return do_list(cfg, mk);

    if (cmd == "release") {
        if (argc < 3) { usage(); return 2; }
        std::string job_id = argv[2];
        bool keep = (argc >= 4 && std::string(argv[3]) == "--keep");
        return do_release(cfg, mk, job_id, keep);
    }

    usage();
    return 2;

} catch (const securedrv::Error& e) {
    std::cerr << "cipherjet-release: " << e.what() << "\n";
    return 1;
} catch (const std::exception& e) {
    std::cerr << "cipherjet-release: unexpected error: " << e.what() << "\n";
    return 1;
}
