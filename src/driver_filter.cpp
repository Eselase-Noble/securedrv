// =============================================================================
//  driver_filter.cpp — The "securedrv" printer driver entry point.
//
//  This is the program a print system invokes for every job. It behaves like a
//  CUPS filter: it consumes the raw job on stdin (or from a file argument),
//  encrypts it into the secure spool, and records the event in the audit log.
//  The plaintext is never written to disk.
//
//  CUPS invokes filters as:
//      filter  job-id  user  title  copies  options  [filename]
//  We honour that calling convention while also working as a plain
//  "stdin -> spool" filter when run with no arguments, so the same binary can be
//  wired into CUPS (macOS/Linux) or fed by a redirected printer port (Windows).
//
//  Configuration (all via environment, so it is deployment-agnostic):
//      SECUREDRV_PASSPHRASE   master-key passphrase (required)
//      SECUREDRV_HOME         optional data-directory override
// =============================================================================
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>

#if defined(_WIN32)
  #include <process.h>   // _getpid
#else
  #include <unistd.h>    // getpid
#endif

#include <sodium.h>

#include "securedrv/config.hpp"
#include "securedrv/crypto_engine.hpp"
#include "securedrv/key_manager.hpp"
#include "securedrv/audit_log.hpp"
#include "securedrv/spool.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/util.hpp"
#include "securedrv/errors.hpp"

using namespace securedrv;

namespace {

/// Print CUPS-style usage to stderr.
void print_usage() {
    std::cerr <<
        "securedrv — encrypting printer driver (CUPS filter)\n"
        "Usage:\n"
        "  securedrv [job-id user title copies options [file]]\n"
        "  securedrv --help\n\n"
        "Reads a print job from the file argument (if given) or stdin, encrypts\n"
        "it into the secure spool, and logs the event. Requires the environment\n"
        "variable SECUREDRV_PASSPHRASE to unlock the master key.\n";
}

}  // namespace

int main(int argc, char** argv) try {
    // Binary stdio is mandatory: print data and ciphertext must pass byte-exact.
    platform::set_standard_streams_binary();

    if (argc >= 2 && std::string(argv[1]) == "--help") {
        print_usage();
        return 0;
    }

    // Resolve CUPS-style positional arguments when present.
    std::string title = "print-job";
    std::string user  = "unknown";
    std::string input_file;   // empty => read from stdin
    if (argc >= 3) user  = argv[2] ? argv[2] : user;
    if (argc >= 4) title = argv[3] ? argv[3] : title;
    if (argc >= 7 && argv[6] && argv[6][0] != '\0') input_file = argv[6];

    // Load configuration and unlock the master key.
    Config cfg = Config::load();
    if (!KeyManager::exists(cfg.key_path)) {
        std::cerr << "securedrv: no master key found at " << cfg.key_path
                  << " — run 'securedrv-keygen' first.\n";
        return 2;
    }
    std::string passphrase = Config::passphrase_from_env();
    SecureBuffer master_key = KeyManager::load_master_key(cfg.key_path, passphrase);

    // Choose the input source.
    std::ifstream file_in;
    std::istream* in = &std::cin;
    if (!input_file.empty()) {
        file_in.open(input_file, std::ios::binary);
        if (!file_in) {
            std::cerr << "securedrv: cannot open input file " << input_file << "\n";
            return 2;
        }
        in = &file_in;
    }

    // Constructing the engine also initialises libsodium, which we need for the
    // random temp-file suffix below.
    CryptoEngine engine;

    // Encrypt to a uniquely named temporary file in the spool, then atomically
    // rename it to its job-id name so a partially written job is never
    // observable. The name combines the PID with 8 random bytes so that
    // concurrent jobs — and PID reuse across restarts — can never collide.
    Spool spool(cfg.spool_dir);
    std::uint8_t rnd[8];
    randombytes_buf(rnd, sizeof(rnd));
    const long long pid =
        static_cast<long long>(
#if defined(_WIN32)
            _getpid()
#else
            getpid()
#endif
        );
    const std::string tmp_path = platform::path_join(
        cfg.spool_dir, ".incoming-" + std::to_string(pid) + "-" +
                           util::to_hex(rnd, sizeof(rnd)) + ".tmp");

    JobMetadata meta;
    meta.title        = title;
    meta.created_unix = static_cast<std::int64_t>(std::time(nullptr));
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "securedrv: cannot create spool file\n";
            return 2;
        }
        engine.encrypt_stream(*in, out, master_key, meta);
    }
    platform::restrict_to_owner(tmp_path);

    const std::string final_path = spool.path_for(meta.id_hex());
    std::error_code ec;
    std::filesystem::rename(tmp_path, final_path, ec);
    if (ec) {
        std::filesystem::remove(tmp_path, ec);
        std::cerr << "securedrv: failed to commit spool file: " << ec.message() << "\n";
        return 2;
    }

    // Audit the successful encryption (metadata only — never content).
    AuditLog audit(cfg.audit_path);
    audit.record("encrypt", meta.id_hex(),
                 "user=" + user + " title=\"" + meta.title + "\" bytes=" +
                     std::to_string(meta.original_size));

    // CUPS treats a filter's stderr as status output; report the queued job id.
    std::cerr << "securedrv: queued encrypted job " << meta.id_hex()
              << " (" << meta.original_size << " bytes)\n";
    return 0;

} catch (const securedrv::Error& e) {
    // Domain errors (crypto/integrity/format/io/config) — clean, expected exits.
    std::cerr << "securedrv: " << e.what() << "\n";
    return 1;
} catch (const std::exception& e) {
    std::cerr << "securedrv: unexpected error: " << e.what() << "\n";
    return 1;
}
