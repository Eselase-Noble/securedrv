// =============================================================================
//  config.cpp — Path resolution and environment-driven configuration.
// =============================================================================
#include "securedrv/config.hpp"

#include <cstdlib>
#include <fstream>
#include <string>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"

namespace securedrv {

namespace {

/// Read a passphrase from a file: the first line, with trailing CR/LF and
/// surrounding whitespace stripped. Throws ConfigError if unreadable/empty.
std::string read_passphrase_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw ConfigError("cannot read passphrase file: " + path);
    std::string line;
    std::getline(f, line);
    // Trim CR (Windows line endings) and surrounding spaces/tabs/newlines.
    auto not_space = [](unsigned char c) { return c != ' ' && c != '\t' &&
                                                  c != '\r' && c != '\n'; };
    while (!line.empty() && !not_space(static_cast<unsigned char>(line.back())))
        line.pop_back();
    std::size_t start = 0;
    while (start < line.size() &&
           !not_space(static_cast<unsigned char>(line[start])))
        ++start;
    line = line.substr(start);
    if (line.empty()) throw ConfigError("passphrase file is empty: " + path);
    return line;
}

}  // namespace

Config Config::load() {
    Config c;
    c.data_dir  = platform::default_data_dir();               // created + locked
    c.key_path  = platform::path_join(c.data_dir, "master.spmk");
    c.spool_dir = platform::path_join(c.data_dir, "spool");
    c.audit_path = platform::path_join(c.data_dir, "audit.log");

    // The spool holds encrypted jobs; still, lock it down so file listings and
    // metadata are not exposed to other local users.
    platform::make_directories(c.spool_dir);
    platform::restrict_dir_to_owner(c.spool_dir);
    return c;
}

std::string Config::passphrase_from_env() {
    // Resolution order, so the same binary works as an interactive CLI tool and
    // as an unattended CUPS backend:
    //   1) CIPHERJET_PASSPHRASE        — the passphrase itself (CLI / scripts)
    //   2) CIPHERJET_PASSPHRASE_FILE   — path to a file holding the passphrase
    //   3) ~/.config/cipherjet/passphrase (or %APPDATA%\Cipherjet\passphrase)
    if (const char* p = std::getenv("CIPHERJET_PASSPHRASE"); p && *p) {
        return std::string(p);
    }
    if (const char* pf = std::getenv("CIPHERJET_PASSPHRASE_FILE"); pf && *pf) {
        return read_passphrase_file(pf);
    }
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata && *appdata) {
        std::string def = platform::path_join(
            platform::path_join(appdata, "Cipherjet"), "passphrase");
        if (std::ifstream(def).good()) return read_passphrase_file(def);
    }
#else
    if (const char* home = std::getenv("HOME"); home && *home) {
        std::string def = platform::path_join(
            platform::path_join(home, ".config/cipherjet"), "passphrase");
        if (std::ifstream(def).good()) return read_passphrase_file(def);
    }
#endif
    throw ConfigError(
        "no passphrase available — set CIPHERJET_PASSPHRASE, or "
        "CIPHERJET_PASSPHRASE_FILE, or create ~/.config/cipherjet/passphrase");
}

}  // namespace securedrv
