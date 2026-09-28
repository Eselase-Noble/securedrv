// =============================================================================
//  keygen_main.cpp — "securedrv-keygen": create or re-key the master key.
//
//  Subcommands:
//    init                 Create a new master key (fails if one exists).
//    change               Rotate the master-key passphrase in place.
//
//  Passphrases are read from the environment so the tool can run unattended:
//    SECUREDRV_PASSPHRASE       current / new passphrase (for init)
//    SECUREDRV_NEW_PASSPHRASE   new passphrase (for change)
//
//  Optional:  --strength interactive|moderate|sensitive   (KDF hardness)
// =============================================================================
#include <cstdlib>
#include <iostream>
#include <string>

#include "securedrv/config.hpp"
#include "securedrv/key_manager.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/errors.hpp"

using namespace securedrv;

namespace {

void usage() {
    std::cerr <<
        "securedrv-keygen — master key management\n"
        "Usage:\n"
        "  securedrv-keygen init   [--strength interactive|moderate|sensitive]\n"
        "  securedrv-keygen change [--strength ...]\n\n"
        "Environment:\n"
        "  SECUREDRV_PASSPHRASE       passphrase (init) / OLD passphrase (change)\n"
        "  SECUREDRV_NEW_PASSPHRASE   new passphrase (change)\n"
        "  SECUREDRV_HOME             optional data-directory override\n";
}

KeyManager::KdfStrength parse_strength(int argc, char** argv) {
    for (int i = 2; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--strength") {
            std::string v = argv[i + 1];
            if (v == "interactive") return KeyManager::KdfStrength::kInteractive;
            if (v == "sensitive")   return KeyManager::KdfStrength::kSensitive;
            if (v == "moderate")    return KeyManager::KdfStrength::kModerate;
            throw ConfigError("unknown --strength value: " + v);
        }
    }
    return KeyManager::KdfStrength::kModerate;
}

std::string require_env(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr) throw ConfigError(std::string(name) + " is not set");
    return std::string(v);
}

}  // namespace

int main(int argc, char** argv) try {
    platform::set_standard_streams_binary();
    if (argc < 2) { usage(); return 2; }

    const std::string cmd = argv[1];
    Config cfg = Config::load();
    KeyManager::KdfStrength strength = parse_strength(argc, argv);

    if (cmd == "init") {
        std::string pass = require_env("SECUREDRV_PASSPHRASE");
        KeyManager::create_master_key(cfg.key_path, pass, strength);
        std::cerr << "securedrv-keygen: created master key at " << cfg.key_path << "\n";
        return 0;
    }

    if (cmd == "change") {
        std::string oldp = require_env("SECUREDRV_PASSPHRASE");
        std::string newp = require_env("SECUREDRV_NEW_PASSPHRASE");
        KeyManager::change_passphrase(cfg.key_path, oldp, newp, strength);
        std::cerr << "securedrv-keygen: passphrase rotated for " << cfg.key_path << "\n";
        return 0;
    }

    usage();
    return 2;

} catch (const securedrv::Error& e) {
    std::cerr << "securedrv-keygen: " << e.what() << "\n";
    return 1;
} catch (const std::exception& e) {
    std::cerr << "securedrv-keygen: unexpected error: " << e.what() << "\n";
    return 1;
}
