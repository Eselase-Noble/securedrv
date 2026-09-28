// =============================================================================
//  config.cpp — Path resolution and environment-driven configuration.
// =============================================================================
#include "securedrv/config.hpp"

#include <cstdlib>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"

namespace securedrv {

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
    const char* p = std::getenv("SECUREDRV_PASSPHRASE");
    if (p == nullptr) {
        throw ConfigError(
            "SECUREDRV_PASSPHRASE is not set — the master key passphrase must be "
            "provided via this environment variable");
    }
    return std::string(p);
}

}  // namespace securedrv
