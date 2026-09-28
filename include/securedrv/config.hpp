// =============================================================================
//  config.hpp — Runtime configuration and path resolution.
//
//  Centralises every filesystem location the engine uses so the executables
//  agree on where the master key, spool and audit log live. All paths derive
//  from a single data directory (platform::default_data_dir()), overridable via
//  the SECUREDRV_HOME environment variable for tests and custom deployments.
// =============================================================================
#ifndef SECUREDRV_CONFIG_HPP
#define SECUREDRV_CONFIG_HPP

#include <string>

namespace securedrv {

struct Config {
    std::string data_dir;    ///< Root directory for all SecureDrv state.
    std::string key_path;    ///< Master key file (data_dir/master.spmk).
    std::string spool_dir;   ///< Directory of encrypted .spjob files.
    std::string audit_path;  ///< Audit log file (data_dir/audit.log).

    /// Resolve all paths from the environment, creating any missing directories
    /// with owner-only permissions. Honours SECUREDRV_HOME.
    static Config load();

    /// Read the master-key passphrase from the SECUREDRV_PASSPHRASE environment
    /// variable. Throws ConfigError if it is unset, so a passphrase is never
    /// silently defaulted. (Interactive prompting can be layered on top later.)
    static std::string passphrase_from_env();
};

}  // namespace securedrv

#endif  // SECUREDRV_CONFIG_HPP
