// =============================================================================
//  platform.hpp — Cross-platform OS abstraction layer.
//
//  SecureDrv is designed to run identically on Linux, macOS and Windows. Every
//  operation that differs between operating systems is funnelled through this
//  single interface, so the rest of the engine stays 100% portable C++17.
//
//  Responsibilities:
//    * Put the process's stdin/stdout into binary mode (Windows would otherwise
//      translate CR/LF and corrupt binary print data).
//    * Lock down filesystem permissions on secrets (POSIX chmod 0600 /
//      Windows ACLs restricting access to the current user).
//    * Resolve a per-user, OS-appropriate data directory for the spool and keys.
// =============================================================================
#ifndef SECUREDRV_PLATFORM_HPP
#define SECUREDRV_PLATFORM_HPP

#include <string>

namespace securedrv::platform {

/// Force stdin and stdout into raw binary mode. No-op on POSIX; on Windows this
/// calls _setmode(..., _O_BINARY). Must be invoked before any binary I/O on the
/// standard streams, i.e. at the top of every executable's main().
void set_standard_streams_binary();

/// Restrict `path` so that only the owning user can read or write it.
///   * POSIX:   chmod(path, 0600)
///   * Windows: replace the DACL with a single ACE granting the current user.
/// Throws IoError on failure. Used for the master key and every spool file.
void restrict_to_owner(const std::string& path);

/// Restrict a directory so only the owning user may traverse/read/write it
/// (POSIX 0700 / equivalent Windows ACL). Throws IoError on failure.
void restrict_dir_to_owner(const std::string& path);

/// Return the base directory in which SecureDrv stores its spool and keys,
/// honouring platform conventions and the CIPHERJET_HOME override:
///   * CIPHERJET_HOME if set (all platforms)
///   * Linux/macOS:   $XDG_DATA_HOME/securedrv  or  $HOME/.local/share/securedrv
///   * Windows:       %APPDATA%\SecureDrv
/// The directory is created (with owner-only permissions) if it does not exist.
std::string default_data_dir();

/// Create `path` (and missing parents) as a directory, if not already present.
/// Throws IoError on failure.
void make_directories(const std::string& path);

/// Platform-correct path join (uses '\\' on Windows, '/' elsewhere).
std::string path_join(const std::string& a, const std::string& b);

}  // namespace securedrv::platform

#endif  // SECUREDRV_PLATFORM_HPP
