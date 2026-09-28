// =============================================================================
//  key_manager.hpp — Lifecycle and at-rest protection of the Master Key (MK).
//
//  The Master Key is the root of trust: it wraps every per-job Data Encryption
//  Key. It must therefore be protected both in memory (SecureBuffer) and on
//  disk. At rest the MK lives in a ".spmk" key file, encrypted under a
//  passphrase-derived Key Encryption Key (KEK):
//
//      KEK = Argon2id(passphrase, salt, opslimit, memlimit)   // memory-hard KDF
//      key file stores:  secretbox(MK, KEK, nonce)            // authenticated
//
//  Argon2id is deliberately slow and memory-hard, so brute-forcing a stolen key
//  file is expensive even with a weak passphrase. The KDF parameters are stored
//  alongside the ciphertext so the file remains self-describing across upgrades.
//
//  In a production enterprise deployment this file would ideally be replaced by
//  an HSM / OS keystore (macOS Keychain, Windows DPAPI, PKCS#11); the interface
//  here is intentionally small so such a backend can be slotted in later.
// =============================================================================
#ifndef SECUREDRV_KEY_MANAGER_HPP
#define SECUREDRV_KEY_MANAGER_HPP

#include <cstdint>
#include <string>

#include "securedrv/secure_buffer.hpp"

namespace securedrv {

class KeyManager {
public:
    /// KDF strength presets, mapped to libsodium's calibrated limits.
    enum class KdfStrength { kInteractive, kModerate, kSensitive };

    /// Create a brand-new random Master Key and write it, passphrase-wrapped, to
    /// `key_path`. The file is created with owner-only permissions. Throws
    /// ConfigError if the file already exists (never silently overwrite a key).
    static void create_master_key(const std::string& key_path,
                                  const std::string& passphrase,
                                  KdfStrength strength = KdfStrength::kModerate);

    /// Load and decrypt the Master Key from `key_path` using `passphrase`.
    /// Returns the 256-bit key in guarded memory. Throws IntegrityError if the
    /// passphrase is wrong or the file was tampered with.
    static SecureBuffer load_master_key(const std::string& key_path,
                                        const std::string& passphrase);

    /// Re-wrap the existing Master Key under a new passphrase (passphrase
    /// rotation). The underlying key bytes are unchanged, so previously spooled
    /// jobs remain decryptable. Throws IntegrityError if `old_passphrase` is wrong.
    static void change_passphrase(const std::string& key_path,
                                  const std::string& old_passphrase,
                                  const std::string& new_passphrase,
                                  KdfStrength strength = KdfStrength::kModerate);

    /// True if a key file already exists at `key_path`.
    static bool exists(const std::string& key_path);
};

}  // namespace securedrv

#endif  // SECUREDRV_KEY_MANAGER_HPP
