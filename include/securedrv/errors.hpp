// =============================================================================
//  errors.hpp — Error handling primitives for Cipherjet.
//
//  We use a small, typed exception hierarchy rather than raw error codes so that
//  cryptographic failures can never be silently ignored: a failed decryption,
//  a bad authentication tag, or a tampered file always propagates as an
//  exception that must be handled explicitly at an entry point.
// =============================================================================
#ifndef SECUREDRV_ERRORS_HPP
#define SECUREDRV_ERRORS_HPP

#include <stdexcept>
#include <string>

namespace securedrv {

/// Base class for every error raised by the Cipherjet engine.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& what) : std::runtime_error(what) {}
};

/// Thrown when the underlying crypto library cannot be initialised, or when a
/// primitive returns an unexpected failure that is not attacker-controllable.
class CryptoError : public Error {
public:
    explicit CryptoError(const std::string& what)
        : Error("crypto error: " + what) {}
};

/// Thrown when authenticated decryption fails: wrong key, corrupted ciphertext,
/// or deliberate tampering. This is security-critical — the caller MUST treat
/// the plaintext as invalid and discard any bytes already produced.
class IntegrityError : public Error {
public:
    explicit IntegrityError(const std::string& what)
        : Error("integrity/authentication failure: " + what) {}
};

/// Thrown for malformed containers (bad magic, unsupported version, truncated
/// header, impossible field lengths, etc.).
class FormatError : public Error {
public:
    explicit FormatError(const std::string& what)
        : Error("format error: " + what) {}
};

/// Thrown for I/O problems (cannot open spool, permission denied, short read).
class IoError : public Error {
public:
    explicit IoError(const std::string& what)
        : Error("i/o error: " + what) {}
};

/// Thrown for invalid configuration or key-management state (missing master
/// key, wrong passphrase, bad permissions on a key file, etc.).
class ConfigError : public Error {
public:
    explicit ConfigError(const std::string& what)
        : Error("configuration error: " + what) {}
};

}  // namespace securedrv

#endif  // SECUREDRV_ERRORS_HPP
