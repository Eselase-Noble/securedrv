// =============================================================================
//  secure_buffer.hpp — RAII container for sensitive key material.
//
//  Cryptographic keys must not linger in ordinary heap memory: they could be
//  paged to disk (swap), captured in a core dump, or read by another process.
//  SecureBuffer allocates through libsodium's guarded allocator, which:
//     * places guard pages around the region (over/under-run protection),
//     * calls sodium_mlock() so the pages are excluded from swap,
//     * canary-checks the region, and
//     * is zeroed on free (sodium_free) so the secret never outlives the object.
//
//  This type is move-only: a secret has exactly one owner at a time.
// =============================================================================
#ifndef SECUREDRV_SECURE_BUFFER_HPP
#define SECUREDRV_SECURE_BUFFER_HPP

#include <cstddef>
#include <cstdint>

namespace securedrv {

class SecureBuffer {
public:
    /// Allocate `size` bytes of guarded, swap-locked, zero-initialised memory.
    /// Throws CryptoError if the secure allocator fails.
    explicit SecureBuffer(std::size_t size);

    /// Securely wipes and frees the region.
    ~SecureBuffer();

    // Move-only: transferring ownership leaves the source empty (null/0).
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // Non-copyable: secrets are never silently duplicated.
    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    std::uint8_t*       data()       noexcept { return data_; }
    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t         size() const noexcept { return size_; }

    /// Mark the buffer read-only at the page level (sodium_mprotect_readonly).
    /// Useful once a long-lived key has been populated.
    void make_readonly();
    /// Restore read/write access (sodium_mprotect_readwrite).
    void make_readwrite();

private:
    std::uint8_t* data_ = nullptr;
    std::size_t   size_ = 0;
};

}  // namespace securedrv

#endif  // SECUREDRV_SECURE_BUFFER_HPP
