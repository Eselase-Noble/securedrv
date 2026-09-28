// =============================================================================
//  secure_buffer.cpp — Implementation of the guarded key-material container.
// =============================================================================
#include "securedrv/secure_buffer.hpp"

#include <sodium.h>

#include "securedrv/errors.hpp"

namespace securedrv {

SecureBuffer::SecureBuffer(std::size_t size) : size_(size) {
    // sodium_malloc returns memory that is guarded by no-access pages on either
    // side, locked into RAM (no swap), and will be zeroed by sodium_free.
    // A zero-byte request is allowed but still yields a valid guarded pointer.
    data_ = static_cast<std::uint8_t*>(sodium_malloc(size == 0 ? 1 : size));
    if (data_ == nullptr) {
        throw CryptoError("sodium_malloc failed (out of locked memory?)");
    }
    // sodium_malloc does not zero the usable region, so do it explicitly to
    // guarantee a clean, deterministic starting state.
    sodium_memzero(data_, size == 0 ? 1 : size);
}

SecureBuffer::~SecureBuffer() {
    if (data_ != nullptr) {
        // sodium_free wipes the region before releasing it back to the OS.
        sodium_free(data_);
        data_ = nullptr;
        size_ = 0;
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_ != nullptr) {
            sodium_free(data_);
        }
        data_       = other.data_;
        size_       = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void SecureBuffer::make_readonly() {
    if (data_ != nullptr && sodium_mprotect_readonly(data_) != 0) {
        throw CryptoError("sodium_mprotect_readonly failed");
    }
}

void SecureBuffer::make_readwrite() {
    if (data_ != nullptr && sodium_mprotect_readwrite(data_) != 0) {
        throw CryptoError("sodium_mprotect_readwrite failed");
    }
}

}  // namespace securedrv
