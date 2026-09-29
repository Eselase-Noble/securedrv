// =============================================================================
//  socket.hpp — Minimal cross-platform blocking TCP sockets.
//
//  A thin, exception-throwing wrapper over BSD sockets / Winsock, enough to run
//  the Cipherjet network protocol (a client connection and a listening server).
//  Kept deliberately small: no async, no TLS — confidentiality is provided end
//  to end by sealing each job to the server's key, so the socket only needs to
//  move bytes reliably.
// =============================================================================
#ifndef SECUREDRV_SOCKET_HPP
#define SECUREDRV_SOCKET_HPP

#include <cstdint>
#include <string>

namespace securedrv::net {

/// Initialise the platform socket subsystem (WSAStartup on Windows; a no-op
/// elsewhere). Safe to call more than once. Call once at program start.
void socket_startup();

/// A connected TCP stream. Move-only; closes on destruction.
class Conn {
public:
    Conn() = default;
    explicit Conn(std::intptr_t fd) : fd_(fd) {}
    ~Conn();
    Conn(Conn&& o) noexcept : fd_(o.fd_) { o.fd_ = kInvalid; }
    Conn& operator=(Conn&& o) noexcept;
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

    /// Connect to host:port (host may be a name or literal address). Throws IoError.
    static Conn connect(const std::string& host, std::uint16_t port);

    /// Send all `len` bytes, retrying short writes. Throws IoError on failure.
    void send_all(const std::uint8_t* data, std::size_t len);

    /// Receive up to `len` bytes; returns bytes read, or 0 when the peer has
    /// closed the connection. Throws IoError on error.
    std::size_t recv_some(std::uint8_t* buf, std::size_t len);

    /// Receive exactly `len` bytes; throws IoError if the peer closes early.
    void recv_exact(std::uint8_t* buf, std::size_t len);

    /// Half-close the sending side (signals end-of-stream to the peer).
    void shutdown_write();

private:
    static constexpr std::intptr_t kInvalid = -1;
    std::intptr_t fd_ = kInvalid;
    void close();
};

/// A listening TCP server socket.
class Listener {
public:
    /// Bind to the given port on all interfaces and start listening. Throws IoError.
    explicit Listener(std::uint16_t port);
    ~Listener();
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    /// Block until a client connects. If `peer_ip` is non-null it receives the
    /// client's textual address. Throws IoError on failure.
    Conn accept(std::string* peer_ip = nullptr);

private:
    std::intptr_t fd_ = -1;
};

}  // namespace securedrv::net

#endif  // SECUREDRV_SOCKET_HPP
