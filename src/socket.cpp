// =============================================================================
//  socket.cpp — Cross-platform TCP implementation (Winsock / BSD sockets).
// =============================================================================
#include "securedrv/socket.hpp"

#include <cstring>
#include <string>

#include "securedrv/errors.hpp"

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socklen_t = int;
  #define SD_WR SD_SEND
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <cerrno>
  #define SD_WR SHUT_WR
#endif

namespace securedrv::net {

namespace {

#if defined(_WIN32)
int last_error() { return WSAGetLastError(); }
void close_fd(std::intptr_t fd) { if (fd != -1) closesocket(static_cast<SOCKET>(fd)); }
#else
int last_error() { return errno; }
void close_fd(std::intptr_t fd) { if (fd != -1) ::close(static_cast<int>(fd)); }
#endif

[[noreturn]] void fail(const std::string& what) {
    throw IoError(what + " (errno " + std::to_string(last_error()) + ")");
}

}  // namespace

void socket_startup() {
#if defined(_WIN32)
    static bool done = false;
    if (!done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) fail("WSAStartup failed");
        done = true;
    }
#endif
}

// ---- Conn -------------------------------------------------------------------

Conn::~Conn() { close(); }

Conn& Conn::operator=(Conn&& o) noexcept {
    if (this != &o) { close(); fd_ = o.fd_; o.fd_ = kInvalid; }
    return *this;
}

void Conn::close() { close_fd(fd_); fd_ = kInvalid; }

Conn Conn::connect(const std::string& host, std::uint16_t port) {
    socket_startup();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;      // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string svc = std::to_string(port);
    if (getaddrinfo(host.c_str(), svc.c_str(), &hints, &res) != 0 || !res) {
        throw IoError("cannot resolve host: " + host);
    }
    std::intptr_t fd = kInvalid;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        std::intptr_t s = static_cast<std::intptr_t>(
            ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (s == kInvalid) continue;
        if (::connect(static_cast<int>(s), ai->ai_addr,
                      static_cast<socklen_t>(ai->ai_addrlen)) == 0) {
            fd = s;
            break;
        }
        close_fd(s);
    }
    freeaddrinfo(res);
    if (fd == kInvalid) throw IoError("cannot connect to " + host + ":" + svc);
    return Conn(fd);
}

void Conn::send_all(const std::uint8_t* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
        auto n = ::send(static_cast<int>(fd_),
                        reinterpret_cast<const char*>(data + sent),
#if defined(_WIN32)
                        static_cast<int>(len - sent), 0);
#else
                        len - sent, 0);
#endif
        if (n <= 0) fail("send failed");
        sent += static_cast<std::size_t>(n);
    }
}

std::size_t Conn::recv_some(std::uint8_t* buf, std::size_t len) {
    auto n = ::recv(static_cast<int>(fd_), reinterpret_cast<char*>(buf),
#if defined(_WIN32)
                    static_cast<int>(len), 0);
#else
                    len, 0);
#endif
    if (n < 0) fail("recv failed");
    return static_cast<std::size_t>(n);
}

void Conn::recv_exact(std::uint8_t* buf, std::size_t len) {
    std::size_t got = 0;
    while (got < len) {
        std::size_t n = recv_some(buf + got, len - got);
        if (n == 0) throw IoError("connection closed before all data received");
        got += n;
    }
}

void Conn::shutdown_write() {
    if (fd_ != kInvalid) ::shutdown(static_cast<int>(fd_), SD_WR);
}

// ---- Listener ---------------------------------------------------------------

Listener::Listener(std::uint16_t port) {
    socket_startup();
    fd_ = static_cast<std::intptr_t>(::socket(AF_INET, SOCK_STREAM, 0));
    if (fd_ == -1) fail("socket() failed");

    int yes = 1;
    ::setsockopt(static_cast<int>(fd_), SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (::bind(static_cast<int>(fd_), reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) != 0) {
        close_fd(fd_);
        fail("bind failed on port " + std::to_string(port));
    }
    if (::listen(static_cast<int>(fd_), 16) != 0) {
        close_fd(fd_);
        fail("listen failed");
    }
}

Listener::~Listener() { close_fd(fd_); }

Conn Listener::accept(std::string* peer_ip) {
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    std::intptr_t c = static_cast<std::intptr_t>(
        ::accept(static_cast<int>(fd_), reinterpret_cast<sockaddr*>(&peer), &plen));
    if (c == -1) fail("accept failed");
    if (peer_ip) {
        char buf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, buf, sizeof(buf));
        *peer_ip = buf;
    }
    return Conn(c);
}

}  // namespace securedrv::net
