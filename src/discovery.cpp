// =============================================================================
//  discovery.cpp — UDP LAN discovery (query/response) implementation.
//
//  Wire format (tiny, fixed):
//    Query    : "CJDQ" (4) + version (1)
//    Response : "CJDR" (4) + version (1) + tcp_port (2, LE) + server_pk (32)
//
//  The client sends the query to the broadcast address (and to loopback, so a
//  server on the same host is also found); the server replies to the sender.
// =============================================================================
#include "securedrv/discovery.hpp"

#include <sodium.h>

#include <array>
#include <cstdio>
#include <cstring>

#include "securedrv/errors.hpp"
#include "securedrv/socket.hpp"  // for socket_startup()

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socklen_t = int;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <cerrno>
#endif

namespace securedrv::net {

namespace {

constexpr std::uint8_t kQ[4] = {'C', 'J', 'D', 'Q'};
constexpr std::uint8_t kR[4] = {'C', 'J', 'D', 'R'};
constexpr std::uint8_t kDiscVersion = 2;
constexpr std::size_t  kRespLen = 4 + 1 + 2 + 32;  // 39 bytes

#if defined(_WIN32)
void close_fd(std::intptr_t fd) { if (fd != -1) closesocket(static_cast<SOCKET>(fd)); }
#else
void close_fd(std::intptr_t fd) { if (fd != -1) ::close(static_cast<int>(fd)); }
#endif

void set_recv_timeout(std::intptr_t fd, int ms) {
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(ms);
    setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

}  // namespace

bool is_lan_address(const std::string& ip) {
    if (ip == "::1") return true;                       // IPv6 loopback
    if (ip.rfind("fe80", 0) == 0) return true;          // IPv6 link-local
    if (ip.rfind("fc", 0) == 0 || ip.rfind("fd", 0) == 0) return true;  // IPv6 ULA
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a == 127) return true;                          // loopback
    if (a == 10) return true;                           // 10.0.0.0/8
    if (a == 192 && b == 168) return true;              // 192.168.0.0/16
    if (a == 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
    if (a == 169 && b == 254) return true;              // link-local
    return false;
}

std::optional<Discovered> discover_server(std::uint16_t disc_port, int timeout_ms) {
    socket_startup();
    std::intptr_t fd = static_cast<std::intptr_t>(::socket(AF_INET, SOCK_DGRAM, 0));
    if (fd == -1) return std::nullopt;

    int yes = 1;
    setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&yes), sizeof(yes));
    set_recv_timeout(fd, timeout_ms);

    std::array<std::uint8_t, 5> query{kQ[0], kQ[1], kQ[2], kQ[3], kDiscVersion};

    auto send_to = [&](const char* addr) {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(disc_port);
        inet_pton(AF_INET, addr, &dst.sin_addr);
        ::sendto(static_cast<int>(fd), reinterpret_cast<const char*>(query.data()),
                 static_cast<int>(query.size()), 0,
                 reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    };
    send_to("255.255.255.255");  // the LAN
    send_to("127.0.0.1");        // a server on this same host

    // Collect the first valid response before the timeout expires.
    std::array<std::uint8_t, 64> buf{};
    sockaddr_in from{};
    socklen_t flen = sizeof(from);
    auto n = ::recvfrom(static_cast<int>(fd), reinterpret_cast<char*>(buf.data()),
                        static_cast<int>(buf.size()), 0,
                        reinterpret_cast<sockaddr*>(&from), &flen);
    if (n < static_cast<decltype(n)>(kRespLen) ||
        std::memcmp(buf.data(), kR, 4) != 0 || buf[4] != kDiscVersion) {
        close_fd(fd);
        return std::nullopt;
    }

    Discovered d;
    char ipbuf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &from.sin_addr, ipbuf, sizeof(ipbuf));
    d.ip = ipbuf;
    d.tcp_port = static_cast<std::uint16_t>(buf[5] | (buf[6] << 8));
    std::memcpy(d.pk.data(), buf.data() + 7, 32);
    close_fd(fd);
    return d;
}

void run_discovery_responder(std::uint16_t disc_port, std::uint16_t tcp_port,
                             const PublicKey& server_pk, std::atomic<bool>* stop) {
    socket_startup();
    std::intptr_t fd = static_cast<std::intptr_t>(::socket(AF_INET, SOCK_DGRAM, 0));
    if (fd == -1) return;

    int yes = 1;
    setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));
    setsockopt(static_cast<int>(fd), SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&yes), sizeof(yes));
    set_recv_timeout(fd, 500);  // wake periodically to check *stop

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(disc_port);
    if (::bind(static_cast<int>(fd), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_fd(fd);
        return;
    }

    // Pre-build the response payload (only tcp_port varies at runtime; fixed here).
    std::array<std::uint8_t, kRespLen> resp{};
    std::memcpy(resp.data(), kR, 4);
    resp[4] = kDiscVersion;
    resp[5] = static_cast<std::uint8_t>(tcp_port & 0xFF);
    resp[6] = static_cast<std::uint8_t>((tcp_port >> 8) & 0xFF);
    std::memcpy(resp.data() + 7, server_pk.data(), 32);

    std::array<std::uint8_t, 64> buf{};
    while (!stop->load()) {
        sockaddr_in from{};
        socklen_t flen = sizeof(from);
        auto n = ::recvfrom(static_cast<int>(fd), reinterpret_cast<char*>(buf.data()),
                            static_cast<int>(buf.size()), 0,
                            reinterpret_cast<sockaddr*>(&from), &flen);
        if (n >= 5 && std::memcmp(buf.data(), kQ, 4) == 0 && buf[4] == kDiscVersion) {
            ::sendto(static_cast<int>(fd), reinterpret_cast<const char*>(resp.data()),
                     static_cast<int>(resp.size()), 0,
                     reinterpret_cast<sockaddr*>(&from), flen);
        }
    }
    close_fd(fd);
}

}  // namespace securedrv::net
