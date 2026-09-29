// =============================================================================
//  discovery.hpp — Zero-configuration server discovery on the local network.
//
//  So that same-network clients can print with no setup, the server advertises
//  itself over UDP and hands out its public key; the client broadcasts a probe,
//  takes the first responder, and seals the job to the key it learned. No manual
//  key exchange, no allowlist — the document is still encrypted in transit, but
//  onboarding is as smooth as a normal network printer.
//
//  This is Cipherjet's own lightweight LAN discovery (a small UDP query/response
//  on a fixed port), not system Bonjour, so it does not appear in the OS printer
//  browser; it is used by cipherjet-send to locate a cipherjet-server.
// =============================================================================
#ifndef SECUREDRV_DISCOVERY_HPP
#define SECUREDRV_DISCOVERY_HPP

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

#include "securedrv/net_keys.hpp"

namespace securedrv::net {

/// A server found on the local network.
struct Discovered {
    std::string   ip;        ///< Responder's IPv4 address.
    std::uint16_t tcp_port;  ///< TCP port the server accepts jobs on.
    PublicKey     pk{};      ///< Server's public key (used to seal the job).
};

/// Broadcast a discovery probe on `disc_port` and wait up to `timeout_ms` for a
/// server. Returns the first responder, or nullopt if none answered.
std::optional<Discovered> discover_server(std::uint16_t disc_port, int timeout_ms);

/// Run the server-side discovery responder until `*stop` becomes true. Answers
/// probes with `tcp_port` and `server_pk`. Intended to run on its own thread.
void run_discovery_responder(std::uint16_t disc_port, std::uint16_t tcp_port,
                             const PublicKey& server_pk, std::atomic<bool>* stop);

/// True if `ip` (dotted IPv4, or an IPv6 loopback/link-local/ULA text form) is on
/// a private / loopback / link-local network — i.e. treat the peer as "on the LAN".
bool is_lan_address(const std::string& ip);

}  // namespace securedrv::net

#endif  // SECUREDRV_DISCOVERY_HPP
