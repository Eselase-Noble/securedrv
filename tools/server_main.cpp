// =============================================================================
//  server_main.cpp — "cipherjet-server": the secure print server / release daemon.
//
//  Listens on a TCP port. For each connection it:
//    1. sends a fresh random challenge,
//    2. authenticates the client (Ed25519 signature over the challenge, checked
//       against the allowlist),
//    3. opens the sealed job with the server's secret key, and
//    4. streams the recovered plaintext to a print command (default `lp`),
//       so plaintext is never written to disk.
//
//  Clients may be on any network that can reach this server — the job is sealed
//  end to end, so a plain socket over the internet is safe (see the docs).
//
//  Usage:  cipherjet-server [--port N] [--printer NAME | --exec "CMD"]
//  Keys live in CIPHERJET_HOME (create with `cipherjet-keygen net-server`).
// =============================================================================
#include <sodium.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "securedrv/audit_log.hpp"
#include "securedrv/config.hpp"
#include "securedrv/discovery.hpp"
#include "securedrv/errors.hpp"
#include "securedrv/net_crypto.hpp"
#include "securedrv/net_keys.hpp"
#include "securedrv/socket.hpp"
#include "securedrv/util.hpp"

#ifndef CIPHERJET_VERSION
#define CIPHERJET_VERSION "0.0.0-dev"
#endif

#if defined(_WIN32)
  #define CJ_POPEN _popen
  #define CJ_PCLOSE _pclose
#else
  #define CJ_POPEN popen
  #define CJ_PCLOSE pclose
#endif

using namespace securedrv;

namespace {

constexpr std::uint8_t  kHello[4] = {'C', 'J', 'N', 'P'};
constexpr std::uint8_t  kProtoVersion = 2;   // v2: flags byte + optional anon auth
constexpr std::uint8_t  kFlagLanOpen  = 0x01;
constexpr std::uint8_t  kAuthAnon     = 0x00;
constexpr std::uint8_t  kAuthSigned   = 0x01;
constexpr const char*   kAuthDomain = "cipherjet-auth-v1";
constexpr std::uint16_t kDefaultPort = 9310;

void usage() {
    std::cerr <<
        "cipherjet-server — secure print server (decrypts and releases jobs)\n"
        "Usage:\n"
        "  cipherjet-server [--port N] [--printer NAME | --exec \"CMD\"] [options]\n\n"
        "  --port N        TCP + discovery port to listen on (default 9310)\n"
        "  --printer NAME  release each job with: lp -d NAME\n"
        "  --exec \"CMD\"    release each job by piping plaintext to CMD (default: lp)\n"
        "  --require-auth  require an authorised client key even on the LAN\n"
        "  --no-discovery  do not advertise on the local network\n\n"
        "By default, clients on the local network can print with no key exchange;\n"
        "clients from other networks must be in <CIPHERJET_HOME>/authorized_clients.\n"
        "Keys live in CIPHERJET_HOME; create them with 'cipherjet-keygen net-server'.\n";
}

/// Handle one client connection. Returns true if a job was accepted+released.
/// `lan_open` allows anonymous/unlisted clients when the peer is on the LAN.
bool handle_client(net::Conn& conn, const std::string& peer, bool lan_open,
                   const net::ServerBoxKey& server,
                   const std::vector<net::PublicKey>& allow,
                   const std::string& exec_cmd, AuditLog& audit) {
    const bool peer_is_lan = net::is_lan_address(peer);

    // 1) Send hello + flags + challenge.
    std::uint8_t challenge[net::kContextBytes];
    randombytes_buf(challenge, sizeof(challenge));
    std::vector<std::uint8_t> hello;
    hello.insert(hello.end(), kHello, kHello + 4);
    hello.push_back(kProtoVersion);
    hello.push_back((lan_open && peer_is_lan) ? kFlagLanOpen : 0);
    hello.insert(hello.end(), challenge, challenge + sizeof(challenge));
    conn.send_all(hello.data(), hello.size());

    // 2) Read the auth mode the client chose.
    std::uint8_t auth_mode = 0;
    conn.recv_exact(&auth_mode, 1);

    bool ok = false;
    std::string cid = "anonymous";
    if (auth_mode == kAuthSigned) {
        std::uint8_t client_pk[crypto_sign_PUBLICKEYBYTES];
        std::uint8_t sig[crypto_sign_BYTES];
        conn.recv_exact(client_pk, sizeof(client_pk));
        conn.recv_exact(sig, sizeof(sig));
        std::vector<std::uint8_t> signed_msg(kAuthDomain, kAuthDomain + std::strlen(kAuthDomain));
        signed_msg.insert(signed_msg.end(), challenge, challenge + sizeof(challenge));
        net::PublicKey cpk{};
        std::memcpy(cpk.data(), client_pk, cpk.size());
        const bool sig_ok = crypto_sign_verify_detached(
            sig, signed_msg.data(), signed_msg.size(), client_pk) == 0;
        cid = util::to_hex(client_pk, sizeof(client_pk));
        // A valid signer is accepted if allow-listed, or if it's a LAN peer and
        // LAN access is open.
        ok = sig_ok && (net::is_authorized(allow, cpk) || (lan_open && peer_is_lan));
    } else if (auth_mode == kAuthAnon) {
        // Anonymous clients are only accepted on the LAN when LAN access is open.
        ok = lan_open && peer_is_lan;
    }

    std::uint8_t status = ok ? 1 : 0;
    conn.send_all(&status, 1);
    if (!ok) {
        std::cerr << "cipherjet-server: rejected " << cid.substr(0, 16)
                  << "… from " << peer << (peer_is_lan ? " (lan)" : " (remote)") << "\n";
        audit.record("net-reject", cid, "peer=" + peer);
        return false;
    }

    // 3) Open the sealed job and 4) release it to the print command.
    FILE* pipe = CJ_POPEN(exec_cmd.c_str(), "w");
    if (!pipe) throw IoError("cannot start print command: " + exec_cmd);

    net::ByteSource src = [&](std::uint8_t* b, std::size_t n) {
        return conn.recv_some(b, n);
    };
    net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
        if (std::fwrite(d, 1, n, pipe) != n) {
            throw IoError("failed writing to print command");
        }
    };

    net::SealedJobMeta meta;
    try {
        net::open_job(src, sink, server, challenge, meta);
    } catch (...) {
        CJ_PCLOSE(pipe);
        throw;
    }
    CJ_PCLOSE(pipe);

    std::uint8_t done = 1;
    conn.send_all(&done, 1);

    audit.record("net-release", meta.id_hex(),
                 "client=" + cid.substr(0, 16) + " peer=" + peer +
                 " title=\"" + meta.title + "\" bytes=" +
                 std::to_string(meta.plaintext_bytes));
    std::cerr << "cipherjet-server: released job " << meta.id_hex() << " ("
              << meta.plaintext_bytes << " bytes) from " << peer << "\n";
    return true;
}

}  // namespace

int main(int argc, char** argv) try {
    if (sodium_init() < 0) { std::cerr << "sodium init failed\n"; return 1; }
    net::socket_startup();

    std::uint16_t port = kDefaultPort;
    std::string exec_cmd = "lp";
    bool lan_open = true;      // LAN clients need no key exchange by default
    bool discovery = true;     // advertise on the LAN by default
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--version") { std::cout << "cipherjet-server " CIPHERJET_VERSION "\n"; return 0; }
        if (a == "--help") { usage(); return 0; }
        else if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        else if (a == "--printer" && i + 1 < argc) exec_cmd = "lp -d " + std::string(argv[++i]);
        else if (a == "--exec" && i + 1 < argc) exec_cmd = argv[++i];
        else if (a == "--require-auth") lan_open = false;
        else if (a == "--no-discovery") discovery = false;
        else { usage(); return 2; }
    }

    Config cfg = Config::load();
    net::ServerBoxKey server;
    try {
        server = net::load_server_box_key(cfg.data_dir);
    } catch (const Error&) {
        std::cerr << "cipherjet-server: no server key — run 'cipherjet-keygen net-server' first.\n";
        return 2;
    }
    auto allow = net::load_authorized_clients(cfg.data_dir);
    if (!lan_open && allow.empty()) {
        std::cerr << "cipherjet-server: warning — --require-auth is set but there are "
                     "no authorised clients; every connection will be rejected. Add "
                     "client keys with 'cipherjet-keygen net-allow <key>'.\n";
    }

    AuditLog audit(cfg.audit_path);

    // Advertise on the local network so same-network clients need no setup.
    std::atomic<bool> stop_discovery{false};
    std::thread discovery_thread;
    if (discovery) {
        discovery_thread = std::thread(net::run_discovery_responder, port, port,
                                       server.pk, &stop_discovery);
        discovery_thread.detach();
    }

    net::Listener listener(port);
    std::cerr << "cipherjet-server " CIPHERJET_VERSION " listening on port " << port
              << (discovery ? " (discoverable on the LAN)" : "")
              << ", releasing via: " << exec_cmd << "\n"
              << "  LAN clients: " << (lan_open ? "no setup required" : "must be authorised")
              << "\n";

    // Single-threaded accept loop: one job at a time. A failing client is logged
    // and skipped without bringing the server down.
    for (;;) {
        std::string peer;
        net::Conn conn = listener.accept(&peer);
        try {
            handle_client(conn, peer, lan_open, server, allow, exec_cmd, audit);
        } catch (const std::exception& e) {
            std::cerr << "cipherjet-server: connection from " << peer
                      << " failed: " << e.what() << "\n";
        }
    }
} catch (const std::exception& e) {
    std::cerr << "cipherjet-server: " << e.what() << "\n";
    return 1;
}
