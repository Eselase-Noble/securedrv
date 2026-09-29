// =============================================================================
//  send_main.cpp — "cipherjet-send": send a print job to a Cipherjet server.
//
//  Encrypts a job end to end (sealed to the server's public key) and streams it
//  over TCP to a cipherjet-server, which decrypts and releases it to the printer.
//  The client and server may be on entirely different networks; only the
//  server's address needs to be reachable.
//
//  Usage:
//    cipherjet-send --host HOST [--port N] --server-key HEX|--server-key-file P
//                   [--title T] [FILE]
//  Reads the job from FILE (or stdin). The client identity key lives in
//  CIPHERJET_HOME (create with `cipherjet-keygen net-client`).
// =============================================================================
#include <sodium.h>

#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "securedrv/config.hpp"
#include "securedrv/discovery.hpp"
#include "securedrv/errors.hpp"
#include "securedrv/net_crypto.hpp"
#include "securedrv/net_keys.hpp"
#include "securedrv/platform.hpp"
#include "securedrv/socket.hpp"
#include "securedrv/util.hpp"

#ifndef CIPHERJET_VERSION
#define CIPHERJET_VERSION "0.0.0-dev"
#endif

using namespace securedrv;

namespace {

constexpr std::uint8_t kHello[4] = {'C', 'J', 'N', 'P'};
constexpr std::uint8_t kProtoVersion = 2;
constexpr std::uint8_t kAuthAnon   = 0x00;
constexpr std::uint8_t kAuthSigned = 0x01;
constexpr const char*  kAuthDomain = "cipherjet-auth-v1";

void usage() {
    std::cerr <<
        "cipherjet-send — send an encrypted print job to a Cipherjet server\n"
        "Usage:\n"
        "  cipherjet-send [FILE]                       (same network: auto-discovers)\n"
        "  cipherjet-send --host HOST [--port N] \\\n"
        "                 (--server-key HEX | --server-key-file PATH) [FILE]\n\n"
        "  (no --host)           find a printer on the local network and print with\n"
        "                        no setup (still encrypted to the discovered key)\n"
        "  --host HOST           a remote server's hostname or IP\n"
        "  --port N             server port (default 9310)\n"
        "  --server-key HEX      remote server's public key (64 hex chars)\n"
        "  --server-key-file P   file containing the server public key hex\n"
        "  --title TITLE         job title (default: file name or 'print-job')\n"
        "  FILE                  job to send (default: stdin)\n\n"
        "For a remote server the client identity lives in CIPHERJET_HOME "
        "('cipherjet-keygen net-client').\n";
}

std::string read_file_text(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw ConfigError("cannot read: " + path);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return s;
}

}  // namespace

int main(int argc, char** argv) try {
    if (sodium_init() < 0) { std::cerr << "sodium init failed\n"; return 1; }
    net::socket_startup();

    std::string host, server_key_hex, server_key_file, title, input_file;
    std::uint16_t port = 9310;
    bool port_from_cli = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--version") { std::cout << "cipherjet-send " CIPHERJET_VERSION "\n"; return 0; }
        else if (a == "--help") { usage(); return 0; }
        else if (a == "--host" && i + 1 < argc) host = argv[++i];
        else if (a == "--port" && i + 1 < argc) { port = static_cast<std::uint16_t>(std::stoi(argv[++i])); port_from_cli = true; }
        else if (a == "--server-key" && i + 1 < argc) server_key_hex = argv[++i];
        else if (a == "--server-key-file" && i + 1 < argc) server_key_file = argv[++i];
        else if (a == "--title" && i + 1 < argc) title = argv[++i];
        else if (!a.empty() && a[0] != '-') input_file = a;
        else { usage(); return 2; }
    }

    Config cfg = Config::load();

    // Fill any unset options from an optional client.conf in the data directory,
    // so once it's set up a client can simply run:  cipherjet-send report.pdf
    //     host = print.example.com
    //     port = 9310
    //     server_key = <64-hex server public key>
    {
        std::ifstream cf(platform::path_join(cfg.data_dir, "client.conf"));
        std::string line;
        auto trim = [](std::string& s) {
            std::size_t b = s.find_first_not_of(" \t\r\n");
            std::size_t e = s.find_last_not_of(" \t\r\n");
            s = (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
        };
        while (std::getline(cf, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = line.substr(0, eq), v = line.substr(eq + 1);
            trim(k); trim(v);
            if (k == "host" && host.empty()) host = v;
            else if (k == "port" && !port_from_cli) port = static_cast<std::uint16_t>(std::stoi(v));
            else if (k == "server_key" && server_key_hex.empty() && server_key_file.empty()) server_key_hex = v;
        }
    }
    // Decide how we reach the server:
    //   * no host configured  -> discover one on the LAN and print anonymously
    //     (zero setup, still encrypted to the server's discovered key);
    //   * host configured      -> a remote server: authenticate with our identity
    //     and seal to its pinned key.
    net::PublicKey server_pk{};
    bool anonymous = false;

    if (host.empty()) {
        std::cerr << "cipherjet-send: looking for a printer on the local network...\n";
        auto found = net::discover_server(port, 1200);
        if (!found) {
            std::cerr << "cipherjet-send: none found on the LAN. For a remote server, "
                         "pass --host (with --server-key), or set them in "
                      << platform::path_join(cfg.data_dir, "client.conf") << "\n";
            return 2;
        }
        host = found->ip;
        port = found->tcp_port;
        server_pk = found->pk;
        anonymous = true;
        std::cerr << "cipherjet-send: found printer at " << host << ":" << port << "\n";
    } else {
        if (!server_key_hex.empty()) {
            server_pk = net::parse_pubkey_hex(server_key_hex);
        } else if (!server_key_file.empty()) {
            server_pk = net::parse_pubkey_hex(read_file_text(server_key_file));
        } else {
            std::string local = platform::path_join(cfg.data_dir, "server_box.pub");
            if (std::ifstream(local).good()) {
                server_pk = net::parse_pubkey_hex(read_file_text(local));
            } else {
                std::cerr << "cipherjet-send: provide --server-key or --server-key-file for a remote server\n";
                return 2;
            }
        }
    }

    // A remote (authenticated) send needs our identity key; a discovered LAN send
    // does not.
    net::ClientIdentity id;
    if (!anonymous) {
        try {
            id = net::load_client_identity(cfg.data_dir);
        } catch (const Error&) {
            std::cerr << "cipherjet-send: no client identity — run 'cipherjet-keygen net-client' first.\n";
            return 2;
        }
    }

    // Choose the input source and a title.
    std::ifstream file_in;
    std::istream* in = &std::cin;
    if (!input_file.empty()) {
        file_in.open(input_file, std::ios::binary);
        if (!file_in) { std::cerr << "cipherjet-send: cannot open " << input_file << "\n"; return 2; }
        in = &file_in;
        if (title.empty()) {
            auto slash = input_file.find_last_of("/\\");
            title = (slash == std::string::npos) ? input_file : input_file.substr(slash + 1);
        }
    }
    if (title.empty()) title = "print-job";

    // Connect and run the handshake (protocol v2: hello = magic|ver|flags|challenge).
    net::Conn conn = net::Conn::connect(host, port);
    std::uint8_t hello[6 + net::kContextBytes];
    conn.recv_exact(hello, sizeof(hello));
    if (std::memcmp(hello, kHello, 4) != 0 || hello[4] != kProtoVersion) {
        std::cerr << "cipherjet-send: unexpected server handshake\n";
        return 1;
    }
    const std::uint8_t* challenge = hello + 6;

    if (anonymous) {
        std::uint8_t mode = kAuthAnon;
        conn.send_all(&mode, 1);
    } else {
        std::uint8_t mode = kAuthSigned;
        conn.send_all(&mode, 1);
        std::vector<std::uint8_t> signed_msg(kAuthDomain, kAuthDomain + std::strlen(kAuthDomain));
        signed_msg.insert(signed_msg.end(), challenge, challenge + net::kContextBytes);
        std::uint8_t sig[crypto_sign_BYTES];
        crypto_sign_detached(sig, nullptr, signed_msg.data(), signed_msg.size(), id.sk.data());
        conn.send_all(id.pk.data(), id.pk.size());
        conn.send_all(sig, sizeof(sig));
    }

    std::uint8_t status = 0;
    conn.recv_exact(&status, 1);
    if (status != 1) {
        std::cerr << "cipherjet-send: server rejected the job"
                  << (anonymous ? " (LAN printing may be disabled on the server)."
                                : " (is our key authorised on the server?).") << "\n";
        return 1;
    }

    // Seal and stream the job, bound to this session's challenge.
    net::ByteSource src = [&](std::uint8_t* b, std::size_t n) -> std::size_t {
        in->read(reinterpret_cast<char*>(b), static_cast<std::streamsize>(n));
        return static_cast<std::size_t>(in->gcount());
    };
    net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
        conn.send_all(d, n);
    };
    std::uint8_t job_id[16];
    std::uint64_t bytes = net::seal_job(src, sink, server_pk, challenge, title,
                                        static_cast<std::int64_t>(std::time(nullptr)), job_id);
    conn.shutdown_write();

    std::uint8_t done = 0;
    conn.recv_exact(&done, 1);  // server confirms release

    std::cerr << "cipherjet-send: sent job " << util::to_hex(job_id, sizeof(job_id))
              << " (" << bytes << " bytes) to " << host << ":" << port
              << (done == 1 ? " — released" : " — server reported a problem") << "\n";
    return done == 1 ? 0 : 1;

} catch (const std::exception& e) {
    std::cerr << "cipherjet-send: " << e.what() << "\n";
    return 1;
}
