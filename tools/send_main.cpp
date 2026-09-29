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
constexpr std::uint8_t kProtoVersion = 1;
constexpr const char*  kAuthDomain = "cipherjet-auth-v1";

void usage() {
    std::cerr <<
        "cipherjet-send — send an encrypted print job to a Cipherjet server\n"
        "Usage:\n"
        "  cipherjet-send --host HOST [--port N] \\\n"
        "                 (--server-key HEX | --server-key-file PATH) \\\n"
        "                 [--title TITLE] [FILE]\n\n"
        "  --host HOST            server hostname or IP (reachable from here)\n"
        "  --port N              server port (default 9310)\n"
        "  --server-key HEX      server public key (64 hex chars)\n"
        "  --server-key-file P   file containing the server public key hex\n"
        "  --title TITLE         job title (default: file name or 'print-job')\n"
        "  FILE                  job to send (default: stdin)\n\n"
        "The client identity lives in CIPHERJET_HOME "
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
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--version") { std::cout << "cipherjet-send " CIPHERJET_VERSION "\n"; return 0; }
        else if (a == "--help") { usage(); return 0; }
        else if (a == "--host" && i + 1 < argc) host = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        else if (a == "--server-key" && i + 1 < argc) server_key_hex = argv[++i];
        else if (a == "--server-key-file" && i + 1 < argc) server_key_file = argv[++i];
        else if (a == "--title" && i + 1 < argc) title = argv[++i];
        else if (!a.empty() && a[0] != '-') input_file = a;
        else { usage(); return 2; }
    }
    if (host.empty()) { std::cerr << "cipherjet-send: --host is required\n"; return 2; }

    Config cfg = Config::load();

    // Resolve the server's public key: explicit hex, a file, or the local
    // server_box.pub (handy when testing client and server on one machine).
    net::PublicKey server_pk{};
    if (!server_key_hex.empty()) {
        server_pk = net::parse_pubkey_hex(server_key_hex);
    } else if (!server_key_file.empty()) {
        server_pk = net::parse_pubkey_hex(read_file_text(server_key_file));
    } else {
        std::string local = platform::path_join(cfg.data_dir, "server_box.pub");
        if (std::ifstream(local).good()) {
            server_pk = net::parse_pubkey_hex(read_file_text(local));
        } else {
            std::cerr << "cipherjet-send: provide --server-key or --server-key-file\n";
            return 2;
        }
    }

    net::ClientIdentity id;
    try {
        id = net::load_client_identity(cfg.data_dir);
    } catch (const Error&) {
        std::cerr << "cipherjet-send: no client identity — run 'cipherjet-keygen net-client' first.\n";
        return 2;
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

    // Connect and run the handshake.
    net::Conn conn = net::Conn::connect(host, port);

    std::uint8_t hello[5 + net::kContextBytes];
    conn.recv_exact(hello, sizeof(hello));
    if (std::memcmp(hello, kHello, 4) != 0 || hello[4] != kProtoVersion) {
        std::cerr << "cipherjet-send: unexpected server handshake\n";
        return 1;
    }
    const std::uint8_t* challenge = hello + 5;

    // Sign the challenge with our identity key to authenticate.
    std::vector<std::uint8_t> signed_msg(kAuthDomain, kAuthDomain + std::strlen(kAuthDomain));
    signed_msg.insert(signed_msg.end(), challenge, challenge + net::kContextBytes);
    std::uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, signed_msg.data(), signed_msg.size(), id.sk.data());

    conn.send_all(id.pk.data(), id.pk.size());
    conn.send_all(sig, sizeof(sig));

    std::uint8_t status = 0;
    conn.recv_exact(&status, 1);
    if (status != 1) {
        std::cerr << "cipherjet-send: server rejected this client "
                     "(is our key in the server's authorized_clients?)\n";
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
