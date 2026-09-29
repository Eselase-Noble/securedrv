// =============================================================================
//  test_main.cpp — Self-contained unit tests for the Cipherjet engine.
//
//  No external test framework: a tiny CHECK/SECTION harness keeps the build
//  dependency-free. Tests cover the security-critical behaviours:
//    * encrypt/decrypt round-trips across edge-case sizes,
//    * detection of ciphertext tampering,
//    * rejection of the wrong key/passphrase,
//    * master-key file create/load/rotate,
//    * audit-log hash-chain verification and tamper detection.
//
//  The tests are hermetic: they point CIPHERJET_HOME at a fresh temp directory.
// =============================================================================
#include <sodium.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "securedrv/audit_log.hpp"
#include "securedrv/config.hpp"
#include "securedrv/crypto_engine.hpp"
#include "securedrv/errors.hpp"
#include "securedrv/key_manager.hpp"
#include "securedrv/net_crypto.hpp"
#include "securedrv/net_keys.hpp"
#include "securedrv/secure_buffer.hpp"

using namespace securedrv;
namespace fs = std::filesystem;

// ---- Minimal test harness ---------------------------------------------------
static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond)                                                           \
    do {                                                                      \
        ++g_checks;                                                           \
        if (!(cond)) {                                                        \
            ++g_failures;                                                     \
            std::cerr << "  FAIL: " << #cond << "  (" << __FILE__ << ":"      \
                      << __LINE__ << ")\n";                                   \
        }                                                                     \
    } while (0)

#define SECTION(name) std::cerr << "[ RUN ] " << name << "\n"

/// Build a random Master Key directly in guarded memory (for engine tests).
static SecureBuffer random_master_key() {
    SecureBuffer mk(CryptoEngine::master_key_bytes());
    randombytes_buf(mk.data(), mk.size());
    return mk;
}

/// Fill a string with `n` deterministic-but-varied bytes.
static std::string make_payload(std::size_t n) {
    std::string s;
    s.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(static_cast<char>((i * 131 + 7) & 0xFF));
    }
    return s;
}

// ---- Tests ------------------------------------------------------------------

static void test_secure_buffer() {
    SECTION("SecureBuffer move semantics");
    SecureBuffer a(32);
    a.data()[0] = 0xAB;
    SecureBuffer b(std::move(a));
    CHECK(b.size() == 32);
    CHECK(b.data()[0] == 0xAB);
    CHECK(a.data() == nullptr);  // moved-from is emptied
}

static void test_roundtrip_sizes() {
    SECTION("CryptoEngine round-trip across sizes");
    CryptoEngine engine;
    SecureBuffer mk = random_master_key();

    const std::size_t sizes[] = {
        0, 1, 100, CryptoEngine::kChunkSize - 1, CryptoEngine::kChunkSize,
        CryptoEngine::kChunkSize + 1, 3 * CryptoEngine::kChunkSize + 123};

    for (std::size_t sz : sizes) {
        std::string plain = make_payload(sz);
        std::stringstream ct(std::ios::in | std::ios::out | std::ios::binary);
        std::istringstream pt_in(plain);

        JobMetadata meta;
        meta.title = "unit-test";
        meta.created_unix = 1000;
        std::uint64_t n = engine.encrypt_stream(pt_in, ct, mk, meta);
        CHECK(n == sz);
        CHECK(meta.original_size == sz);

        ct.seekg(0);
        std::ostringstream out;
        JobMetadata meta2;
        engine.decrypt_stream(ct, out, mk, meta2);
        CHECK(out.str() == plain);
        CHECK(meta2.title == "unit-test");
        CHECK(meta2.original_size == sz);
        CHECK(meta2.id_hex() == meta.id_hex());
    }
}

static void test_tamper_detection() {
    SECTION("Tampered ciphertext is rejected");
    CryptoEngine engine;
    SecureBuffer mk = random_master_key();

    std::string plain = make_payload(5000);
    std::istringstream pt_in(plain);
    std::stringstream ct(std::ios::in | std::ios::out | std::ios::binary);
    JobMetadata meta;
    meta.title = "tamper";
    engine.encrypt_stream(pt_in, ct, mk, meta);

    std::string blob = ct.str();
    blob.back() ^= 0x01;  // flip a bit in the final ciphertext chunk

    std::istringstream bad(blob);
    std::ostringstream out;
    JobMetadata m2;
    bool threw = false;
    try {
        engine.decrypt_stream(bad, out, mk, m2);
    } catch (const IntegrityError&) {
        threw = true;
    }
    CHECK(threw);
}

static void test_wrong_key() {
    SECTION("Wrong master key is rejected");
    CryptoEngine engine;
    SecureBuffer mk1 = random_master_key();
    SecureBuffer mk2 = random_master_key();

    std::istringstream pt_in(make_payload(256));
    std::stringstream ct(std::ios::in | std::ios::out | std::ios::binary);
    JobMetadata meta;
    engine.encrypt_stream(pt_in, ct, mk1, meta);

    ct.seekg(0);
    std::ostringstream out;
    JobMetadata m2;
    bool threw = false;
    try {
        engine.decrypt_stream(ct, out, mk2, m2);
    } catch (const IntegrityError&) {
        threw = true;
    }
    CHECK(threw);
}

static void test_key_manager(const std::string& home) {
    SECTION("KeyManager create / load / rotate");
    const std::string key_path = (fs::path(home) / "master.spmk").string();

    KeyManager::create_master_key(key_path, "correct horse battery",
                                  KeyManager::KdfStrength::kInteractive);
    CHECK(KeyManager::exists(key_path));

    // Correct passphrase unlocks.
    SecureBuffer mk = KeyManager::load_master_key(key_path, "correct horse battery");
    CHECK(mk.size() == CryptoEngine::master_key_bytes());

    // Wrong passphrase is rejected.
    bool threw = false;
    try {
        KeyManager::load_master_key(key_path, "wrong");
    } catch (const IntegrityError&) {
        threw = true;
    }
    CHECK(threw);

    // Refuse to overwrite an existing key.
    bool refused = false;
    try {
        KeyManager::create_master_key(key_path, "x",
                                      KeyManager::KdfStrength::kInteractive);
    } catch (const ConfigError&) {
        refused = true;
    }
    CHECK(refused);

    // Rotate the passphrase; the key bytes must stay the same.
    KeyManager::change_passphrase(key_path, "correct horse battery", "new-pass-9",
                                  KeyManager::KdfStrength::kInteractive);
    SecureBuffer mk2 = KeyManager::load_master_key(key_path, "new-pass-9");
    CHECK(sodium_memcmp(mk.data(), mk2.data(), mk.size()) == 0);
}

static void test_key_manager_end_to_end(const std::string& home) {
    SECTION("End-to-end: keyfile-derived key encrypts & decrypts a job");
    const std::string key_path = (fs::path(home) / "e2e.spmk").string();
    KeyManager::create_master_key(key_path, "pw-e2e",
                                  KeyManager::KdfStrength::kInteractive);
    SecureBuffer mk = KeyManager::load_master_key(key_path, "pw-e2e");

    CryptoEngine engine;
    std::string plain = make_payload(9000);
    std::istringstream pt_in(plain);
    std::stringstream ct(std::ios::in | std::ios::out | std::ios::binary);
    JobMetadata meta;
    meta.title = "e2e-doc";
    engine.encrypt_stream(pt_in, ct, mk, meta);

    ct.seekg(0);
    std::ostringstream out;
    JobMetadata m2;
    engine.decrypt_stream(ct, out, mk, m2);
    CHECK(out.str() == plain);
    CHECK(m2.title == "e2e-doc");
}

static void test_audit_log(const std::string& home) {
    SECTION("Audit log chain verify + tamper detection");
    const std::string log_path = (fs::path(home) / "audit.log").string();
    {
        AuditLog log(log_path);
        log.record("encrypt", "aabbcc", "bytes=10");
        log.record("release", "aabbcc", "bytes=10 removed=yes");
        log.record("encrypt", "ddeeff", "bytes=20");
        CHECK(log.verify(nullptr));
    }

    // Corrupt the middle line and confirm verification fails there. Read and
    // rewrite in binary so we don't perturb line endings — the log is stored
    // with '\n' terminators, and on Windows a text-mode rewrite would turn every
    // '\n' into "\r\n", corrupting line 1 instead of just the line we target.
    std::vector<std::string> lines;
    {
        std::ifstream f(log_path, std::ios::binary);
        std::string l;
        while (std::getline(f, l)) lines.push_back(l);
    }
    CHECK(lines.size() == 3);
    if (lines.size() == 3) {
        lines[1] += "x";  // mutate the payload of line 2
        std::ofstream f(log_path, std::ios::trunc | std::ios::binary);
        for (auto& l : lines) f << l << "\n";
    }
    AuditLog log2(log_path);
    std::size_t bad = 0;
    CHECK(!log2.verify(&bad));
    CHECK(bad == 2);
}

// Helper: make a ByteSource that reads from a std::string.
static net::ByteSource string_source(const std::string& s, std::size_t& pos) {
    return [&s, &pos](std::uint8_t* b, std::size_t n) -> std::size_t {
        std::size_t k = std::min(n, s.size() - pos);
        std::memcpy(b, s.data() + pos, k);
        pos += k;
        return k;
    };
}

static void test_net_crypto() {
    SECTION("Sealed job round-trip + context/key checks");
    net::ServerBoxKey server;
    crypto_box_keypair(server.pk.data(), server.sk.data());

    std::string plain = make_payload(9000);
    std::uint8_t ctx[net::kContextBytes];
    randombytes_buf(ctx, sizeof(ctx));

    // Seal to the server's public key.
    std::string blob;
    {
        std::size_t pos = 0;
        auto src = string_source(plain, pos);
        net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
            blob.append(reinterpret_cast<const char*>(d), n);
        };
        std::uint8_t jid[16];
        std::uint64_t n = net::seal_job(src, sink, server.pk, ctx, "net-doc", 4242, jid);
        CHECK(n == plain.size());
    }

    // Open with the right key and context.
    {
        std::size_t pos = 0;
        auto src = string_source(blob, pos);
        std::string out;
        net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
            out.append(reinterpret_cast<const char*>(d), n);
        };
        net::SealedJobMeta meta;
        net::open_job(src, sink, server, ctx, meta);
        CHECK(out == plain);
        CHECK(meta.title == "net-doc");
        CHECK(meta.created_unix == 4242);
        CHECK(meta.plaintext_bytes == plain.size());
    }

    // Wrong context (replay into a different session) is rejected.
    {
        std::uint8_t bad[net::kContextBytes];
        randombytes_buf(bad, sizeof(bad));
        std::size_t pos = 0;
        auto src = string_source(blob, pos);
        std::string out;
        net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
            out.append(reinterpret_cast<const char*>(d), n);
        };
        net::SealedJobMeta meta;
        bool threw = false;
        try { net::open_job(src, sink, server, bad, meta); }
        catch (const IntegrityError&) { threw = true; }
        CHECK(threw);
    }

    // A different server key cannot open the job.
    {
        net::ServerBoxKey other;
        crypto_box_keypair(other.pk.data(), other.sk.data());
        std::size_t pos = 0;
        auto src = string_source(blob, pos);
        std::string out;
        net::ByteSink sink = [&](const std::uint8_t* d, std::size_t n) {
            out.append(reinterpret_cast<const char*>(d), n);
        };
        net::SealedJobMeta meta;
        bool threw = false;
        try { net::open_job(src, sink, other, ctx, meta); }
        catch (const IntegrityError&) { threw = true; }
        CHECK(threw);
    }
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 99;
    }

    // Hermetic data directory for the KeyManager/AuditLog tests.
    fs::path home = fs::temp_directory_path() /
                    ("securedrv-test-" + std::to_string(
                         static_cast<unsigned long long>(randombytes_random())));
    fs::create_directories(home);
#if defined(_WIN32)
    _putenv_s("CIPHERJET_HOME", home.string().c_str());
#else
    setenv("CIPHERJET_HOME", home.string().c_str(), 1);
#endif

    test_secure_buffer();
    test_roundtrip_sizes();
    test_tamper_detection();
    test_wrong_key();
    test_key_manager(home.string());
    test_key_manager_end_to_end(home.string());
    test_audit_log(home.string());
    test_net_crypto();

    // Clean up the temp directory (best effort).
    std::error_code ec;
    fs::remove_all(home, ec);

    std::cerr << "\n" << (g_checks - g_failures) << "/" << g_checks
              << " checks passed\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " CHECK(S) FAILED\n";
    return 1;
}
