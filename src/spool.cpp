// =============================================================================
//  spool.cpp — Encrypted job spool implementation.
// =============================================================================
#include "securedrv/spool.hpp"

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <utility>
#include <vector>

#include "securedrv/errors.hpp"
#include "securedrv/platform.hpp"

namespace fs = std::filesystem;

namespace securedrv {

namespace {
constexpr const char* kExt = ".spjob";
}

Spool::Spool(std::string spool_dir) : dir_(std::move(spool_dir)) {}

std::string Spool::path_for(const std::string& job_id_hex) const {
    return platform::path_join(dir_, job_id_hex + kExt);
}

std::vector<std::string> Spool::list() const {
    // Collect (mtime, id) pairs so we can present jobs in FIFO order.
    std::vector<std::pair<fs::file_time_type, std::string>> items;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir_, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const fs::path& p = entry.path();
        if (p.extension() != kExt) continue;
        auto t = fs::last_write_time(p, ec);
        if (ec) continue;
        items.emplace_back(t, p.stem().string());
    }
    std::sort(items.begin(), items.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<std::string> ids;
    ids.reserve(items.size());
    for (auto& it : items) ids.push_back(std::move(it.second));
    return ids;
}

bool Spool::secure_remove(const std::string& job_id_hex) const {
    const std::string path = path_for(job_id_hex);
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec) return false;  // Not present.

    // Overwrite existing bytes with random data before unlinking. This is a
    // best-effort hygiene measure layered on top of the fact that the on-disk
    // job was encrypted to begin with.
    {
        std::ofstream f(path, std::ios::binary | std::ios::in | std::ios::out);
        if (f) {
            std::vector<unsigned char> chunk(64 * 1024);
            std::uintmax_t remaining = size;
            while (remaining > 0) {
                std::size_t n = static_cast<std::size_t>(
                    std::min<std::uintmax_t>(remaining, chunk.size()));
                randombytes_buf(chunk.data(), n);
                f.write(reinterpret_cast<const char*>(chunk.data()),
                        static_cast<std::streamsize>(n));
                remaining -= n;
            }
            f.flush();
        }
    }
    fs::remove(path, ec);
    return !ec;
}

}  // namespace securedrv
