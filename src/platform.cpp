// =============================================================================
//  platform.cpp — Implementation of the cross-platform OS abstraction layer.
//
//  The file is split into a Windows branch and a POSIX branch guarded by the
//  _WIN32 macro. Everything above the branches is shared. This is the ONLY
//  translation unit in the engine that includes OS-specific headers.
// =============================================================================
#include "securedrv/platform.hpp"

#include <cstdlib>
#include <filesystem>
#include <system_error>
#include <vector>

#include "securedrv/errors.hpp"

#if defined(_WIN32)
  #include <io.h>
  #include <fcntl.h>
  #include <windows.h>
  #include <aclapi.h>
#else
  #include <sys/stat.h>
  #include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace securedrv::platform {

// -----------------------------------------------------------------------------
//  Shared helpers
// -----------------------------------------------------------------------------

std::string path_join(const std::string& a, const std::string& b) {
    // std::filesystem already knows the native separator; use it so the same
    // code produces valid paths on every OS.
    return (fs::path(a) / b).string();
}

void make_directories(const std::string& path) {
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec) {
        throw IoError("cannot create directory '" + path + "': " + ec.message());
    }
}

// -----------------------------------------------------------------------------
//  Windows implementation
// -----------------------------------------------------------------------------
#if defined(_WIN32)

void set_standard_streams_binary() {
    // Without this, the CRT translates '\n' <-> "\r\n" on the standard streams,
    // which silently corrupts binary print jobs and ciphertext.
    _setmode(_fileno(stdin),  _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
}

// Build a DACL that grants full control ONLY to the current user token, then
// apply it to the named object (file or directory). This is the Windows
// analogue of chmod 0600 / 0700.
static void apply_owner_only_dacl(const std::string& path) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        throw IoError("OpenProcessToken failed for '" + path + "'");
    }

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<unsigned char> buf(len);
    if (!GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        CloseHandle(token);
        throw IoError("GetTokenInformation failed for '" + path + "'");
    }
    CloseHandle(token);
    auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());

    EXPLICIT_ACCESSA ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName    = reinterpret_cast<LPSTR>(user->User.Sid);

    PACL acl = nullptr;
    if (SetEntriesInAclA(1, &ea, nullptr, &acl) != ERROR_SUCCESS) {
        throw IoError("SetEntriesInAcl failed for '" + path + "'");
    }

    // PROTECTED_DACL_SECURITY_INFORMATION detaches inherited ACEs, so only the
    // single owner-only ACE we just built remains in force.
    DWORD rc = SetNamedSecurityInfoA(
        const_cast<LPSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, acl, nullptr);
    LocalFree(acl);
    if (rc != ERROR_SUCCESS) {
        throw IoError("SetNamedSecurityInfo failed for '" + path + "'");
    }
}

void restrict_to_owner(const std::string& path)     { apply_owner_only_dacl(path); }
void restrict_dir_to_owner(const std::string& path) { apply_owner_only_dacl(path); }

std::string default_data_dir() {
    if (const char* over = std::getenv("CIPHERJET_HOME"); over && *over) {
        make_directories(over);
        restrict_dir_to_owner(over);
        return over;
    }
    const char* appdata = std::getenv("APPDATA");
    std::string base = (appdata && *appdata) ? appdata : ".";
    std::string dir  = path_join(base, "Cipherjet");
    make_directories(dir);
    restrict_dir_to_owner(dir);
    return dir;
}

// -----------------------------------------------------------------------------
//  POSIX implementation (Linux, macOS, *BSD)
// -----------------------------------------------------------------------------
#else

void set_standard_streams_binary() {
    // POSIX streams are already byte-transparent; nothing to do.
}

void restrict_to_owner(const std::string& path) {
    // 0600 = read/write for owner, nothing for group or others.
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw IoError("chmod 0600 failed for '" + path + "'");
    }
}

void restrict_dir_to_owner(const std::string& path) {
    // 0700 = full access for owner, nothing for group or others.
    if (::chmod(path.c_str(), S_IRWXU) != 0) {
        throw IoError("chmod 0700 failed for '" + path + "'");
    }
}

std::string default_data_dir() {
    // 1) Explicit override wins everywhere and makes tests hermetic.
    if (const char* over = std::getenv("CIPHERJET_HOME"); over && *over) {
        make_directories(over);
        restrict_dir_to_owner(over);
        return over;
    }
    // 2) Respect the XDG base-directory spec when present.
    std::string base;
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        base = path_join(xdg, "cipherjet");
    } else if (const char* home = std::getenv("HOME"); home && *home) {
        base = path_join(path_join(home, ".local/share"), "cipherjet");
    } else {
        base = "./cipherjet";  // Last-resort fallback (e.g. no HOME in a daemon).
    }
    make_directories(base);
    restrict_dir_to_owner(base);
    return base;
}

#endif  // _WIN32

}  // namespace securedrv::platform
