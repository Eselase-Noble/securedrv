# =============================================================================
#  Cipherjet — Encrypting Printer Driver
#  Top-level CMake build definition.
#
#  Targets produced:
#    * securedrv_core      (static library)  — reusable crypto / spool engine
#    * cipherjet           (executable)      — the driver / CUPS backend
#    * cipherjet-release   (executable)      — decrypt & release a spooled job
#    * cipherjet-keygen    (executable)      — create / rotate the master key
#    * securedrv_tests     (executable)      — self-contained unit tests
#
#  Build:
#    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#    cmake --build build -j
#    ctest --test-dir build --output-on-failure
# =============================================================================
cmake_minimum_required(VERSION 3.16)

project(Cipherjet
    VERSION 1.2.1
    DESCRIPTION "Cipherjet — enterprise encrypting printer driver using libsodium"
    LANGUAGES CXX)

# ---- Global language / hardening settings -----------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Export compile_commands.json so editors / clang-tidy can index the project.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Security-oriented compile & link hardening flags, chosen per compiler so the
# same tree builds cleanly with GCC/Clang (Linux, macOS) and MSVC (Windows).
include(CheckCXXCompilerFlag)
function(securedrv_add_flag flag var)
    check_cxx_compiler_flag("${flag}" ${var})
    if(${var})
        add_compile_options("${flag}")
    endif()
endfunction()

if(MSVC)
    # /W3 warnings, standards conformance, and control-flow-guard hardening.
    add_compile_options(/W3 /permissive- /guard:cf)
    add_link_options(/guard:cf)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    securedrv_add_flag(-fstack-protector-strong HAVE_STACK_PROTECTOR)
    securedrv_add_flag(-fstack-clash-protection HAVE_STACK_CLASH)
    securedrv_add_flag(-D_FORTIFY_SOURCE=2       HAVE_FORTIFY)  # honoured in optimized builds
endif()

# ---- Dependencies -----------------------------------------------------------
# libsodium provides all cryptographic primitives. Discovery is cross-platform:
#   0) CIPHERJET_SODIUM_ROOT — an explicit prefix holding a *static* libsodium,
#      used by the release builds to produce fully self-contained binaries
#   1) pkg-config        (Homebrew on macOS, distro -dev packages on Linux)
#   2) unofficial-sodium CONFIG package (how vcpkg exposes it on Windows)
#   3) a manual find as a last resort
# The result is normalised to one link target: securedrv_sodium.
add_library(securedrv_sodium INTERFACE)
if(CIPHERJET_SODIUM_ROOT)
    message(STATUS "Using static libsodium from ${CIPHERJET_SODIUM_ROOT}")
    find_library(SODIUM_STATIC_LIB NAMES sodium libsodium
                 PATHS "${CIPHERJET_SODIUM_ROOT}/lib" NO_DEFAULT_PATH)
    if(NOT SODIUM_STATIC_LIB)
        message(FATAL_ERROR "CIPHERJET_SODIUM_ROOT set but no libsodium found under it")
    endif()
    target_include_directories(securedrv_sodium INTERFACE "${CIPHERJET_SODIUM_ROOT}/include")
    target_link_libraries(securedrv_sodium INTERFACE "${SODIUM_STATIC_LIB}")
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
    endif()
    if(TARGET PkgConfig::SODIUM)
        target_link_libraries(securedrv_sodium INTERFACE PkgConfig::SODIUM)
    else()
        find_package(unofficial-sodium CONFIG QUIET)
        if(TARGET unofficial-sodium::sodium)
            target_link_libraries(securedrv_sodium INTERFACE unofficial-sodium::sodium)
        else()
            find_path(SODIUM_INCLUDE_DIR sodium.h)
            find_library(SODIUM_LIBRARY NAMES sodium libsodium)
            if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
                message(FATAL_ERROR "libsodium not found (install libsodium-dev / brew libsodium / vcpkg libsodium)")
            endif()
            target_include_directories(securedrv_sodium INTERFACE "${SODIUM_INCLUDE_DIR}")
            target_link_libraries(securedrv_sodium INTERFACE "${SODIUM_LIBRARY}")
        endif()
    endif()
endif()
# When libsodium is linked statically on Windows (vcpkg *-static triplets),
# consumers must define SODIUM_STATIC so headers don't use __declspec(dllimport).
if(WIN32)
    target_compile_definitions(securedrv_sodium INTERFACE SODIUM_STATIC)
endif()
# On Linux, also fold in the C++ runtime so a downloaded binary doesn't depend on
# a matching libstdc++/libgcc being present. (macOS ships libc++; Windows is
# handled by the static vcpkg triplet.)
if(UNIX AND NOT APPLE)
    add_link_options(-static-libgcc -static-libstdc++)
endif()

# =============================================================================
#  Core library: all reusable engine code lives here so that the driver, the
#  release tool, the keygen tool and the tests all share one audited codebase.
# =============================================================================
add_library(securedrv_core STATIC
    src/secure_buffer.cpp
    src/platform.cpp
    src/crypto_engine.cpp
    src/key_manager.cpp
    src/audit_log.cpp
    src/spool.cpp
    src/config.cpp
    src/net_keys.cpp
    src/net_crypto.cpp
    src/socket.cpp
    src/discovery.cpp
)

target_include_directories(securedrv_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(securedrv_core PUBLIC securedrv_sodium)

# Windows sockets live in ws2_32; POSIX sockets need no extra library.
if(WIN32)
    target_link_libraries(securedrv_core PUBLIC ws2_32)
endif()

# The server runs its LAN-discovery responder on a background thread.
find_package(Threads REQUIRED)
target_link_libraries(securedrv_core PUBLIC Threads::Threads)

# Propagate the project version into the code as CIPHERJET_VERSION so every
# executable can answer `--version`. Single source of truth: project(... VERSION).
target_compile_definitions(securedrv_core
    PUBLIC CIPHERJET_VERSION="${PROJECT_VERSION}")

# =============================================================================
#  Executables
# =============================================================================
# The driver. Also serves as the CUPS backend (see install/).
add_executable(cipherjet         src/driver_filter.cpp)
target_link_libraries(cipherjet         PRIVATE securedrv_core)

add_executable(cipherjet-release tools/release_main.cpp)
target_link_libraries(cipherjet-release PRIVATE securedrv_core)

add_executable(cipherjet-keygen  tools/keygen_main.cpp)
target_link_libraries(cipherjet-keygen  PRIVATE securedrv_core)

# Networked printing: client sender and server/release daemon.
add_executable(cipherjet-send    tools/send_main.cpp)
target_link_libraries(cipherjet-send    PRIVATE securedrv_core)

add_executable(cipherjet-server  tools/server_main.cpp)
target_link_libraries(cipherjet-server  PRIVATE securedrv_core)

# =============================================================================
#  Tests
# =============================================================================
enable_testing()
add_executable(securedrv_tests tests/test_main.cpp)
target_link_libraries(securedrv_tests PRIVATE securedrv_core)
add_test(NAME unit_tests COMMAND securedrv_tests)

# ---- Install rules (enterprise deployment) ----------------------------------
include(GNUInstallDirs)
install(TARGETS cipherjet cipherjet-release cipherjet-keygen
                cipherjet-send cipherjet-server
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
