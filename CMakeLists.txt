# =============================================================================
#  SecureDrv — Encrypting Printer Driver
#  Top-level CMake build definition.
#
#  Targets produced:
#    * securedrv_core      (static library)  — reusable crypto / spool engine
#    * securedrv           (executable)      — the CUPS-style filter "driver"
#    * securedrv-release   (executable)      — decrypt & release a spooled job
#    * securedrv-keygen    (executable)      — create / rotate the master key
#    * securedrv_tests     (executable)      — self-contained unit tests
#
#  Build:
#    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#    cmake --build build -j
#    ctest --test-dir build --output-on-failure
# =============================================================================
cmake_minimum_required(VERSION 3.16)

project(SecureDrv
    VERSION 1.0.0
    DESCRIPTION "Enterprise encrypting printer driver (CUPS filter) using libsodium"
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

# Security-oriented compile & link hardening flags. These are best-effort:
# unsupported flags are simply ignored by the compiler feature checks below.
include(CheckCXXCompilerFlag)
function(securedrv_add_flag flag var)
    check_cxx_compiler_flag("${flag}" ${var})
    if(${var})
        add_compile_options("${flag}")
    endif()
endfunction()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
securedrv_add_flag(-fstack-protector-strong HAVE_STACK_PROTECTOR)
securedrv_add_flag(-fstack-clash-protection HAVE_STACK_CLASH)
securedrv_add_flag(-D_FORTIFY_SOURCE=2       HAVE_FORTIFY)   # honoured in optimized builds

# ---- Dependencies -----------------------------------------------------------
# libsodium provides all cryptographic primitives. We locate it via pkg-config,
# which is how Homebrew installs it on macOS and how distros ship it on Linux.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

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
)

target_include_directories(securedrv_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(securedrv_core PUBLIC PkgConfig::SODIUM)

# =============================================================================
#  Executables
# =============================================================================
add_executable(securedrv         src/driver_filter.cpp)
target_link_libraries(securedrv         PRIVATE securedrv_core)

add_executable(securedrv-release tools/release_main.cpp)
target_link_libraries(securedrv-release PRIVATE securedrv_core)

add_executable(securedrv-keygen  tools/keygen_main.cpp)
target_link_libraries(securedrv-keygen  PRIVATE securedrv_core)

# =============================================================================
#  Tests
# =============================================================================
enable_testing()
add_executable(securedrv_tests tests/test_main.cpp)
target_link_libraries(securedrv_tests PRIVATE securedrv_core)
add_test(NAME unit_tests COMMAND securedrv_tests)

# ---- Install rules (enterprise deployment) ----------------------------------
include(GNUInstallDirs)
install(TARGETS securedrv securedrv-release securedrv-keygen
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
