# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

cmake_minimum_required(VERSION 3.22)

option(IO_URING_ENABLED "Enable io_uring support" ON)
option(IO_URING_NVME_ENABLED "Enable the io_uring NVMe uring_cmd block backend (auto-detected when ON; set OFF to force-disable, e.g. under the clang static analyzer)" ON)
option(REQUIRE_NETNS_TESTS "Fail configure if network namespace tests cannot be enabled" OFF)
set(LIBAIO_ENABLED "" CACHE STRING "Enable libaio support (empty=autodetect, YES=required, NO=disabled)")
option(EVPL_IOVEC_PROFILE "Enable retained-iovec stack profiling" OFF)

project(libevpl LANGUAGES C)

enable_testing()

# Network namespace testing detection.
# Tests run inside `ip netns` for isolation, which needs CAP_NET_ADMIN.
# A previous probe (e.g. by a parent project) may have already populated
# LIBEVPL_NETNS_TESTING in the cache; otherwise do a fresh probe.
# `ip netns` is Linux-only, so on other platforms (macOS) skip the probe and
# fall back to serialized, non-isolated test execution (see src/CMakeLists.txt).
if(NOT DEFINED LIBEVPL_NETNS_TESTING)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        execute_process(
            COMMAND bash -c "set -e; n=libevpl_netns_probe_$$; ip netns add \"$n\"; ip netns delete \"$n\""
            RESULT_VARIABLE LIBEVPL_NETNS_PROBE_RESULT
            OUTPUT_QUIET
            ERROR_QUIET
        )
        if(LIBEVPL_NETNS_PROBE_RESULT EQUAL 0)
            set(LIBEVPL_NETNS_TESTING TRUE)
        else()
            set(LIBEVPL_NETNS_TESTING FALSE)
        endif()
    else()
        set(LIBEVPL_NETNS_TESTING FALSE)
    endif()
endif()

if(LIBEVPL_NETNS_TESTING)
    message(STATUS "Network namespace testing enabled")
else()
    if(REQUIRE_NETNS_TESTS)
        message(FATAL_ERROR
            "REQUIRE_NETNS_TESTS=ON but `ip netns add` failed "
            "(need CAP_NET_ADMIN / root).")
    endif()
    message(STATUS "Network namespace testing disabled "
        "(netns-requiring tests will be skipped)")
endif()

message(STATUS "Building ${CMAKE_BUILD_TYPE} for ${CMAKE_SYSTEM_NAME}")

# Keep frame pointers in every build type so that perf and other
# frame-pointer-based profilers can unwind call stacks (the cost at -O3 is
# negligible and the unwind reliability is worth it for production profiling).
add_compile_options(-fno-omit-frame-pointer)

set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/opt/nvidia")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EVPL_MECH epoll)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(EVPL_MECH kqueue)

    # Homebrew keeps keg-only libraries (openssl@3) and headers (uthash's
    # utlist.h) outside the default search paths.  Add the common Homebrew
    # prefixes so find_library/find_path and the compiler locate them.
    if(EXISTS /opt/homebrew)
        set(HOMEBREW_PREFIX /opt/homebrew)
    else()
        set(HOMEBREW_PREFIX /usr/local)
    endif()

    list(APPEND CMAKE_PREFIX_PATH
        ${HOMEBREW_PREFIX}
        ${HOMEBREW_PREFIX}/opt/openssl@3
        ${HOMEBREW_PREFIX}/opt/nghttp2)

    include_directories(${HOMEBREW_PREFIX}/include)
    link_directories(${HOMEBREW_PREFIX}/lib)
else()
    message(FATAL_ERROR "Unsupported build platform ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Enabling AddressSanitizer")
    add_definitions(-fsanitize=address -fno-omit-frame-pointer
                    -fno-optimize-sibling-calls -fstack-protector-all)
    add_link_options(-fsanitize=address)
    add_definitions(-DEVPL_ASSERT=1)
    message(STATUS "Enabling iovec reference tracing")
    add_definitions(-DEVPL_IOVEC_TRACE=1)
endif()    

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-O3)
endif()

# Coverage build: clang source-based code coverage, instrumenting every TU.
# The matching merge/report step lives in etc/coverage-report.sh, driven by the
# Makefile's test_coverage target.  Kept deliberately parallel to the same
# build type in the parent chimera project so a report can be read the same way
# from either side; running it here narrows the picture to libevpl alone, with
# its own test suite as the workload.
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "Coverage build requires clang for source-based coverage "
            "(re-run with -DCMAKE_C_COMPILER=clang; the Makefile does this for you).")
    endif()
    message(STATUS "Enabling clang source-based code coverage")
    add_definitions(-O0 -fprofile-instr-generate -fcoverage-mapping -DEVPL_COVERAGE=1)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
endif()

if(EVPL_IOVEC_PROFILE)
    message(STATUS "Enabling retained-iovec stack profiling")
    add_definitions(-DEVPL_IOVEC_PROFILE=1)
endif()

if(IO_URING_ENABLED)
find_library(URING_LIB NAMES uring)
find_path(URING_INCLUDE_DIR NAMES liburing/io_uring.h)

if (URING_LIB AND URING_INCLUDE_DIR)
    message(STATUS "io_uring library ${URING_LIB}")
    message(STATUS "io_uring include ${URING_INCLUDE_DIR}")
    # Treat liburing as a system include: its headers define static-inline
    # helpers (e.g. io_uring_prep_uring_cmd) that the clang static analyzer
    # would otherwise analyze as user code and flag with false positives
    # (a null-deref of an sqe the caller already guards).  SYSTEM also keeps
    # any third-party-header warnings out of our -Werror build.
    include_directories(SYSTEM ${URING_INCLUDE_DIR})
    add_definitions(-DHAVE_IO_URING)
    set(HAVE_IO_URING 1)

    # The NVMe passthrough block backend needs io_uring_prep_uring_cmd()
    # (newer liburing) plus the NVMe uring_cmd ioctl definitions (newer kernel
    # headers).  Detect both and build that backend only when present, so the
    # rest of io_uring still builds on older toolchains.  IO_URING_NVME_ENABLED
    # lets a consumer force it off without touching detection -- chimera's
    # scan-build pass sets it OFF because the clang static analyzer
    # false-positives on liburing's io_uring_prep_uring_cmd inline (a NULL deref
    # of an sqe the only call site already guards).
    if (IO_URING_NVME_ENABLED)
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${URING_INCLUDE_DIR})
        set(CMAKE_REQUIRED_LIBRARIES ${URING_LIB})
        check_c_source_compiles("
#define _GNU_SOURCE
#include <liburing.h>
#include <linux/nvme_ioctl.h>
int main(void) {
    struct io_uring_sqe   *sqe = 0;
    struct nvme_uring_cmd *cmd = 0;
    io_uring_prep_uring_cmd(sqe, NVME_URING_CMD_IO_VEC, 0);
    (void) cmd;
    return 0;
}
" HAVE_IO_URING_NVME)
        unset(CMAKE_REQUIRED_INCLUDES)
        unset(CMAKE_REQUIRED_LIBRARIES)
    else()
        set(HAVE_IO_URING_NVME OFF)
        message(STATUS "io_uring NVMe uring_cmd backend force-disabled (IO_URING_NVME_ENABLED=OFF)")
    endif()

    if (HAVE_IO_URING_NVME)
        add_definitions(-DHAVE_IO_URING_NVME)
        message(STATUS "io_uring NVMe uring_cmd backend enabled")
    else()
        message(STATUS "io_uring NVMe uring_cmd backend unavailable (needs newer liburing/kernel headers)")
    endif()
else()
    message(STATUS "io_uring library not found.")
endif()
else()
    message(STATUS "IO_URING disabled")
endif()

if(NOT LIBAIO_ENABLED STREQUAL "NO" AND NOT LIBAIO_ENABLED STREQUAL "OFF")
find_library(AIO_LIB NAMES aio)
find_path(AIO_INCLUDE_DIR NAMES libaio.h)

if (AIO_LIB AND AIO_INCLUDE_DIR)
    message(STATUS "libaio library ${AIO_LIB}")
    message(STATUS "libaio include ${AIO_INCLUDE_DIR}")
    include_directories(${AIO_INCLUDE_DIR})
    add_definitions(-DHAVE_LIBAIO)
    set(HAVE_LIBAIO 1)
else()
    if(LIBAIO_ENABLED STREQUAL "YES" OR LIBAIO_ENABLED STREQUAL "ON")
        message(FATAL_ERROR "libaio required but not found.")
    endif()
    message(STATUS "libaio library not found.")
endif()
else()
    message(STATUS "LIBAIO disabled")
endif()

find_path(VFIO_INCLUDE_DIR NAMES linux/vfio.h)

if (VFIO_INCLUDE_DIR)
    message(STATUS "VFIO include ${VFIO_INCLUDE_DIR}")
    include_directories(${VFIO_INCLUDE_DIR})
    add_definitions(-DHAVE_VFIO)
    set(HAVE_VFIO 1)
else()
    message(STATUS "vfio library not found.")
endif()

find_library(RDMACM_LIB NAMES rdmacm)
find_path(RDMACM_INCLUDE_DIR NAMES rdma/rdma_cma.h)

if (RDMACM_LIB AND RDMACM_INCLUDE_DIR) 
    message(STATUS "RDMACM library ${RDMACM_LIB}")
    message(STATUS "RDMACM include ${RDMACM_INCLUDE_DIR}")
    include_directories(${RDMACM_INCLUDE_DIR})
    add_definitions(-DHAVE_RDMACM)
    set(HAVE_RDMACM 1)
else()
    message(STATUS "rdmacm library not found.")
endif()

find_library(XLIO_LIB NAMES xlio)
find_path(XLIO_INCLUDE_DIR NAMES mellanox/xlio.h)

if (XLIO_LIB AND XLIO_INCLUDE_DIR)
    message(STATUS "XLIO library ${XLIO_LIB}")
    message(STATUS "XLIO include ${XLIO_INCLUDE_DIR}")
    include_directories(${XLIO_INCLUDE_DIR})
    add_definitions(-DHAVE_XLIO)
    set(HAVE_XLIO 1)
else()
    message(STATUS "xlio library not found.")
endif()

# OpenSSL backs the TLS protocol.  macOS ships no OpenSSL/LibreSSL headers or
# linkable stubs in the SDK, so this resolves to a Homebrew openssl@3 (found
# via the prefixes added above) -- find_package is used rather than a bare
# -lssl because that formula is keg-only and lives outside the default paths.
find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_SSL_LIBRARY}")

set(HAVE_TLS 1)
add_definitions(-DHAVE_TLS)

find_library(NGHTTP2_LIB NAMES nghttp2)
find_path(NGHTTP2_INCLUDE_DIR NAMES nghttp2/nghttp2.h)

if (NGHTTP2_LIB AND NGHTTP2_INCLUDE_DIR)
    message(STATUS "nghttp2 library ${NGHTTP2_LIB}")
    message(STATUS "nghttp2 include ${NGHTTP2_INCLUDE_DIR}")
    include_directories(SYSTEM ${NGHTTP2_INCLUDE_DIR})
    add_definitions(-DHAVE_NGHTTP2)
    set(HAVE_NGHTTP2 1)
else()
    message(STATUS "nghttp2 library not found; HTTP/2 support disabled.")
endif()

# Detect every event-loop core mechanism this platform supports.  All of the
# supported ones are compiled in unconditionally and selected at runtime via
# evpl_global_config_set_core_mech(); epoll/kqueue remain the platform
# defaults, with select available everywhere as a portable fallback.
include(CheckIncludeFile)
check_include_file("sys/epoll.h"  EVPL_HAVE_EPOLL)
check_include_file("sys/event.h"  EVPL_HAVE_KQUEUE)
check_include_file("sys/select.h" EVPL_HAVE_SELECT)

set(EVPL_MECHANISMS)

if(EVPL_HAVE_EPOLL)
    add_definitions(-DEVPL_HAVE_EPOLL)
    list(APPEND EVPL_MECHANISMS epoll)
endif()

if(EVPL_HAVE_KQUEUE)
    add_definitions(-DEVPL_HAVE_KQUEUE)
    list(APPEND EVPL_MECHANISMS kqueue)
endif()

if(EVPL_HAVE_SELECT)
    add_definitions(-DEVPL_HAVE_SELECT)
    list(APPEND EVPL_MECHANISMS select)
endif()

if(NOT EVPL_MECHANISMS)
    message(FATAL_ERROR "No supported event core mechanism found on ${CMAKE_SYSTEM_NAME}")
endif()

message(STATUS "Event core mechanisms: ${EVPL_MECHANISMS} (default: ${EVPL_MECH})")

add_definitions(-g -Wall -Werror -Wno-unused-function)
add_definitions(-fvisibility=hidden)

# Warnings to waive on xdrzcc-generated sources, which are held to the same
# -Werror as hand-written code: the emitted code carries helpers a given .x
# does not use, and its dumpers snprintf() into fixed buffers where truncation
# is the intent.
#
# -Wno-format-truncation is a GCC spelling with no clang equivalent.  clang
# does not reject an unknown -Wno-* on sight -- it holds the complaint back and
# only raises it if some other diagnostic fires -- so a build can pass with the
# flag present and still fail the moment anything else warns, which is what
# happened on macOS.  Offer it only where it exists.
set(EVPL_XDR_WARNING_FLAGS "-Wno-unused")

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND EVPL_XDR_WARNING_FLAGS "-Wno-format-truncation")
endif()

set(LIBEVPL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(3rdparty)
include_directories(include)

include_directories(ext/prometheus-c)
# stopwatch.h is vendored by the prometheus-c submodule; use that single copy
# so libevpl and prometheus-c always share the same version.
include_directories(ext/prometheus-c/ext/stopwatch)

add_subdirectory(ext)
add_subdirectory(src)
add_subdirectory(docs)
add_subdirectory(include)

execute_process(COMMAND ln -sf ${CMAKE_BINARY_DIR}/compile_commands.json ${CMAKE_SOURCE_DIR}/compile_commands.json)

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(XDRZCC ${XDRZCC} PARENT_SCOPE)
endif()
