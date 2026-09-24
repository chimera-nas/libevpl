# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

cmake_minimum_required(VERSION 3.22)

option(IO_URING_ENABLED "Enable io_uring support" ON)
option(IO_URING_NVME_ENABLED "Enable the io_uring NVMe uring_cmd block backend (auto-detected when ON; set OFF to force-disable, e.g. under the clang static analyzer)" ON)
option(REQUIRE_NETNS_TESTS "Fail configure if network namespace tests cannot be enabled" OFF)
set(EVPL_RDMA_TEST_IP "$ENV{EVPL_RDMACM_IP}" CACHE STRING "Local RDMA interface address; enables RDMA integration and model tests")
set(LIBAIO_ENABLED "" CACHE STRING "Enable libaio support (empty=autodetect, YES=required, NO=disabled)")
set(LIBFABRIC_ENABLED "AUTO" CACHE STRING "libfabric (OFI) backend: AUTO (enable iff available), ON (require), or OFF")
set_property(CACHE LIBFABRIC_ENABLED PROPERTY STRINGS AUTO ON OFF)
set(SPDK_ENABLED "" CACHE STRING "Enable SPDK support (empty=autodetect, YES=required, NO=disabled)")
option(EVPL_IOVEC_PROFILE "Enable retained-iovec stack profiling" OFF)

option(EVPL_STORAGE_TESTS "Register guest storage model tests" OFF)
option(EVPL_REQUIRE_KRB5_MBT "Require MIT Kerberos and execution of protected RPC model cases" OFF)

project(libevpl LANGUAGES C)
option(EVPL_TLS_MEMORY_BIO "Run TLS over the portable byte-stream backend" ${WIN32})
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/experimental:c11atomics>)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

set(EVPL_CONFORMANCE_CASES_DIR "" CACHE PATH "Directory containing pre-generated core, HTTP and RPC conformance case headers")
if(EVPL_CONFORMANCE_CASES_DIR)
    foreach(header core_cases.h http_cases.h conformance_cases.h client_cases.h fd_cases.h lifecycle_cases.h block_lifecycle_cases.h listener_cases.h)
        if(NOT EXISTS "${EVPL_CONFORMANCE_CASES_DIR}/${header}")
            message(FATAL_ERROR "Missing conformance case table: ${header}")
        endif()
    endforeach()
endif()
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
if(NOT MSVC)
    add_compile_options(-fno-omit-frame-pointer)
endif()

set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/opt/nvidia")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EVPL_MECH epoll)
elseif(WIN32)
    set(EVPL_MECH iocp)
    set(EVPL_HAVE_IOCP ON)
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

if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT MSVC)
    message(STATUS "Enabling AddressSanitizer")
    add_definitions(-fsanitize=address -fno-omit-frame-pointer
                    -fno-optimize-sibling-calls -fstack-protector-all)
    add_link_options(-fsanitize=address)
    add_definitions(-DEVPL_ASSERT=1)
    message(STATUS "Enabling iovec reference tracing")
    add_definitions(-DEVPL_IOVEC_TRACE=1)
endif()    

if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT MSVC)
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

if(EVPL_IOVEC_PROFILE AND WIN32)
    message(FATAL_ERROR "Retained-iovec stack profiling is not yet supported on Windows")
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
        include(CMakePushCheckState)
        cmake_push_check_state(RESET)
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
        cmake_pop_check_state()
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

    # Probe the liburing / kernel-header surface that zero-copy receive and the
    # registered buffer/file fast paths need.  Each feature is detected
    # independently so an older toolchain still builds the rest of io_uring.
    include(CheckSymbolExists)
    include(CheckCSourceCompiles)
    include(CMakePushCheckState)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${URING_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${URING_LIB})

    check_symbol_exists(io_uring_register_ifq "liburing.h"
                        HAVE_IO_URING_REGISTER_IFQ)
    check_symbol_exists(io_uring_prep_send_zc "liburing.h"
                        HAVE_IO_URING_PREP_SEND_ZC)
    check_symbol_exists(io_uring_prep_sendmsg_zc_fixed "liburing.h"
                        HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED)
    check_symbol_exists(io_uring_register_buffers_sparse "liburing.h"
                        HAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
    check_symbol_exists(io_uring_register_files_sparse "liburing.h"
                        HAVE_IO_URING_REGISTER_FILES_SPARSE)
    check_symbol_exists(io_uring_register_buffers_update_tag "liburing.h"
                        HAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
    check_symbol_exists(io_uring_register_files_update "liburing.h"
                        HAVE_IO_URING_REGISTER_FILES_UPDATE)
    check_symbol_exists(io_uring_prep_close_direct "liburing.h"
                        HAVE_IO_URING_PREP_CLOSE_DIRECT)

    # IORING_OP_RECV_ZC is an enum value (not a #define), so use compile test
    check_c_source_compiles("
        #include <liburing/io_uring.h>
        int main(void) { return (int)IORING_OP_RECV_ZC; }
    " HAVE_IO_URING_OP_RECV_ZC)

    check_symbol_exists(IORING_RECVSEND_BUNDLE "liburing/io_uring.h"
                        HAVE_IO_URING_RECVSEND_BUNDLE)
    check_symbol_exists(IORING_RECVSEND_FIXED_BUF "liburing/io_uring.h"
                        HAVE_IO_URING_RECVSEND_FIXED_BUF)
    check_symbol_exists(IOSQE_FIXED_FILE "liburing/io_uring.h"
                        HAVE_IO_URING_IOSQE_FIXED_FILE)
    check_symbol_exists(IORING_ZCRX_AREA_SHIFT "liburing/io_uring.h"
                        HAVE_IO_URING_ZCRX_AREA_SHIFT)
    check_c_source_compiles("
        #include <liburing/io_uring.h>
        int main(void) { struct io_uring_zcrx_ifq_reg r; (void)r; return 0; }
    " HAVE_IO_URING_ZCRX_IFQ_REG)

    if (HAVE_IO_URING_REGISTER_IFQ)
        add_definitions(-DHAVE_IO_URING_REGISTER_IFQ)
    endif()
    if (HAVE_IO_URING_PREP_SEND_ZC)
        add_definitions(-DHAVE_IO_URING_PREP_SEND_ZC)
    endif()
    if (HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED)
        add_definitions(-DHAVE_IO_URING_PREP_SENDMSG_ZC_FIXED)
    endif()
    if (HAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
        add_definitions(-DHAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
    endif()
    if (HAVE_IO_URING_REGISTER_FILES_SPARSE)
        add_definitions(-DHAVE_IO_URING_REGISTER_FILES_SPARSE)
    endif()
    if (HAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
        add_definitions(-DHAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
    endif()
    if (HAVE_IO_URING_REGISTER_FILES_UPDATE)
        add_definitions(-DHAVE_IO_URING_REGISTER_FILES_UPDATE)
    endif()
    if (HAVE_IO_URING_PREP_CLOSE_DIRECT)
        add_definitions(-DHAVE_IO_URING_PREP_CLOSE_DIRECT)
    endif()
    if (HAVE_IO_URING_OP_RECV_ZC)
        add_definitions(-DHAVE_IO_URING_OP_RECV_ZC)
    endif()
    if (HAVE_IO_URING_RECVSEND_BUNDLE)
        add_definitions(-DHAVE_IO_URING_RECVSEND_BUNDLE)
    endif()
    if (HAVE_IO_URING_RECVSEND_FIXED_BUF)
        add_definitions(-DHAVE_IO_URING_RECVSEND_FIXED_BUF)
    endif()
    if (HAVE_IO_URING_IOSQE_FIXED_FILE)
        add_definitions(-DHAVE_IO_URING_IOSQE_FIXED_FILE)
    endif()
    if (HAVE_IO_URING_ZCRX_AREA_SHIFT)
        add_definitions(-DHAVE_IO_URING_ZCRX_AREA_SHIFT)
    endif()

    if (HAVE_IO_URING_REGISTER_IFQ AND HAVE_IO_URING_OP_RECV_ZC AND
        HAVE_IO_URING_ZCRX_AREA_SHIFT AND HAVE_IO_URING_ZCRX_IFQ_REG)
        add_definitions(-DHAVE_IO_URING_ZCRX)
        set(HAVE_IO_URING_ZCRX 1)
        message(STATUS "io_uring ZCRX support: available")
    else()
        message(STATUS "io_uring ZCRX support: NOT available")
    endif()

    cmake_pop_check_state()
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
find_library(IBVERBS_LIB NAMES ibverbs)
find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (RDMACM_LIB AND RDMACM_INCLUDE_DIR AND IBVERBS_LIB AND IBVERBS_INCLUDE_DIR)
    message(STATUS "RDMACM library ${RDMACM_LIB}")
    message(STATUS "RDMACM include ${RDMACM_INCLUDE_DIR}")
    include_directories(${RDMACM_INCLUDE_DIR} ${IBVERBS_INCLUDE_DIR})
    add_definitions(-DHAVE_RDMACM)
    set(HAVE_RDMACM 1)
else()
    message(STATUS "rdmacm library not found.")
endif()

string(TOUPPER "${LIBFABRIC_ENABLED}" LIBFABRIC_ENABLED)

if (LIBFABRIC_ENABLED STREQUAL "OFF" OR LIBFABRIC_ENABLED STREQUAL "NO")
    message(STATUS "libfabric backend disabled")
elseif(WIN32)
    if(LIBFABRIC_ENABLED STREQUAL "ON" OR LIBFABRIC_ENABLED STREQUAL "YES")
        message(FATAL_ERROR "The libfabric backend requires POSIX descriptor events; Windows IOCP is not supported")
    endif()
    message(STATUS "libfabric backend unavailable on Windows")
else()
    find_library(LIBFABRIC_LIB NAMES fabric)
    find_path(LIBFABRIC_INCLUDE_DIR NAMES rdma/fabric.h)

    if (LIBFABRIC_LIB AND LIBFABRIC_INCLUDE_DIR)
        # Probe for what the backend actually uses rather than trusting a
        # version number: fi_context2, the FI_WAIT_POLLFD wait object, and the
        # FI_MR_* bitmask mr_mode.  All are present from 1.17, which is what
        # Ubuntu 24.04 packages; EVPL_LIBFABRIC_API_VERSION in libfabric.c is
        # the matching runtime floor and the two must move together.
        include(CheckCSourceCompiles)
        include(CMakePushCheckState)
        cmake_push_check_state(RESET)
        set(CMAKE_REQUIRED_INCLUDES ${LIBFABRIC_INCLUDE_DIR})
        check_c_source_compiles("
            #include <rdma/fabric.h>
            #include <rdma/fi_eq.h>
            #if FI_VERSION_LT(FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION), FI_VERSION(1, 17))
            #error libfabric too old
            #endif
            int main(void) {
                struct fi_context2 ctx;
                int wait = FI_WAIT_POLLFD;
                uint64_t mr = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
                              FI_MR_ALLOCATED | FI_MR_PROV_KEY;
                (void) ctx; (void) wait; (void) mr;
                return 0;
            }
        " LIBFABRIC_VERSION_OK)
        cmake_pop_check_state()
    endif()

    if (LIBFABRIC_LIB AND LIBFABRIC_INCLUDE_DIR AND LIBFABRIC_VERSION_OK)
        message(STATUS "libfabric library ${LIBFABRIC_LIB}")
        message(STATUS "libfabric include ${LIBFABRIC_INCLUDE_DIR}")
        include_directories(${LIBFABRIC_INCLUDE_DIR})
        add_definitions(-DHAVE_LIBFABRIC)
        set(HAVE_LIBFABRIC 1)
    elseif (LIBFABRIC_ENABLED STREQUAL "ON" OR LIBFABRIC_ENABLED STREQUAL "YES")
        message(FATAL_ERROR "LIBFABRIC_ENABLED=ON but libfabric >= 1.17 was not found")
    else()
        message(STATUS "libfabric >= 1.17 not found; libfabric backend disabled")
    endif()
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

# SPDK guest-mode integration (EVPL_CORE_MECH_SPDK + spdk_mem_register memory
# framework).  Detected via pkg-config against SPDK shared libraries
# (./configure --with-shared); static SPDK is not supported.  SPDK is Linux
# only and the mechanism composes with epoll, so both are required when found.
if((SPDK_ENABLED STREQUAL "YES" OR SPDK_ENABLED STREQUAL "ON") AND
   NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "SPDK support is only available on Linux")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   NOT SPDK_ENABLED STREQUAL "NO" AND NOT SPDK_ENABLED STREQUAL "OFF")
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(SPDK IMPORTED_TARGET GLOBAL
                          spdk_bdev spdk_sock spdk_sock_posix
                          spdk_thread spdk_env_dpdk spdk_util spdk_log)
    endif()
    if(SPDK_FOUND)
        if(CMAKE_VERSION VERSION_LESS 3.24)
            message(FATAL_ERROR "SPDK support requires CMake 3.24 or newer; use -DSPDK_ENABLED=OFF to disable")
        endif()
        # Keep constructor-only modules even when the compiler defaults to
        # --as-needed. A link feature keeps its state attached to the actual
        # libraries when CMake reorders/deduplicates transitive dependencies.
        set(CMAKE_C_LINK_LIBRARY_USING_evpl_spdk_modules_SUPPORTED TRUE)
        set(CMAKE_C_LINK_LIBRARY_USING_evpl_spdk_modules
            "LINKER:--push-state,--no-as-needed" "<LINK_ITEM>" "LINKER:--pop-state")
        function(evpl_spdk_link_modules target)
            get_target_property(libraries ${target} INTERFACE_LINK_LIBRARIES)
            set_property(TARGET ${target} PROPERTY INTERFACE_LINK_LIBRARIES
                "$<LINK_LIBRARY:evpl_spdk_modules,${libraries}>")
        endfunction()
        include(CheckCSourceCompiles)
        include(CMakePushCheckState)
        cmake_push_check_state(RESET)
        set(CMAKE_REQUIRED_INCLUDES ${SPDK_INCLUDE_DIRS})
        check_c_source_compiles("#include <spdk/version.h>
#if SPDK_VERSION < SPDK_VERSION_NUM(25, 9, 0)
#error SPDK 25.09 or newer is required
#endif
int main(void) { return 0; }" SPDK_SUPPORTED_VERSION)
        cmake_pop_check_state()
        if(NOT SPDK_SUPPORTED_VERSION)
            message(FATAL_ERROR "libevpl requires SPDK 25.09 or newer; use -DSPDK_ENABLED=OFF to disable")
        endif()
        message(STATUS "SPDK found via pkg-config")
        add_definitions(-DHAVE_SPDK)
        set(HAVE_SPDK 1)
        # --no-as-needed: DPDK driver libraries (librte_mempool_ring et al.)
        # and SPDK module libraries (sock impls, bdev modules) register
        # themselves via constructors and are referenced by no symbol, so the
        # default --as-needed link drops them and their functionality is
        # silently absent at runtime.
        set(SPDK_LINK_TARGETS PkgConfig::SPDK)
        get_target_property(_spdk_libraries PkgConfig::SPDK INTERFACE_LINK_LIBRARIES)

        # SPDK's shared libspdk_util leaves ISA-L symbols undefined (SPDK
        # normally links ISA-L statically into applications), so link ISA-L
        # explicitly when its pkg-config -- installed by SPDK's own build --
        # is present.
        pkg_check_modules(ISAL IMPORTED_TARGET GLOBAL libisal libisal_crypto)
        if(ISAL_FOUND)
            list(APPEND _spdk_libraries ${ISAL_LINK_LIBRARIES})
        endif()

        set_property(TARGET PkgConfig::SPDK PROPERTY INTERFACE_LINK_LIBRARIES "${_spdk_libraries}")
        evpl_spdk_link_modules(PkgConfig::SPDK)

        # Test-only modules: subsystem JSON bring-up (spdk_init) and the bdev
        # subsystem registration constructors (spdk_event_bdev), used by the
        # SPDK bdev tests to create a malloc bdev without the app framework.
        pkg_check_modules(SPDK_INIT IMPORTED_TARGET GLOBAL
                          spdk_init spdk_event_bdev)
        if(NOT DISABLE_TESTS AND NOT SPDK_INIT_FOUND)
            message(FATAL_ERROR "SPDK tests require spdk_init and spdk_event_bdev")
        endif()
        if(SPDK_INIT_FOUND)
            evpl_spdk_link_modules(PkgConfig::SPDK_INIT)
            set(SPDK_TEST_LINK_TARGETS PkgConfig::SPDK_INIT)
        endif()
    else()
        if(SPDK_ENABLED STREQUAL "YES" OR SPDK_ENABLED STREQUAL "ON")
            message(FATAL_ERROR "SPDK required but not found.")
        endif()
        message(STATUS "SPDK not found.")
    endif()
else()
    message(STATUS "SPDK disabled")
endif()

# Windows uses the operating system TLS implementation; Unix retains OpenSSL.
if(WIN32)
    set(EVPL_TLS_MEMORY_BIO ON)
    message(STATUS "TLS backend: Windows Schannel")
else()
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_SSL_LIBRARY}")
endif()

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
if(EVPL_HAVE_IOCP)
    add_compile_definitions(EVPL_HAVE_IOCP)
    list(APPEND EVPL_MECHANISMS iocp)
endif()

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

# The SPDK mechanism delegates its fd handling to the epoll backend.  SPDK is
# deliberately NOT appended to EVPL_MECHANISMS: that list replicates generic
# tests which pump evpl from a plain pthread and cannot run in guest mode;
# SPDK coverage comes from dedicated tests and host-driven MBT variants.
if(HAVE_SPDK AND NOT EVPL_HAVE_EPOLL)
    message(FATAL_ERROR "SPDK support requires the epoll core mechanism")
endif()

message(STATUS "Event core mechanisms: ${EVPL_MECHANISMS} (default: ${EVPL_MECH})")

if(MSVC)
    # Match the existing Unix warning policy: it does not enable conversion
    # or sign-compare diagnostics. Keep pointer-width and ABI warnings enabled.
    add_compile_options(/W3 /WX /wd4244 /wd4267 /wd4018)
else()
    add_definitions(-g -Wall -Werror -Wno-unused-function)
    add_definitions(-fvisibility=hidden)
endif()

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
set(EVPL_XDR_WARNING_FLAGS)
if(MSVC)
    set(EVPL_XDR_WARNING_FLAGS "/wd4101")
endif()
if(NOT MSVC)
    set(EVPL_XDR_WARNING_FLAGS "-Wno-unused")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    list(APPEND EVPL_XDR_WARNING_FLAGS "-Wno-format-truncation")
endif()

set(LIBEVPL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

find_path(UTHASH_INCLUDE_DIR uthash.h REQUIRED)
include_directories(SYSTEM ${UTHASH_INCLUDE_DIR})
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

if(NOT WIN32)
    execute_process(COMMAND ln -sf ${CMAKE_BINARY_DIR}/compile_commands.json ${CMAKE_SOURCE_DIR}/compile_commands.json)
endif()

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(XDRZCC ${XDRZCC} PARENT_SCOPE)
endif()
