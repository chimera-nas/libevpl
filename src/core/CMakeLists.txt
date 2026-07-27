# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

set(CORE_SRC
    evpl.c
    allocator.c
    iovec.c
    iovec_profile.c
    config.c
    protocol.c
    address.c
    endpoint.c
    bind.c
    logging.c
    memory.c
    doorbell.c
    listen.c
    timer.c
    deferral.c
    block.c
    poll.c
    send.c
    recv.c
    rdma.c
    numa.c
)

# Every mechanism supported on this platform is compiled in; the one used is
# chosen at runtime from the global config (see core.c).
set(CORE_SRC ${CORE_SRC} core.c core.h)

if (EVPL_HAVE_EPOLL)
    set(CORE_SRC ${CORE_SRC} epoll.c epoll.h)
endif()

if (EVPL_HAVE_KQUEUE)
    set(CORE_SRC ${CORE_SRC} kqueue.c kqueue.h)
endif()

if (EVPL_HAVE_SELECT)
    set(CORE_SRC ${CORE_SRC} select.c select.h)
endif()

set(BACKEND_LIBDEPS)

set(CORE_SRC ${CORE_SRC} socket/tcp.c socket/tcp.h socket/common.h socket/udp.c socket/udp.h socket/tcp_rdma.c socket/tcp_rdma.h)
add_subdirectory(socket)

# TLS is available wherever OpenSSL is (HAVE_TLS is set at the top level).  Its
# kTLS zero-copy path is Linux-only; on other platforms BIO_get_ktls_*() simply
# reports unavailable and the normal SSL_read/SSL_write path is used.
if (HAVE_TLS)
    set(CORE_SRC ${CORE_SRC} tls/tls.c tls/tls.h)
    add_subdirectory(tls)
endif()

if (HAVE_VFIO)
    set(CORE_SRC ${CORE_SRC} vfio/vfio.c vfio/vfio.h vfio/nvme.h)
    add_subdirectory(vfio)
endif()

if (HAVE_IO_URING)
    set(CORE_SRC ${CORE_SRC} io_uring/io_uring.c io_uring/io_uring_tcp.c io_uring/io_uring_block.c io_uring/io_uring.h)
    if (HAVE_IO_URING_NVME)
        set(CORE_SRC ${CORE_SRC} io_uring/io_uring_nvme_block.c)
    endif()
    add_subdirectory(io_uring)
    set(BACKEND_LIBDEPS ${BACKEND_LIBDEPS} uring)
endif()

if (HAVE_LIBAIO)
    set(CORE_SRC ${CORE_SRC} libaio/libaio.c libaio/libaio_block.c libaio/libaio.h)
    add_subdirectory(libaio)
    set(BACKEND_LIBDEPS ${BACKEND_LIBDEPS} aio)
endif()

if (HAVE_RDMACM)
    set(CORE_SRC ${CORE_SRC} rdmacm/rdmacm.c rdmacm/rdmacm.h)
    add_subdirectory(rdmacm)
    set(BACKEND_LIBDEPS ${BACKEND_LIBDEPS} rdmacm ibverbs)
endif()

if (HAVE_XLIO)
    set(CORE_SRC ${CORE_SRC} xlio/xlio.c xlio/xlio.h xlio/tcp.c xlio/common.h)
    add_subdirectory(xlio)
endif()

if (HAVE_SPDK)
    set(CORE_SRC ${CORE_SRC}
        spdk/spdk_core.c spdk/evpl_spdk.h
        spdk/spdk_framework.c
        spdk/spdk_sock_common.h
        spdk/spdk_block.c
        spdk/tcp.c
        thread/thread_spdk.c)
    add_subdirectory(spdk)
    set(BACKEND_LIBDEPS ${BACKEND_LIBDEPS} ${SPDK_LINK_TARGETS})
endif()

set(CORE_SRC ${CORE_SRC} thread/thread.c)
add_subdirectory(thread)

add_library(evpl SHARED ${CORE_SRC})

# Base dependencies present on every platform.
set(EVPL_LIBDEPS ${BACKEND_LIBDEPS} prometheus-c)

# libnuma is Linux-only; on macOS numa.c compiles to a stub with no link dep.
if (NOT APPLE)
    set(EVPL_LIBDEPS ${EVPL_LIBDEPS} numa)
endif()

# OpenSSL is only needed when TLS is compiled in.  Use the imported targets so
# the include and library paths of a non-standard prefix (Homebrew's keg-only
# openssl@3) come along automatically.
if (HAVE_TLS)
    set(EVPL_LIBDEPS ${EVPL_LIBDEPS} OpenSSL::SSL OpenSSL::Crypto)
endif()

target_link_libraries(evpl ${EVPL_LIBDEPS})

install(TARGETS evpl DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
