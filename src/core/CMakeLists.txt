# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

set(CORE_SRC
    evpl.c
    allocator.c
    buffer.c
    iovec.c
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

if (EVPL_MECH STREQUAL "epoll") 
    set(CORE_SRC ${CORE_SRC} epoll.c epoll.h)
elseif (EVPL_MECH STREQUAL "kqueue")
    set(CORE_SRC ${COER_SRC} kqueue.c kqueue.h)
else()
    message(FATAL_ERROR "No supported EVPL_MECH specified")
endif()

set(BACKEND_LIBDEPS)

set(CORE_SRC ${CORE_SRC} socket/tcp.c socket/tcp.h socket/common.h socket/udp.c socket/udp.h)
add_subdirectory(socket)

set(CORE_SRC ${CORE_SRC} tls/tls.c tls/tls.h)
add_subdirectory(tls)

if (HAVE_VFIO)
    set(CORE_SRC ${CORE_SRC} vfio/vfio.c vfio/vfio.h vfio/nvme.h)
    add_subdirectory(vfio)
endif()

if (HAVE_IO_URING)
    set(CORE_SRC ${CORE_SRC} io_uring/io_uring.c io_uring/io_uring_tcp.c io_uring/io_uring_block.c io_uring/io_uring.h)
    add_subdirectory(io_uring)
    set(BACKEND_LIBDEPS ${BACKEND_LIBDEPS} uring)
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

set(CORE_SRC ${CORE_SRC} thread/thread.c)
add_subdirectory(thread)

add_library(evpl SHARED ${CORE_SRC})

target_link_libraries(evpl ${BACKEND_LIBDEPS} ssl crypto numa)

install(TARGETS evpl DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
