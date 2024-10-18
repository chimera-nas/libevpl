# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

set(CORE_SRC
    evpl.c
    evpl.h
    config.c
    internal.c
)

if (EVPL_MECH STREQUAL "epoll") 
    set(CORE_SRC ${CORE_SRC} epoll.c epoll.h)
elseif (EVPL_MECH STREQUAL "kqueue")
    set(CORE_SRC ${COER_SRC} kqueue.c kqueue.h)
else()
    message(FATAL_ERROR "No supported EVPL_MECH specified")
endif()

add_library(evpl SHARED ${CORE_SRC})

target_link_libraries(evpl evpl_socket evpl_thread)

if (HAVE_RDMACM)
    target_link_libraries(evpl evpl_rdmacm)
endif()

if (HAVE_XLIO)
    target_link_libraries(evpl evpl_xlio)
endif()

add_subdirectory(tests)
