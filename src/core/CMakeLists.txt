# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

set(CORE_SRC
    evpl.c
    evpl.h
    tcp.c
    tcp.h
    config.c
    config.h
    internal.c
    internal.h
)

if (EVPL_MECH STREQUAL "epoll") 
    set(CORE_SRC ${CORE_SRC} epoll.c epoll.h)
elseif (EVPL_MECH STREQUAL "kqueue")
    set(CORE_SRC ${COER_SRC} kqueue.c kqueue.h)
else()
    message(FATAL_ERROR "No supported EVPL_MECH specified")
endif()

add_library(evpl_core SHARED ${CORE_SRC})

add_subdirectory(tests)
