# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

set(CORE_SRC
    eventpoll.c
    eventpoll.h
    tcp.c
    tcp.h
    config.c
    config.h
    internal.c
    internal.h
)

if (EVENTPOLL_MECH STREQUAL "epoll") 
    set(CORE_SRC ${CORE_SRC} epoll.c epoll.h)
elseif (EVENTPOLL_MECH STREQUAL "kqueue")
    set(CORE_SRC ${COER_SRC} kqueue.c kqueue.h)
else()
    message(FATAL_ERROR "No supported EVENTPOLL_MECH specified")
endif()

add_library(eventpoll_core SHARED ${CORE_SRC})


add_subdirectory(tests)
