# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

set(SRC
    eventpoll.c
    eventpoll.h
    eventpoll_tcp.c
    eventpoll_tcp.h
    eventpoll_config.c
    eventpoll_config.h
    eventpoll_internal.c
    eventpoll_internal.h
)

if (EVENTPOLL_MECH STREQUAL "epoll") 
    set(SRC ${SRC} eventpoll_core_epoll.c eventpoll_core_epoll.h)
elseif (EVENTPOLL_MECH STREQUAL "kqueue")
    set(SRC ${SRC} eventpoll_core_kqueue.c eventpoll_core_kqueue.h)
else()
    message(FATAL_ERROR "No supported EVENTPOLL_MECH specified")
endif()

add_library(eventpoll SHARED ${SRC})

