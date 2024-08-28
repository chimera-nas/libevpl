
set(SRC
    eventpoll.c
    eventpoll.h
)

if (EVENTPOLL_MECH STREQUAL "epoll") 
    set(SRC ${SRC} eventpoll_epoll.c eventpoll_epoll.h)
elseif (EVENTPOLL_MECH STREQUAL "kqueue")
    set(SRC ${SRC} eventpoll_kqueue.c eventpoll_kqueue.h)
else()
    message(FATAL_ERROR "No supported EVENTPOLL_MECH specified")
endif()

add_library(eventpoll SHARED ${SRC})

