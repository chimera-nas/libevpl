#ifndef __EVENTPOLL_EPOLL_H__
#define __EVENTPOLL_EPOLL_H__

#include <stdint.h>

struct eventpoll_epoll {
    int fd;
    int max_events;
    struct epoll_event *events;
};

int eventpoll_epoll_init(struct eventpoll_epoll *evepoll, int max_events);
void eventpoll_epoll_destroy(struct eventpoll_epoll *evepoll);

int eventpoll_epoll_wait(struct eventpoll_epoll *evepoll, uint64_t max_msecs);


#endif
