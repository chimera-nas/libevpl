#include <stdlib.h>

#include "eventpoll.h"

struct eventpoll_epoll {
    int fd;
};

struct eventpoll {
    union {
        struct eventpoll_epoll  epoll;
    };
};

struct eventpoll *
eventpoll_init()
{
    struct eventpoll *eventpoll;

    eventpoll = calloc(1, sizeof(*eventpoll));

    return eventpoll;
}

void
eventpoll_destroy(
    struct eventpoll *eventpoll)
{
    free(eventpoll);
}
