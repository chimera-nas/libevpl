#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

#include "eventpoll_epoll.h"

int
eventpoll_epoll_init(
    struct eventpoll_epoll *evepoll,
    int max_events)
{
    evepoll->fd = epoll_create(255); /* size is ignored in linux >= 2.6.8 */

    if (evepoll->fd < 0) {
        return errno;
    }

    evepoll->max_events = max_events;

    evepoll->events = calloc(max_events, sizeof(struct epoll_event));

    return 0;
}

void eventpoll_epoll_destroy(
    struct eventpoll_epoll *evepoll)
{
    free(evepoll->events);
    close(evepoll->fd);
}

int eventpoll_epoll_wait(struct eventpoll_epoll *evepoll, uint64_t max_msecs)
{
    int n;

    n = epoll_wait(evepoll->fd, evepoll->events, evepoll->max_events, max_msecs);

    return n;
}
