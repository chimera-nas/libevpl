#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "utlist.h"

#if EVENTPOLL_MECH == epoll
#include "eventpoll_epoll.h"
#else
#error  No EVENTPOLL_MECH
#endif

#include "eventpoll.h"
#include "eventpoll_internal.h"
#include "eventpoll_config.h"

struct eventpoll_listener {
    int fd;
    eventpoll_accept_callback_t accept_callback;
    eventpoll_recv_callback_t recv_callback;
    eventpoll_error_callback_t error_callback;
    void *private_data;
    struct eventpoll_listener *prev;
    struct eventpoll_listener *next;
};

struct eventpoll {
    struct eventpoll_config   *config;
    struct eventpoll_listener *listeners;

#if EVENTPOLL_MECH == epoll
    struct eventpoll_epoll  epoll;
#else
#error No EVENTPOLL_MECH
#endif

};

struct eventpoll *
eventpoll_init(struct eventpoll_config *config)
{
    struct eventpoll *eventpoll;

    if (config) {
        ++config->refcnt;
    } else {
        config = eventpoll_config_init();
    }

    eventpoll = eventpoll_zalloc(sizeof(*eventpoll));

    eventpoll->config = config;

#if EVENTPOLL_MECH == epoll
    eventpoll_epoll_init(&eventpoll->epoll, 64);
#else
#error No EVENTPOLL_MECH
#endif


    return eventpoll;
}

void
eventpoll_listener_destroy(
    struct eventpoll_listener *listener)
{
    close(listener->fd);
    eventpoll_free(listener);
}

void
eventpoll_destroy(
    struct eventpoll *eventpoll)
{
    struct eventpoll_listener *listener;

    while (eventpoll->listeners) {
        listener = eventpoll->listeners;
        DL_DELETE(eventpoll->listeners, listener);
        eventpoll_listener_destroy(listener);
    }

#if EVENTPOLL_MECH == epoll
    eventpoll_epoll_destroy(&eventpoll->epoll);
#else
#error No EVENTPOLL_MECH
#endif


    eventpoll_config_release(eventpoll->config);
    eventpoll_free(eventpoll);
}

int
eventpoll_wait(struct eventpoll *eventpoll, int max_msecs)
{
#if EVENTPOLL_MECH == epoll
    return eventpoll_epoll_wait(&eventpoll->epoll, max_msecs);
#else
#error No EVENTPOLL_MECH
#endif
}

static int
eventpoll_listen_tcp(
    struct eventpoll *eventpoll,
    const char *address,
    int port,
    eventpoll_accept_callback_t accept_callback,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data)
{
    struct eventpoll_listener *listener;
    char port_str[8];
    struct addrinfo hints, *res, *p;
    int rc, fd;
    const int yes = 1;

    listener = eventpoll_zalloc(sizeof(*listener));

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(address, port_str, &hints, &res);
    
    if (rc) {
        return errno;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            return errno;
        }


        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        return EINVAL;
    }

    listener->fd = fd;

    rc = fcntl(listener->fd, F_SETFL, fcntl(listener->fd, F_GETFL, 0) | O_NONBLOCK);

    rc = listen(listener->fd, eventpoll->config->max_pending);

    eventpoll_fatal_if(rc, "Failed to listen on listener fd");

    listener->accept_callback = accept_callback;
    listener->recv_callback = recv_callback;
    listener->error_callback = error_callback;
    listener->private_data = private_data;

    DL_APPEND(eventpoll->listeners, listener);

    return 0;

}

int eventpoll_listen(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_accept_callback_t accept_callback,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data)
{
    switch (protocol) {
    case EVENTPOLL_PROTO_TCP:
        return eventpoll_listen_tcp(eventpoll, address, port, 
                accept_callback, recv_callback, error_callback, private_data);
    default:
        return EINVAL;
    }
}
