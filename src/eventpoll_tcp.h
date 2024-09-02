#ifndef __EVENTPOLL_TCP_H__
#define __EVENTPOLL_TCP_H__

struct eventpoll_socket {
    int                   fd;
    int                   connected;
    int                   recv_size;
    struct eventpoll_bvec recv1;
    struct eventpoll_bvec recv2;
};

int
eventpoll_listen_tcp(
    struct eventpoll *eventpoll,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port);

int
eventpoll_connect_tcp(
    struct eventpoll *eventpoll,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port);

void
eventpoll_close_tcp(
    struct eventpoll *eventpoll,
    struct eventpoll_socket *s);

#endif
