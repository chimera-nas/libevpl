#ifndef __EVENTPOLL_TCP_H__
#define __EVENTPOLL_TCP_H__

struct eventpoll_socket {
    int fd;
    int connected;
};

int
eventpoll_listen_tcp(
    struct eventpoll_config *config,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port);

int
eventpoll_connect_tcp(
    struct eventpoll_config *config,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port);

void
eventpoll_close_tcp(
    struct eventpoll_socket *s);

#endif
