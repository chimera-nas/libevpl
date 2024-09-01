#ifndef __EVENTPOLL_CONN_H__
#define __EVENTPOLL_CONN_H__

struct eventpoll_conn {
    struct eventpoll_event  event; /* must be first member */

    union { /* must be second member */
        struct eventpoll_socket s;
    };

    struct eventpoll_bvec_ring send_ring;
    struct eventpoll_bvec_ring recv_ring;

    char address[256];
    int port;
    int protocol;
};

struct eventpoll_conn *
eventpoll_alloc_conn(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port);

#endif
