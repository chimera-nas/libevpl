#ifndef __EVENTPOLL_CLIENT_H__
#define __EVENTPOLL_CLIENT_H__

#include "eventpoll_config.h"

#define EVENTPOLL_PROTO_TCP 1

struct eventpoll;

struct eventpoll * eventpoll_init(struct eventpoll_config *config);

void eventpoll_destroy(struct eventpoll *eventpoll);

int eventpoll_wait(struct eventpoll *eventpoll, int max_msecs);

typedef int (*eventpoll_accept_callback_t)(
    const char *client_address,
    const char *server_address,
    void       *private_data);

typedef int (*eventpoll_recv_callback_t)(
    struct iovec *iov,
    int niov,
    void *private_data);

typedef int (*eventpoll_error_callback_t)(
    int error_code,
    void *private_data);

int
eventpoll_listen(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_accept_callback_t accept_callback,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data);

int eventpoll_connect(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data);
    

#endif
