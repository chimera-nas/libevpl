#ifndef __EVENTPOLL_CLIENT_H__
#define __EVENTPOLL_CLIENT_H__

struct iovec;

#include "eventpoll_config.h"

#define EVENTPOLL_PROTO_TCP 1

struct eventpoll;
struct eventpoll_conn;

struct eventpoll * eventpoll_init(struct eventpoll_config *config);

void eventpoll_destroy(struct eventpoll *eventpoll);

void eventpoll_wait(struct eventpoll *eventpoll, int max_msecs);

typedef int (*eventpoll_recv_callback_t)(
    struct iovec *iov,
    int niov,
    void *private_data);

typedef void (*eventpoll_error_callback_t)(
    int error_code,
    void *private_data);

typedef void (*eventpoll_accept_callback_t)(
    struct eventpoll_conn      *conn,
    eventpoll_recv_callback_t  *recv_callback,
    eventpoll_error_callback_t *error_callback,
    void                       **conn_private_data,
    void                        *private_data);

int
eventpoll_listen(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_accept_callback_t acceot_callback,
    void *private_data);

struct eventpoll_conn *
eventpoll_connect(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data);

const char *
eventpoll_conn_address(struct eventpoll_conn *conn);

int
eventpoll_conn_port(struct eventpoll_conn *conn);
    

#endif
