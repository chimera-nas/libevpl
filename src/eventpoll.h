/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#ifndef __EVENTPOLL_CLIENT_H__
#define __EVENTPOLL_CLIENT_H__

struct iovec;

#include "eventpoll_config.h"

#define EVENTPOLL_PROTO_TCP 1

struct eventpoll;
struct eventpoll_conn;
struct eventpoll_buffer;

struct eventpoll_bvec {
    struct eventpoll_buffer *buffer;
    void                    *data;
    unsigned int             length;
    unsigned int             flags;
};

struct eventpoll * eventpoll_init(struct eventpoll_config *config);

void eventpoll_destroy(struct eventpoll *eventpoll);

void eventpoll_wait(struct eventpoll *eventpoll, int max_msecs);

#define EVENTPOLL_EVENT_CONNECTED       1
#define EVENTPOLL_EVENT_DISCONNECTED    2
#define EVENTPOLL_EVENT_RECEIVED        3

typedef int (*eventpoll_event_callback_t)(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data);

typedef void (*eventpoll_accept_callback_t)(
    struct eventpoll_conn      *conn,
    eventpoll_event_callback_t *callback,
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
    eventpoll_event_callback_t callback,
    void *private_data);

void
eventpoll_bvec_alloc(
    struct eventpoll *eventpoll,
    unsigned int length,
    unsigned int alignment,
    struct eventpoll_bvec *r_bvec);

void
eventpoll_bvec_release(
    struct eventpoll *eventpoll,
    struct eventpoll_bvec *bvec);

static inline void *
eventpoll_bvec_data(
    struct eventpoll_bvec *bvec)
{
    return bvec->data;
}

void
eventpoll_bvec_addref(
    struct eventpoll_bvec *bvec);


void
eventpoll_send(
    struct eventpoll       *eventpoll,
    struct eventpoll_conn  *conn,
    struct eventpoll_bvec **bvecs,
    int                     nbufvecs);


void
eventpoll_close(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn);

void
eventpoll_finish(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn);

const char *
eventpoll_conn_address(struct eventpoll_conn *conn);

int
eventpoll_conn_port(struct eventpoll_conn *conn);
    
struct eventpoll_config *
eventpoll_config(struct eventpoll *eventpoll);

#endif
