/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct iovec;
struct evpl_config;

enum evpl_protocol_id {
    EVPL_SOCKET_TCP      = 1,
    EVPL_SOCKET_UDP      = 2,
    EVPL_SOCKET_UNIX     = 3,
    EVPL_RDMACM_RC       = 4,
    EVPL_RDMACM_UD       = 5,
    EVPL_NUM_PROTO       = 6
};

struct evpl;
struct evpl_endpoint;
struct evpl_conn;
struct evpl_buffer;

struct evpl_bvec {
    struct evpl_buffer *buffer;
    void               *data;
    unsigned int        length;
};

void
evpl_init(struct evpl_config *config);

void
evpl_cleanup(void);


struct evpl * evpl_create(void);

void evpl_destroy(
    struct evpl *evpl);

void evpl_wait(
    struct evpl *evpl,
    int          max_msecs);

#define EVPL_EVENT_CONNECTED    1
#define EVPL_EVENT_DISCONNECTED 2
#define EVPL_EVENT_RECEIVED     3

typedef int (*evpl_event_callback_t)(
    struct evpl      *evpl,
    struct evpl_conn *conn,
    unsigned int      event_type,
    unsigned int      event_code,
    void             *private_data);

typedef void (*evpl_accept_callback_t)(
    struct evpl_conn      *conn,
    evpl_event_callback_t *callback,
    void                 **conn_private_data,
    void                  *private_data);

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl           *evpl,
    int                    protocol,
    const char            *address,
    int                    port);

void
evpl_endpoint_close(
    struct evpl *evpl,
    struct evpl_endpoint *endpoint);

struct evpl_listener *
evpl_listen(
    struct evpl           *evpl,
    struct evpl_endpoint  *endpoint,
    evpl_accept_callback_t acceot_callback,
    void                  *private_data);

void
evpl_listener_destroy(
    struct evpl *evpl,
    struct evpl_listener *listener);

struct evpl_conn *
evpl_connect(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint,
    evpl_event_callback_t callback,
    void                 *private_data);

int
evpl_bvec_alloc(
    struct evpl      *evpl,
    unsigned int      length,
    unsigned int      alignment,
    unsigned int      max_bvecs,
    struct evpl_bvec *r_bvec);

int
evpl_bvec_reserve(
    struct evpl      *evpl,
    unsigned int      length,
    unsigned int      alignment,
    unsigned int      max_vec,
    struct evpl_bvec *r_bvec);

void
evpl_bvec_commit(
    struct evpl *evpl,
    struct evpl_bvec *bvecs,
    int         nbvecs);


void
evpl_bvec_release(
    struct evpl      *evpl,
    struct evpl_bvec *bvec);

static inline void *
evpl_bvec_data(struct evpl_bvec *bvec)
{
    return bvec->data;
} // evpl_bvec_data

void
evpl_bvec_addref(
    struct evpl *evpl,
    struct evpl_bvec *bvec);


void
evpl_send(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_bvec  *bvecs,
    int                nbufvecs);

int
evpl_peek(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    void              *buffer,
    int                length);

int
evpl_read(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    void              *buffer,
    int                length);

int
evpl_readv(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_bvec  *bvecs,
    int                maxbvecs,
    int                length);

void
evpl_close(
    struct evpl      *evpl,
    struct evpl_conn *conn);

void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_conn *conn);

const struct evpl_endpoint *
evpl_conn_endpoint(
    struct evpl_conn *conn);

const char *
evpl_endpoint_address(const struct evpl_endpoint *ep);

int
evpl_endpoint_port(const struct evpl_endpoint *ep);


struct evpl_config *
evpl_config(
    struct evpl *evpl);
