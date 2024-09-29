/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct iovec;
struct evpl_config;

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM = 0,
    EVPL_NUM_FRAMEWORK    = 1
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP = 0,
    EVPL_DATAGRAM_RDMACM_RC  = 1,
    EVPL_STREAM_SOCKET_TCP   = 2,
    EVPL_STREAM_RDMACM_RC    = 3,
    EVPL_NUM_PROTO           = 4
};

struct evpl;
struct evpl_endpoint;
struct evpl_endpoint_stub;
struct evpl_bind;
struct evpl_bind;
struct evpl_buffer;

struct evpl_bvec {
    struct evpl_buffer *buffer;
    void               *data;
    unsigned int        length;
    unsigned int        eom;
};

struct evpl_endpoint_stub {
    unsigned char addr[128];
    int           addrlen;
};

struct evpl_notify {
    unsigned int notify_type;
    int          notify_status;
    union {
        struct {
            struct evpl_bvec                *bvec;
            unsigned int                     nbvec;
            const struct evpl_endpoint_stub *eps;
        } recv_msg;
    };
};

void
evpl_init(
    struct evpl_config *config);

void
evpl_cleanup(
    void);


struct evpl * evpl_create(
    void);

void evpl_destroy(
    struct evpl *evpl);

void evpl_wait(
    struct evpl *evpl,
    int          max_msecs);

#define EVPL_NOTIFY_CONNECTED     1
#define EVPL_NOTIFY_DISCONNECTED  2
#define EVPL_NOTIFY_RECV_DATA     3
#define EVPL_NOTIFY_RECV_DATAGRAM 4
#define EVPL_NOTIFY_SENT          5


typedef int (*evpl_notify_callback_t)(
    struct evpl              *evpl,
    struct evpl_bind         *bind,
    const struct evpl_notify *notify,
    void                     *private_data);

typedef void (*evpl_accept_callback_t)(
    struct evpl_bind       *bind,
    evpl_notify_callback_t *callback,
    void                  **conn_private_data,
    void                   *private_data);

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl *evpl,
    const char  *address,
    int          port);

void
evpl_endpoint_close(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint);

struct evpl_bind *
evpl_listen(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol,
    struct evpl_endpoint  *endpoint,
    evpl_accept_callback_t accept_callback,
    void                  *private_data);

struct evpl_bind *
evpl_connect(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data);

struct evpl_bind *
evpl_bind(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data);

void
evpl_bind_request_send_notifications(
    struct evpl      *evpl,
    struct evpl_bind *bind);

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
    struct evpl      *evpl,
    struct evpl_bvec *bvecs,
    int               nbvecs);


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
    struct evpl      *evpl,
    struct evpl_bvec *bvec);


void
evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length);

void
evpl_sendv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_bvec *bvecs,
    int               nbufvecs,
    int               length);

void
evpl_sendto(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length);

void
evpl_sendtov(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_bvec     *bvecs,
    int                   nbufvecs,
    int                   length);

int
evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);

int
evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);

int
evpl_recvv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_bvec *bvecs,
    int               maxbvecs,
    int               length);

void
evpl_disconnect(
    struct evpl      *evpl,
    struct evpl_bind *bind);

void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind);

const char *
evpl_endpoint_address(
    const struct evpl_endpoint *ep);

int
evpl_endpoint_port(
    const struct evpl_endpoint *ep);


int
evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name);

struct evpl_config *
evpl_config(
    struct evpl *evpl);
