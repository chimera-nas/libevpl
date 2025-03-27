// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_bind.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_listener;
struct evpl_bind;

struct iovec;

struct evpl_notify {
    unsigned int notify_type;
    int          notify_status;
    union {
        struct {
            struct evpl_iovec   *iovec;
            unsigned int         niov;
            unsigned int         length;
            struct evpl_address *addr;
        } recv_msg;
        struct {
            unsigned long bytes;
            unsigned long msgs;
        } sent;
    };
};

#define EVPL_NOTIFY_CONNECTED    1
#define EVPL_NOTIFY_DISCONNECTED 2
#define EVPL_NOTIFY_RECV_DATA    3
#define EVPL_NOTIFY_RECV_MSG     4
#define EVPL_NOTIFY_SENT         5

typedef void (*evpl_notify_callback_t)(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data);

typedef int (*evpl_segment_callback_t)(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data);

typedef void (*evpl_attach_callback_t)(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data);

struct evpl_listener *
evpl_listener_create(
    void);

void
evpl_listener_destroy(
    struct evpl_listener *listener);

void evpl_listener_attach(
    struct evpl           *evpl,
    struct evpl_listener  *listener,
    evpl_attach_callback_t attach_callback,
    void                  *private_data);

void evpl_listener_detach(
    struct evpl          *evpl,
    struct evpl_listener *listener);

void
evpl_listen(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol,
    struct evpl_endpoint *endpoint);

struct evpl_bind *
evpl_connect(
    struct evpl            *evpl,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *local_endpoint,
    struct evpl_endpoint   *remote_endpoint,
    evpl_notify_callback_t  notify_callback,
    evpl_segment_callback_t segment_callback,
    void                   *private_data);

struct evpl_bind *
evpl_bind(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data);

void evpl_bind_request_send_notifications(
    struct evpl      *evpl,
    struct evpl_bind *bind);

void evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length);

void evpl_sendv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                nbufvecs,
    int                length);

void evpl_sendto(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    const void          *buffer,
    unsigned int         length);

void evpl_sendtoep(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length);

void evpl_sendtov(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    struct evpl_iovec   *iovecs,
    int                  nbufvecs,
    int                  length);

void evpl_sendtoepv(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_iovec    *iovecs,
    int                   nbufvecs,
    int                   length);

int evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);

int evpl_peekv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length);

void evpl_consume(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               length);

int evpl_read(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);

int evpl_readv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length);

int evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);

int evpl_recvv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length);

void evpl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind);

void evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind);

void evpl_bind_get_local_address(
    struct evpl_bind *bind,
    char             *str,
    int               len);

void evpl_bind_get_remote_address(
    struct evpl_bind *bind,
    char             *str,
    int               len);

enum evpl_protocol_id evpl_bind_get_protocol(
    struct evpl_bind *bind);
