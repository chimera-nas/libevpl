/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include <stdint.h>

struct iovec;
struct evpl_config;

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM   = 0,
    EVPL_FRAMEWORK_XLIO     = 1,
    EVPL_FRAMEWORK_IO_URING = 2,
    EVPL_NUM_FRAMEWORK      = 3
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP = 0,
    EVPL_DATAGRAM_RDMACM_RC  = 1,
    EVPL_DATAGRAM_RDMACM_UD  = 2,
    EVPL_STREAM_SOCKET_TCP   = 3,
    EVPL_STREAM_XLIO_TCP     = 4,
    EVPL_STREAM_RDMACM_RC    = 5,
    EVPL_NUM_PROTO           = 6
};

enum evpl_block_protocol_id {
    EVPL_BLOCK_PROTOCOL_IO_URING = 0,
    EVPL_NUM_BLOCK_PROTOCOL      = 1
};

struct evpl;
struct evpl_endpoint;
struct evpl_address;
struct evpl_bind;
struct evpl_bind;
struct evpl_buffer;
struct evpl_uevent;
struct evpl_poll;

#ifndef EVPL_INTERNAL
struct evpl_iovec {
    void        *data;
    unsigned int length;
    unsigned int pad;
    void        *private; /* for internal use by libevpl */
};
#else  // ifndef EVPL_INTERNAL
struct evpl_iovec;
#endif // ifndef EVPL_INTERNAL

struct evpl_endpoint_stub {
    unsigned char addr[128];
    int           addrlen;
};

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

struct evpl_config *
evpl_config_init(
    void);

void evpl_config_release(
    struct evpl_config *config);

void evpl_config_set_rdmacm_datagram_size_override(
    struct evpl_config *config,
    unsigned int        size);

void evpl_init(
    struct evpl_config *config);

void evpl_init_auto(
    struct evpl_config *config);

void evpl_cleanup(
    void);

struct evpl * evpl_create(
    void);

void evpl_destroy(
    struct evpl *evpl);

void evpl_wait(
    struct evpl *evpl,
    int          max_msecs);

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

typedef void (*evpl_accept_callback_t)(
    struct evpl             *evpl,
    struct evpl_bind        *listen_bind,
    struct evpl_bind        *accepted_bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data);

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl *evpl,
    const char  *address,
    int          port);

void evpl_endpoint_close(
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
    struct evpl            *evpl,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *endpoint,
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

int evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    struct evpl_iovec *r_iovec);

int evpl_iovec_reserve(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_vec,
    struct evpl_iovec *r_iovec);

void evpl_iovec_commit(
    struct evpl       *evpl,
    unsigned int       alignment,
    struct evpl_iovec *iovecs,
    int                niovs);

void evpl_iovec_release(
    struct evpl_iovec *iovec);

const void *
evpl_iovec_data(
    const struct evpl_iovec *iovec);

unsigned int
evpl_iovec_length(
    const struct evpl_iovec *iovec);

void evpl_iovec_addref(
    struct evpl_iovec *iovec);

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

void
evpl_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data);

void
evpl_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data);

void evpl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind);

void evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind);

const char *
evpl_endpoint_address(
    const struct evpl_endpoint *ep);

int evpl_endpoint_port(
    const struct evpl_endpoint *ep);

int evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name);

int evpl_protocol_is_stream(
    enum evpl_protocol_id protocol);

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_poll *
evpl_add_poll(
    struct evpl         *evpl,
    evpl_poll_callback_t callback,
    void                *private_data);

void evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll);

struct evpl_config *
evpl_config(
    struct evpl *evpl);

typedef void (*evpl_uevent_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_uevent *
evpl_add_uevent(
    struct evpl           *evpl,
    evpl_uevent_callback_t callback,
    void                  *private_data);

void evpl_arm_uevent(
    struct evpl        *evpl,
    struct evpl_uevent *uevent);

void evpl_destroy_uevent(
    struct evpl        *evpl,
    struct evpl_uevent *uevent);

struct evpl_block_device;
struct evpl_block_queue;

struct evpl_block_device *
evpl_block_open_device(
    enum evpl_block_protocol_id protocol,
    const char                 *uri);

void evpl_block_close_device(
    struct evpl_block_device *blockdev);

struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev);

void evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue);


void evpl_block_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data);

void evpl_block_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data);

void evpl_block_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data);
