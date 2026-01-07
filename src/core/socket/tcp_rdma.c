// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <endian.h>

#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/socket/common.h"
#include "core/socket/tcp.h"
#include "core/socket/tcp_rdma.h"

/*
 * TCP_RDMA Message Header - 32 bytes, network byte order
 */
#define TCP_RDMA_MAGIC          0x54524D41 /* "TRMA" */
#define TCP_RDMA_HEADER_SIZE    32

enum tcp_rdma_opcode {
    TCP_RDMA_OP_SEND          = 1,
    TCP_RDMA_OP_READ_REQUEST  = 2,
    TCP_RDMA_OP_READ_REPLY    = 3,
    TCP_RDMA_OP_WRITE_REQUEST = 4,
    TCP_RDMA_OP_WRITE_REPLY   = 5,
    TCP_RDMA_OP_ERROR         = 6,
};

struct tcp_rdma_header {
    uint32_t magic;
    uint32_t opcode;
    uint32_t length;
    uint32_t remote_key;
    uint64_t remote_address;
    uint64_t id;
} __attribute__((packed));

/*
 * Memory registration structures
 */
#define TCP_RDMA_MR_HASH_SIZE 256

struct tcp_rdma_mr {
    void               *base;
    size_t              size;
    uint32_t            rkey;
    struct tcp_rdma_mr *next;
};

struct tcp_rdma_mr_table {
    struct tcp_rdma_mr *buckets[TCP_RDMA_MR_HASH_SIZE];
    uint32_t            next_rkey;
    pthread_mutex_t     lock;
};

/*
 * Pending operation tracking
 */
struct tcp_rdma_pending_op {
    uint64_t                    id;
    int                         opcode;
    struct evpl_iovec          *iov;
    int                         niov;
    int                         length;
    void                      (*callback)(int status, void *private_data);
    void                       *private_data;
    struct tcp_rdma_pending_op *next;
};

/*
 * Per-connection state (extends evpl_socket)
 */
struct evpl_tcp_rdma_socket {
    struct evpl_socket          socket;
    struct tcp_rdma_pending_op *pending_ops;
    uint64_t                    next_op_id;
};

#define evpl_event_tcp_rdma_socket(eventp) \
    container_of((eventp), struct evpl_tcp_rdma_socket, socket.event)

/*
 * Global and per-thread framework state
 */
struct evpl_tcp_rdma_global {
    struct tcp_rdma_mr_table mr_table;
};

struct evpl_tcp_rdma {
    struct evpl_tcp_rdma_global *global;
};

/*
 * Forward declarations
 */
static void evpl_tcp_rdma_read(struct evpl *evpl, struct evpl_event *event);
static void evpl_tcp_rdma_write(struct evpl *evpl, struct evpl_event *event);
static void evpl_tcp_rdma_error(struct evpl *evpl, struct evpl_event *event);
void evpl_tcp_rdma_flush(struct evpl *evpl, struct evpl_bind *bind);

/*
 * Memory registration functions
 */
static struct tcp_rdma_mr *
tcp_rdma_mr_lookup(
    struct evpl_tcp_rdma_global *global,
    uint32_t                     rkey)
{
    struct tcp_rdma_mr *mr;
    int                 bucket = rkey % TCP_RDMA_MR_HASH_SIZE;

    pthread_mutex_lock(&global->mr_table.lock);
    mr = global->mr_table.buckets[bucket];
    while (mr) {
        if (mr->rkey == rkey) {
            pthread_mutex_unlock(&global->mr_table.lock);
            return mr;
        }
        mr = mr->next;
    }
    pthread_mutex_unlock(&global->mr_table.lock);
    return NULL;
}

static int
tcp_rdma_validate_access(
    struct evpl_tcp_rdma_global *global,
    uint32_t                     rkey,
    uint64_t                     address,
    uint32_t                     length,
    void                       **out_ptr)
{
    struct tcp_rdma_mr *mr = tcp_rdma_mr_lookup(global, rkey);

    if (!mr) {
        return -EINVAL;
    }

    if (address < (uint64_t) mr->base ||
        address + length > (uint64_t) mr->base + mr->size) {
        return -EINVAL;
    }

    *out_ptr = (void *) address;
    return 0;
}

/*
 * Pending operation management
 */
static struct tcp_rdma_pending_op *
tcp_rdma_pending_add(
    struct evpl_tcp_rdma_socket *ts,
    int                          opcode,
    struct evpl_iovec           *iov,
    int                          niov,
    int                          length,
    void                       (*callback)(int status, void *private_data),
    void                        *private_data)
{
    struct tcp_rdma_pending_op *op = evpl_zalloc(sizeof(*op));
    int                         i;

    op->id           = ts->next_op_id++;
    op->opcode       = opcode;
    op->niov         = niov;
    op->length       = length;
    op->callback     = callback;
    op->private_data = private_data;
    op->next         = ts->pending_ops;
    ts->pending_ops  = op;

    /* Move iovecs (they may be stack-allocated, so we need to properly
     * transfer ownership including canary tracking) */
    if (niov > 0) {
        op->iov = evpl_zalloc(niov * sizeof(*op->iov));
        for (i = 0; i < niov; i++) {
            evpl_iovec_move(&op->iov[i], &iov[i]);
        }
    } else {
        op->iov = NULL;
    }

    return op;
}

static struct tcp_rdma_pending_op *
tcp_rdma_pending_find(
    struct evpl_tcp_rdma_socket *ts,
    uint64_t                     id)
{
    struct tcp_rdma_pending_op *op = ts->pending_ops;

    while (op) {
        if (op->id == id) {
            return op;
        }
        op = op->next;
    }
    return NULL;
}

static void
tcp_rdma_pending_remove(
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_pending_op  *op)
{
    struct tcp_rdma_pending_op **pp = &ts->pending_ops;

    while (*pp) {
        if (*pp == op) {
            *pp = op->next;
            if (op->iov) {
                /* Release the library's reference to the iovecs.
                 * For RDMA READ: we cloned the app's iovec, now release our ref.
                 * For RDMA WRITE: we moved the iovec, releasing is correct. */
                evpl_iovecs_release(op->iov, op->niov);
                evpl_free(op->iov);
            }
            evpl_free(op);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void
tcp_rdma_pending_clear(struct evpl_tcp_rdma_socket *ts)
{
    struct tcp_rdma_pending_op *op, *next;

    op = ts->pending_ops;
    while (op) {
        next = op->next;
        if (op->callback) {
            op->callback(ECONNRESET, op->private_data);
        }
        if (op->iov) {
            evpl_iovecs_release(op->iov, op->niov);
            evpl_free(op->iov);
        }
        evpl_free(op);
        op = next;
    }
    ts->pending_ops = NULL;
}

/*
 * Helper to peek at bytes in iovec_recv ring without consuming
 */
static int
tcp_rdma_peek_bytes(
    struct evpl_iovec_ring *ring,
    void                   *buf,
    int                     offset,
    int                     length)
{
    struct evpl_iovec *iovec;
    int                pos, skip, copied = 0;
    int                chunk;
    char              *dst = buf;

    if (evpl_iovec_ring_bytes(ring) < (uint64_t) (offset + length)) {
        return -1;
    }

    pos = ring->tail;

    /* Skip to offset */
    skip = offset;
    while (skip > 0 && pos != ring->head) {
        iovec = &ring->iovec[pos];
        if ((int) iovec->length <= skip) {
            skip -= iovec->length;
            pos   = (pos + 1) & ring->mask;
        } else {
            break;
        }
    }

    /* Copy length bytes */
    while (copied < length && pos != ring->head) {
        iovec = &ring->iovec[pos];
        chunk = iovec->length - skip;
        if (chunk > length - copied) {
            chunk = length - copied;
        }
        memcpy(dst + copied, (char *) iovec->data + skip, chunk);
        copied += chunk;
        skip    = 0;
        pos     = (pos + 1) & ring->mask;
    }

    return copied;
}

/*
 * Helper to copy payload from ring to contiguous buffer
 */
static void
tcp_rdma_copy_payload_to_buffer(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring,
    int                     offset,
    void                   *buf,
    int                     length)
{
    /* Use peek to copy, then consume */
    tcp_rdma_peek_bytes(ring, buf, offset, length);
}

/*
 * Helper to copy payload from ring to iovec array
 */
static void
tcp_rdma_copy_payload_to_iovec(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring,
    int                     offset,
    struct evpl_iovec      *iov,
    int                     niov)
{
    struct evpl_iovec *src;
    int                pos, skip, i;
    int                chunk, remaining;
    char              *dst;

    pos = ring->tail;

    /* Skip to offset */
    skip = offset;
    while (skip > 0 && pos != ring->head) {
        src = &ring->iovec[pos];
        if ((int) src->length <= skip) {
            skip -= src->length;
            pos   = (pos + 1) & ring->mask;
        } else {
            break;
        }
    }

    /* Copy to each destination iovec */
    for (i = 0; i < niov; i++) {
        dst       = iov[i].data;
        remaining = iov[i].length;

        while (remaining > 0 && pos != ring->head) {
            src   = &ring->iovec[pos];
            chunk = src->length - skip;
            if (chunk > remaining) {
                chunk = remaining;
            }
            memcpy(dst, (char *) src->data + skip, chunk);
            dst       += chunk;
            remaining -= chunk;
            skip       = 0;
            if (chunk == (int) src->length) {
                pos = (pos + 1) & ring->mask;
            } else {
                skip = chunk;
            }
        }
    }
}

/*
 * Queue a header + optional payload for sending
 */
static void
tcp_rdma_queue_message(
    struct evpl            *evpl,
    struct evpl_bind       *bind,
    struct tcp_rdma_header *header,
    void                   *payload,
    int                     payload_len)
{
    struct evpl_iovec iov;
    char             *buf;
    int               alloc_len = TCP_RDMA_HEADER_SIZE + payload_len;

    /* Allocate buffer for header + payload */
    evpl_iovec_alloc(evpl, alloc_len, 1, 1, &iov);
    buf = iov.data;

    /* Copy header in network byte order */
    struct tcp_rdma_header *hdr = (struct tcp_rdma_header *) buf;

    hdr->magic          = htonl(header->magic);
    hdr->opcode         = htonl(header->opcode);
    hdr->length         = htonl(header->length);
    hdr->remote_key     = htonl(header->remote_key);
    hdr->remote_address = htobe64(header->remote_address);
    hdr->id             = htobe64(header->id);

    /* Copy payload if any */
    if (payload && payload_len > 0) {
        memcpy(buf + TCP_RDMA_HEADER_SIZE, payload, payload_len);
    }

    iov.length = TCP_RDMA_HEADER_SIZE + payload_len;

    /* Add to send ring */
    evpl_iovec_ring_add(&bind->iovec_send, &iov);
}

/*
 * Queue header + iovecs for sending (for RDMA write)
 */
static void
tcp_rdma_queue_message_iov(
    struct evpl            *evpl,
    struct evpl_bind       *bind,
    struct tcp_rdma_header *header,
    struct evpl_iovec      *payload_iov,
    int                     niov)
{
    struct evpl_iovec iov;
    char             *buf;
    int               i;

    /* Allocate buffer for header only */
    evpl_iovec_alloc(evpl, TCP_RDMA_HEADER_SIZE, 1, 1, &iov);
    buf = iov.data;

    /* Copy header in network byte order */
    struct tcp_rdma_header *hdr = (struct tcp_rdma_header *) buf;

    hdr->magic          = htonl(header->magic);
    hdr->opcode         = htonl(header->opcode);
    hdr->length         = htonl(header->length);
    hdr->remote_key     = htonl(header->remote_key);
    hdr->remote_address = htobe64(header->remote_address);
    hdr->id             = htobe64(header->id);

    iov.length = TCP_RDMA_HEADER_SIZE;

    /* Add header to send ring */
    evpl_iovec_ring_add(&bind->iovec_send, &iov);

    /* Add payload iovecs to send ring */
    for (i = 0; i < niov; i++) {
        evpl_iovec_ring_add_clone(&bind->iovec_send, &payload_iov[i]);
    }
}

/*
 * Message handlers
 */
static void
tcp_rdma_handle_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    uint32_t          length)
{
    struct evpl_notify  notify;
    struct evpl_iovec  *iovec;
    int                 niov;

    /* Skip header, extract payload */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    iovec = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);
    niov  = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv, length);

    notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
    notify.recv_msg.iovec  = iovec;
    notify.recv_msg.niov   = niov;
    notify.recv_msg.length = length;
    notify.recv_msg.addr   = bind->remote;

    bind->notify_callback(evpl, bind, &notify, bind->private_data);
}

static void
tcp_rdma_handle_read_request(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *req_hdr)
{
    struct evpl_tcp_rdma        *tcp_rdma = evpl_framework_private(evpl, EVPL_FRAMEWORK_TCP_RDMA);
    struct evpl_tcp_rdma_global *global   = tcp_rdma->global;
    struct tcp_rdma_header       reply;
    void                        *ptr;
    int                          rc;
    uint32_t                     read_len_payload;
    uint32_t                     read_len;

    /* Consume the header */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    /* Extract the read length from 4-byte payload */
    tcp_rdma_copy_payload_to_buffer(evpl, &bind->iovec_recv, 0,
                                    &read_len_payload, sizeof(read_len_payload));
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, sizeof(read_len_payload));
    read_len = ntohl(read_len_payload);

    /* Validate memory access */
    rc = tcp_rdma_validate_access(global, req_hdr->remote_key,
                                  req_hdr->remote_address, read_len,
                                  &ptr);

    if (rc < 0) {
        /* Send error response */
        reply.magic          = TCP_RDMA_MAGIC;
        reply.opcode         = TCP_RDMA_OP_ERROR;
        reply.length         = EINVAL;
        reply.remote_key     = req_hdr->remote_key;
        reply.remote_address = req_hdr->remote_address;
        reply.id             = req_hdr->id;
        tcp_rdma_queue_message(evpl, bind, &reply, NULL, 0);
    } else {
        /* Send read reply with data */
        reply.magic          = TCP_RDMA_MAGIC;
        reply.opcode         = TCP_RDMA_OP_READ_REPLY;
        reply.length         = read_len;
        reply.remote_key     = req_hdr->remote_key;
        reply.remote_address = req_hdr->remote_address;
        reply.id             = req_hdr->id;
        tcp_rdma_queue_message(evpl, bind, &reply, ptr, read_len);
    }

    evpl_defer(evpl, &bind->flush_deferral);
}

static void
tcp_rdma_handle_read_reply(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *hdr)
{
    struct tcp_rdma_pending_op *op;
    int                         i, remaining, chunk;

    op = tcp_rdma_pending_find(ts, hdr->id);
    if (!op) {
        /* Unexpected reply - discard */
        evpl_iovec_ring_consume(evpl, &bind->iovec_recv,
                                TCP_RDMA_HEADER_SIZE + hdr->length);
        return;
    }

    /* Skip header */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    /* Copy payload to pending operation's iovecs */
    remaining = hdr->length;
    for (i = 0; i < op->niov && remaining > 0; i++) {
        chunk = op->iov[i].length;
        if (chunk > remaining) {
            chunk = remaining;
        }

        /* Read from ring directly into iovec */
        struct evpl_iovec *src_iov;
        int                copied = 0;
        int                pos    = bind->iovec_recv.tail;

        while (copied < chunk && pos != bind->iovec_recv.head) {
            src_iov = &bind->iovec_recv.iovec[pos];
            int copy_len = src_iov->length;

            if (copy_len > chunk - copied) {
                copy_len = chunk - copied;
            }
            memcpy((char *) op->iov[i].data + copied, src_iov->data, copy_len);
            copied += copy_len;
            pos     = (pos + 1) & bind->iovec_recv.mask;
        }

        remaining -= chunk;
    }

    /* Consume payload from ring */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, hdr->length);

    /* Invoke callback */
    if (op->callback) {
        op->callback(0, op->private_data);
    }

    tcp_rdma_pending_remove(ts, op);
}

static void
tcp_rdma_handle_write_request(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *req_hdr)
{
    struct evpl_tcp_rdma        *tcp_rdma = evpl_framework_private(evpl, EVPL_FRAMEWORK_TCP_RDMA);
    struct evpl_tcp_rdma_global *global   = tcp_rdma->global;
    struct tcp_rdma_header       reply;
    void                        *ptr;
    int                          rc;

    /* Validate memory access */
    rc = tcp_rdma_validate_access(global, req_hdr->remote_key,
                                  req_hdr->remote_address, req_hdr->length,
                                  &ptr);

    if (rc < 0) {
        /* Consume message and send error */
        evpl_iovec_ring_consume(evpl, &bind->iovec_recv,
                                TCP_RDMA_HEADER_SIZE + req_hdr->length);

        reply.magic          = TCP_RDMA_MAGIC;
        reply.opcode         = TCP_RDMA_OP_ERROR;
        reply.length         = EINVAL;
        reply.remote_key     = req_hdr->remote_key;
        reply.remote_address = req_hdr->remote_address;
        reply.id             = req_hdr->id;
        tcp_rdma_queue_message(evpl, bind, &reply, NULL, 0);
    } else {
        /* Skip header */
        evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

        /* Copy payload directly to registered memory */
        int       remaining = req_hdr->length;
        int       copied    = 0;
        char     *dst       = ptr;

        while (remaining > 0 && bind->iovec_recv.tail != bind->iovec_recv.head) {
            struct evpl_iovec *src_iov = &bind->iovec_recv.iovec[bind->iovec_recv.tail];
            int                chunk   = src_iov->length;

            if (chunk > remaining) {
                chunk = remaining;
            }
            memcpy(dst + copied, src_iov->data, chunk);
            copied    += chunk;
            remaining -= chunk;

            if (chunk == (int) src_iov->length) {
                evpl_iovec_release(src_iov);
                bind->iovec_recv.tail = (bind->iovec_recv.tail + 1) &
                                        bind->iovec_recv.mask;
            } else {
                src_iov->data   += chunk;
                src_iov->length -= chunk;
            }
            bind->iovec_recv.length -= chunk;
        }

        /* Send write reply (acknowledgment) */
        reply.magic          = TCP_RDMA_MAGIC;
        reply.opcode         = TCP_RDMA_OP_WRITE_REPLY;
        reply.length         = 0;
        reply.remote_key     = req_hdr->remote_key;
        reply.remote_address = req_hdr->remote_address;
        reply.id             = req_hdr->id;
        tcp_rdma_queue_message(evpl, bind, &reply, NULL, 0);
    }

    evpl_defer(evpl, &bind->flush_deferral);
}

static void
tcp_rdma_handle_write_reply(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *hdr)
{
    struct tcp_rdma_pending_op *op;

    /* Consume message (header only) */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    op = tcp_rdma_pending_find(ts, hdr->id);
    if (!op) {
        return;
    }

    /* Invoke callback */
    if (op->callback) {
        op->callback(0, op->private_data);
    }

    tcp_rdma_pending_remove(ts, op);
}

static void
tcp_rdma_handle_error(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *hdr)
{
    struct tcp_rdma_pending_op *op;

    /* Consume message (header only) */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    op = tcp_rdma_pending_find(ts, hdr->id);
    if (!op) {
        return;
    }

    /* Invoke callback with error */
    if (op->callback) {
        op->callback(hdr->length, op->private_data); /* length contains error code */
    }

    tcp_rdma_pending_remove(ts, op);
}

/*
 * Connection check (from TCP)
 */
static inline void
evpl_tcp_rdma_check_conn(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts)
{
    struct evpl_notify notify;
    socklen_t          len;
    int                rc, err;

    if (unlikely(!ts->socket.connected)) {
        len = sizeof(err);
        rc  = getsockopt(ts->socket.fd, SOL_SOCKET, SO_ERROR, &err, &len);
        evpl_socket_fatal_if(rc, "Failed to get SO_ERROR from socket");

        if (err) {
            evpl_close(evpl, bind);
        } else {
            notify.notify_type   = EVPL_NOTIFY_CONNECTED;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

        ts->socket.connected = 1;
    }
}

/*
 * Read handler - peek-based message parsing
 */
static void
evpl_tcp_rdma_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tcp_rdma_socket *ts   = evpl_event_tcp_rdma_socket(event);
    struct evpl_socket          *s    = &ts->socket;
    struct evpl_bind            *bind = evpl_private2bind(ts);
    struct iovec                 iov[2];
    ssize_t                      res, total, remain;
    struct tcp_rdma_header       hdr;
    uint32_t                     msg_len;


    if (unlikely(s->fd < 0)) {
        return;
    }

    evpl_tcp_rdma_check_conn(evpl, bind, ts);

    /* Allocate receive buffers if needed */
    if (s->recv1.length == 0) {
        if (s->recv2.length) {
            evpl_iovec_move(&s->recv1, &s->recv2);
            s->recv2.length = 0;
        } else {
            evpl_iovec_alloc_whole(evpl, &s->recv1);
        }
    }

    if (s->recv2.length == 0) {
        evpl_iovec_alloc_whole(evpl, &s->recv2);
    }

    iov[0].iov_base = s->recv1.data;
    iov[0].iov_len  = s->recv1.length;
    iov[1].iov_base = s->recv2.data;
    iov[1].iov_len  = s->recv2.length;

    total = iov[0].iov_len + iov[1].iov_len;

    res = readv(s->fd, iov, 2);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    /* Append received data to iovec_recv ring */
    if (s->recv1.length >= res) {
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1, res);
    } else {
        remain = res - s->recv1.length;
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1,
                               s->recv1.length);
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv2, remain);
    }

    /* Process complete messages */
    while (evpl_iovec_ring_bytes(&bind->iovec_recv) >= TCP_RDMA_HEADER_SIZE) {
        /* Peek at header */
        if (tcp_rdma_peek_bytes(&bind->iovec_recv, &hdr, 0,
                                TCP_RDMA_HEADER_SIZE) < 0) {
            break;
        }

        /* Convert from network byte order */
        hdr.magic          = ntohl(hdr.magic);
        hdr.opcode         = ntohl(hdr.opcode);
        hdr.length         = ntohl(hdr.length);
        hdr.remote_key     = ntohl(hdr.remote_key);
        hdr.remote_address = be64toh(hdr.remote_address);
        hdr.id             = be64toh(hdr.id);

        /* Validate magic */
        if (hdr.magic != TCP_RDMA_MAGIC) {
            evpl_socket_error("Invalid TCP_RDMA magic: 0x%08x", hdr.magic);
            evpl_close(evpl, bind);
            goto out;
        }

        /* Check if we have complete message */
        msg_len = TCP_RDMA_HEADER_SIZE + hdr.length;
        if (evpl_iovec_ring_bytes(&bind->iovec_recv) < msg_len) {
            break; /* Wait for more data */
        }

        /* Dispatch based on opcode */
        switch (hdr.opcode) {
        case TCP_RDMA_OP_SEND:
            tcp_rdma_handle_send(evpl, bind, hdr.length);
            break;
        case TCP_RDMA_OP_READ_REQUEST:
            tcp_rdma_handle_read_request(evpl, bind, ts, &hdr);
            break;
        case TCP_RDMA_OP_READ_REPLY:
            tcp_rdma_handle_read_reply(evpl, bind, ts, &hdr);
            break;
        case TCP_RDMA_OP_WRITE_REQUEST:
            tcp_rdma_handle_write_request(evpl, bind, ts, &hdr);
            break;
        case TCP_RDMA_OP_WRITE_REPLY:
            tcp_rdma_handle_write_reply(evpl, bind, ts, &hdr);
            break;
        case TCP_RDMA_OP_ERROR:
            tcp_rdma_handle_error(evpl, bind, ts, &hdr);
            break;
        default:
            evpl_socket_error("Unknown TCP_RDMA opcode: %u", hdr.opcode);
            evpl_close(evpl, bind);
            goto out;
        }
    }

 out:
    if (res < total) {
        evpl_event_mark_unreadable(evpl, event);
    }
}

/*
 * Write handler - same as TCP
 */
static void
evpl_tcp_rdma_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tcp_rdma_socket *ts   = evpl_event_tcp_rdma_socket(event);
    struct evpl_socket          *s    = &ts->socket;
    struct evpl_bind            *bind = evpl_private2bind(ts);
    struct evpl_notify           notify;
    struct iovec                *iov;
    int                          maxiov = evpl_shared->config->max_num_iovec;
    int                          niov;
    ssize_t                      res, total;


    if (unlikely(s->fd < 0)) {
        return;
    }

    iov = alloca(sizeof(struct iovec) * maxiov);

    evpl_tcp_rdma_check_conn(evpl, bind, ts);

    /*
     * If dgram_send has pending entries, the flush hasn't processed them yet.
     * The iovecs in iovec_send are raw data from evpl_sendtov that need
     * headers added by the flush. Trigger the flush now and it will re-enable
     * write interest when done.
     */
    if (!evpl_dgram_ring_is_empty(&bind->dgram_send) ||
        !evpl_dgram_ring_is_empty(&bind->dgram_read)) {
        evpl_tcp_rdma_flush(evpl, bind);
    }

    niov = evpl_iovec_ring_iov(&total, iov, maxiov, &bind->iovec_send);

    if (!niov) {
        res = 0;
        goto out;
    }

    res = writev(s->fd, iov, niov);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_send, res);

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }

    if (res && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = res;
        notify.sent.msgs     = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:
    if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_event_write_disinterest(evpl, event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }
}

/*
 * Error handler
 */
static void
evpl_tcp_rdma_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tcp_rdma_socket *ts   = evpl_event_tcp_rdma_socket(event);
    struct evpl_bind            *bind = evpl_private2bind(ts);

    if (unlikely(ts->socket.fd < 0)) {
        return;
    }

    evpl_close(evpl, bind);
}

/*
 * Attach handler - custom version that registers tcp_rdma callbacks
 */
void
evpl_tcp_rdma_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_tcp_rdma_socket *ts              = evpl_bind_private(bind);
    struct evpl_accepted_socket *accepted_socket = accepted;
    struct evpl_notify           notify;
    int                          fd = accepted_socket->fd;
    int                          rc, yes = 1;
    struct sockaddr_storage      ss;
    socklen_t                    sslen = sizeof(ss);

    evpl_free(accepted_socket);

    /* Initialize socket */
    evpl_socket_init(evpl, &ts->socket, fd, 1);

    /* Initialize TCP_RDMA specific state */
    ts->pending_ops = NULL;
    ts->next_op_id  = 1;

    rc = getsockname(fd, (struct sockaddr *) &ss, &sslen);
    evpl_socket_abort_if(rc < 0, "getsockname failed: %s", strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    rc = setsockopt(ts->socket.fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    evpl_socket_abort_if(rc, "Failed to set TCP_NODELAY on socket");

    /* Register tcp_rdma-specific callbacks */
    evpl_add_event(evpl, &ts->socket.event, fd,
                   evpl_tcp_rdma_read,
                   evpl_tcp_rdma_write,
                   evpl_tcp_rdma_error);

    evpl_event_read_interest(evpl, &ts->socket.event);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);
}

/*
 * Connect handler - custom version that registers tcp_rdma callbacks
 */
void
evpl_tcp_rdma_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts = evpl_bind_private(bind);
    int                          rc, yes = 1;
    struct sockaddr_storage      ss;
    socklen_t                    sslen = sizeof(ss);

    ts->socket.fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);
    evpl_socket_abort_if(ts->socket.fd < 0, "Failed to create tcp socket: %s",
                         strerror(errno));

    rc = connect(ts->socket.fd, bind->remote->addr, bind->remote->addrlen);
    evpl_socket_abort_if(rc < 0 && errno != EINPROGRESS,
                         "Failed to connect tcp socket: %s", strerror(errno));

    rc = getsockname(ts->socket.fd, (struct sockaddr *) &ss, &sslen);
    evpl_socket_abort_if(rc < 0, "Failed to getsockname on socket: %s",
                         strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    evpl_socket_init(evpl, &ts->socket, ts->socket.fd, 0);

    /* Initialize TCP_RDMA specific state */
    ts->pending_ops = NULL;
    ts->next_op_id  = 1;

    rc = setsockopt(ts->socket.fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    evpl_socket_abort_if(rc, "Failed to set TCP_NODELAY on socket");

    evpl_add_event(evpl, &ts->socket.event, ts->socket.fd,
                   evpl_tcp_rdma_read,
                   evpl_tcp_rdma_write,
                   evpl_tcp_rdma_error);

    evpl_event_read_interest(evpl, &ts->socket.event);
    evpl_event_write_interest(evpl, &ts->socket.event);
}

/*
 * Flush handler - process dgram rings and create headers
 */
void
evpl_tcp_rdma_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts = evpl_bind_private(bind);
    struct evpl_dgram           *dgram;
    struct evpl_iovec           *iov;
    struct tcp_rdma_header       hdr;
    struct tcp_rdma_pending_op  *op;
    int                          i;


    /* Process RDMA read requests from dgram_read ring */
    while ((dgram = evpl_dgram_ring_tail(&bind->dgram_read)) != NULL) {
        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_READ) {
            /* Extract iovecs from iovec_rdma_read ring */
            iov = alloca(sizeof(struct evpl_iovec) * dgram->niov);
            for (i = 0; i < dgram->niov; i++) {
                struct evpl_iovec *src = evpl_iovec_ring_tail(&bind->iovec_rdma_read);

                if (src) {
                    evpl_iovec_move(&iov[i], src);
                    evpl_iovec_ring_remove(&bind->iovec_rdma_read);
                }
            }

            /* Create pending operation */
            op = tcp_rdma_pending_add(ts, TCP_RDMA_OP_READ_REQUEST,
                                      iov, dgram->niov, dgram->length,
                                      dgram->callback, dgram->private_data);

            /* Send read request - payload contains the read length */
            uint32_t read_len_payload = htonl(dgram->length);

            hdr.magic          = TCP_RDMA_MAGIC;
            hdr.opcode         = TCP_RDMA_OP_READ_REQUEST;
            hdr.length         = sizeof(read_len_payload); /* 4-byte payload */
            hdr.remote_key     = dgram->remote_key;
            hdr.remote_address = dgram->remote_address;
            hdr.id             = op->id;
            tcp_rdma_queue_message(evpl, bind, &hdr, &read_len_payload,
                                   sizeof(read_len_payload));
        }
        evpl_dgram_ring_remove(&bind->dgram_read);
    }

    /* Process sends and RDMA writes from dgram_send ring */
    while ((dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {
        /* Extract iovecs from iovec_send ring */
        iov = alloca(sizeof(struct evpl_iovec) * dgram->niov);
        for (i = 0; i < dgram->niov; i++) {
            struct evpl_iovec *src = evpl_iovec_ring_tail(&bind->iovec_send);

            if (src) {
                evpl_iovec_move(&iov[i], src);
                evpl_iovec_ring_remove(&bind->iovec_send);
            }
        }

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_SEND) {
            /* Regular send - add header + data */
            hdr.magic          = TCP_RDMA_MAGIC;
            hdr.opcode         = TCP_RDMA_OP_SEND;
            hdr.length         = dgram->length;
            hdr.remote_key     = 0;
            hdr.remote_address = 0;
            hdr.id             = 0;
            tcp_rdma_queue_message_iov(evpl, bind, &hdr, iov, dgram->niov);

            /* Release iovecs */
            for (i = 0; i < dgram->niov; i++) {
                evpl_iovec_release(&iov[i]);
            }
        } else if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
            /* Create pending operation */
            op = tcp_rdma_pending_add(ts, TCP_RDMA_OP_WRITE_REQUEST,
                                      NULL, 0, dgram->length,
                                      dgram->callback, dgram->private_data);

            /* Send write request with data */
            hdr.magic          = TCP_RDMA_MAGIC;
            hdr.opcode         = TCP_RDMA_OP_WRITE_REQUEST;
            hdr.length         = dgram->length;
            hdr.remote_key     = dgram->remote_key;
            hdr.remote_address = dgram->remote_address;
            hdr.id             = op->id;
            tcp_rdma_queue_message_iov(evpl, bind, &hdr, iov, dgram->niov);

            /* Release iovecs */
            for (i = 0; i < dgram->niov; i++) {
                evpl_iovec_release(&iov[i]);
            }
        }

        evpl_dgram_ring_remove(&bind->dgram_send);
    }

    /* Enable write interest to send queued data */
    evpl_event_write_interest(evpl, &ts->socket.event);
}

/*
 * Close handler - cleanup pending ops
 */
void
evpl_tcp_rdma_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts = evpl_bind_private(bind);

    /* Clear pending operations with error */
    tcp_rdma_pending_clear(ts);

    /* Call base socket close */
    evpl_socket_close(evpl, bind);
}

/*
 * Framework functions
 */
static void *
tcp_rdma_init(void)
{
    struct evpl_tcp_rdma_global *global = evpl_zalloc(sizeof(*global));

    pthread_mutex_init(&global->mr_table.lock, NULL);
    global->mr_table.next_rkey = 1;

    return global;
}

static void
tcp_rdma_cleanup(void *private_data)
{
    struct evpl_tcp_rdma_global *global = private_data;
    struct tcp_rdma_mr          *mr, *next;
    int                          i;

    for (i = 0; i < TCP_RDMA_MR_HASH_SIZE; i++) {
        mr = global->mr_table.buckets[i];
        while (mr) {
            next = mr->next;
            evpl_free(mr);
            mr = next;
        }
    }

    pthread_mutex_destroy(&global->mr_table.lock);
    evpl_free(global);
}

static void *
tcp_rdma_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_tcp_rdma_global *global   = private_data;
    struct evpl_tcp_rdma        *tcp_rdma = evpl_zalloc(sizeof(*tcp_rdma));

    tcp_rdma->global = global;

    return tcp_rdma;
}

static void
tcp_rdma_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_free(private_data);
}

static void *
tcp_rdma_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *framework_private)
{
    struct evpl_tcp_rdma_global *global = framework_private;
    struct tcp_rdma_mr          *mr;
    int                          bucket;

    if (buffer_private) {
        /* Already registered */
        return buffer_private;
    }

    mr       = evpl_zalloc(sizeof(*mr));
    mr->base = buffer;
    mr->size = size;

    pthread_mutex_lock(&global->mr_table.lock);
    mr->rkey = global->mr_table.next_rkey++;
    bucket   = mr->rkey % TCP_RDMA_MR_HASH_SIZE;
    mr->next = global->mr_table.buckets[bucket];
    global->mr_table.buckets[bucket] = mr;
    pthread_mutex_unlock(&global->mr_table.lock);

    return mr;
}

static void
tcp_rdma_unregister_memory(
    void *buffer_private,
    void *framework_private)
{
    struct tcp_rdma_mr          *mr     = buffer_private;
    struct evpl_tcp_rdma_global *global = framework_private;
    struct tcp_rdma_mr         **pp;
    int                          bucket;

    pthread_mutex_lock(&global->mr_table.lock);
    bucket = mr->rkey % TCP_RDMA_MR_HASH_SIZE;
    pp     = &global->mr_table.buckets[bucket];
    while (*pp) {
        if (*pp == mr) {
            *pp = mr->next;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&global->mr_table.lock);

    evpl_free(mr);
}

static void
tcp_rdma_get_rdma_address(
    struct evpl_bind  *bind,
    struct evpl_iovec *iov,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct tcp_rdma_mr *mr = evpl_memory_framework_private(iov,
                                                           EVPL_FRAMEWORK_TCP_RDMA);

    if (mr) {
        *r_key     = mr->rkey;
        *r_address = (uint64_t) iov->data;
    } else {
        *r_key     = 0;
        *r_address = 0;
    }
}

/*
 * Framework and Protocol definitions
 */
struct evpl_framework evpl_framework_tcp_rdma = {
    .id                = EVPL_FRAMEWORK_TCP_RDMA,
    .name              = "TCP_RDMA",
    .init              = tcp_rdma_init,
    .cleanup           = tcp_rdma_cleanup,
    .create            = tcp_rdma_create,
    .destroy           = tcp_rdma_destroy,
    .register_memory   = tcp_rdma_register_memory,
    .unregister_memory = tcp_rdma_unregister_memory,
    .get_rdma_address  = tcp_rdma_get_rdma_address,
};

struct evpl_protocol evpl_tcp_rdma_datagram = {
    .id            = EVPL_DATAGRAM_TCP_RDMA,
    .connected     = 1,
    .stream        = 0,
    .rdma          = 1,
    .name          = "DATAGRAM_TCP_RDMA",
    .framework     = &evpl_framework_tcp_rdma,
    .connect       = evpl_tcp_rdma_connect,
    .listen        = evpl_socket_tcp_listen,
    .attach        = evpl_tcp_rdma_attach,
    .pending_close = evpl_socket_pending_close,
    .close         = evpl_tcp_rdma_close,
    .flush         = evpl_tcp_rdma_flush,
};
