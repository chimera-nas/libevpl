// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>



#include <errno.h>
#include <fcntl.h>

#include "evpl/evpl_platform.h"

#include "core/endian_compat.h"
#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/rdma_mr.h"
#include "core/logging.h"
#include "core/socket/tcp.h"
#include "core/socket/tcp_rdma.h"

/*
 * TCP_RDMA Message Header - 32 bytes, network byte order
 */
#define TCP_RDMA_MAGIC       0x54524D41    /* "TRMA" */
#define TCP_RDMA_HEADER_SIZE 32

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
};
_Static_assert(sizeof(struct tcp_rdma_header) == TCP_RDMA_HEADER_SIZE, "TCP RDMA wire layout");

/*
 * Pending operation tracking using a ring buffer.
 * Since TCP guarantees in-order delivery, operations complete in FIFO order.
 * Only READ and WRITE requests are tracked (SEND is fire-and-forget).
 * We don't need to track the opcode because the first reply received
 * must correspond to the first request sent.
 */
struct tcp_rdma_pending_op {
    struct evpl_iovec *iov;
    int                niov;
    int                length;
    void               (*callback)(
        int   status,
        void *private_data);
    void              *private_data;
};

struct tcp_rdma_pending_ring {
    struct tcp_rdma_pending_op *ops;
    int                         size;
    int                         mask;
    int                         head;
    int                         tail;
};

/*
 * Per-connection state (extends evpl_socket)
 */
struct evpl_tcp_rdma_socket {
    struct evpl_bind            *wire;
    struct tcp_rdma_pending_ring pending_ring;
};

/*
 * Global and per-thread framework state
 */
struct evpl_tcp_rdma_global {
    struct evpl_rdma_mr_table mr_table;
};

struct evpl_tcp_rdma {
    struct evpl_tcp_rdma_global *global;
};

/*
 * Forward declarations
 */
void evpl_tcp_rdma_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind);

#define tcp_rdma_validate_access(global, rkey, address, length, out_ptr) \
        evpl_rdma_mr_validate(&(global)->mr_table, rkey, address, length, out_ptr)

/*
 * Pending operation ring buffer management
 */
#define TCP_RDMA_PENDING_RING_INITIAL_SIZE 16

static inline void
tcp_rdma_pending_ring_init(struct tcp_rdma_pending_ring *ring)
{
    ring->ops  = evpl_zalloc(TCP_RDMA_PENDING_RING_INITIAL_SIZE * sizeof(*ring->ops));
    ring->size = TCP_RDMA_PENDING_RING_INITIAL_SIZE;
    ring->mask = TCP_RDMA_PENDING_RING_INITIAL_SIZE - 1;
    ring->head = 0;
    ring->tail = 0;
} /* tcp_rdma_pending_ring_init */

static inline void
tcp_rdma_pending_ring_free(struct tcp_rdma_pending_ring *ring)
{
    if (ring->ops) {
        evpl_free(ring->ops);
        ring->ops = NULL;
    }
} /* tcp_rdma_pending_ring_free */

static inline int
tcp_rdma_pending_ring_is_empty(const struct tcp_rdma_pending_ring *ring)
{
    return ring->head == ring->tail;
} /* tcp_rdma_pending_ring_is_empty */

static inline int
tcp_rdma_pending_ring_is_full(const struct tcp_rdma_pending_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
} /* tcp_rdma_pending_ring_is_full */

static inline void
tcp_rdma_pending_ring_resize(struct tcp_rdma_pending_ring *ring)
{
    int                         new_size = ring->size << 1;
    struct tcp_rdma_pending_op *new_ops  = evpl_zalloc(new_size * sizeof(*new_ops));
    int                         i, j;

    /* Copy elements from tail to head in order */
    for (i = ring->tail, j = 0; i != ring->head; i = (i + 1) & ring->mask, j++) {
        new_ops[j] = ring->ops[i];
    }

    evpl_free(ring->ops);
    ring->ops  = new_ops;
    ring->size = new_size;
    ring->mask = new_size - 1;
    ring->tail = 0;
    ring->head = j;
} /* tcp_rdma_pending_ring_resize */

/*
 * Add a pending operation to the ring.
 * Returns the ring index which can be used as the message ID.
 */
static uint64_t
tcp_rdma_pending_add(
    struct evpl_tcp_rdma_socket *ts,
    struct evpl_iovec           *iov,
    int                          niov,
    int                          length,
    void                      ( *callback )(
        int   status,
        void *private_data),
    void                        *private_data)
{
    struct tcp_rdma_pending_ring *ring = &ts->pending_ring;
    struct tcp_rdma_pending_op   *op;
    uint64_t                      id;
    int                           i;

    if (tcp_rdma_pending_ring_is_full(ring)) {
        tcp_rdma_pending_ring_resize(ring);
    }

    id = ring->head;
    op = &ring->ops[ring->head];

    op->niov         = niov;
    op->length       = length;
    op->callback     = callback;
    op->private_data = private_data;

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

    ring->head = (ring->head + 1) & ring->mask;

    return id;
} /* tcp_rdma_pending_add */

/*
 * Get the pending operation at the tail (oldest operation).
 * Returns NULL if the ring is empty.
 */
static inline struct tcp_rdma_pending_op *
tcp_rdma_pending_tail(struct evpl_tcp_rdma_socket *ts)
{
    struct tcp_rdma_pending_ring *ring = &ts->pending_ring;

    if (tcp_rdma_pending_ring_is_empty(ring)) {
        return NULL;
    }
    return &ring->ops[ring->tail];
} /* tcp_rdma_pending_tail */

/*
 * Complete and remove the operation at the tail.
 * Since TCP is in-order, we always complete from the tail.
 */
static void
tcp_rdma_pending_complete(
    struct evpl                 *evpl,
    struct evpl_tcp_rdma_socket *ts)
{
    struct tcp_rdma_pending_ring *ring = &ts->pending_ring;
    struct tcp_rdma_pending_op   *op   = &ring->ops[ring->tail];

    if (op->iov) {
        /* Release the library's reference to the iovecs.
         * For RDMA READ: we cloned the app's iovec, now release our ref.
         * For RDMA WRITE: we moved the iovec, releasing is correct. */
        evpl_iovecs_release_internal(evpl, op->iov, op->niov);
        evpl_free(op->iov);
        op->iov = NULL;
    }

    ring->tail = (ring->tail + 1) & ring->mask;
} /* tcp_rdma_pending_complete */

/*
 * Clear all pending operations (on connection close).
 */
static void
tcp_rdma_pending_clear(
    struct evpl                 *evpl,
    struct evpl_tcp_rdma_socket *ts)
{
    struct tcp_rdma_pending_ring *ring = &ts->pending_ring;
    struct tcp_rdma_pending_op   *op;

    while (!tcp_rdma_pending_ring_is_empty(ring)) {
        op = &ring->ops[ring->tail];
        if (op->callback) {
            op->callback(ECONNRESET, op->private_data);
        }
        if (op->iov) {
            evpl_iovecs_release_internal(evpl, op->iov, op->niov);
            evpl_free(op->iov);
            op->iov = NULL;
        }
        ring->tail = (ring->tail + 1) & ring->mask;
    }
} /* tcp_rdma_pending_clear */

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
} /* tcp_rdma_peek_bytes */

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
} /* tcp_rdma_copy_payload_to_buffer */

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
    struct evpl_iovec       iov;
    char                   *buf;
    int                     alloc_len = TCP_RDMA_HEADER_SIZE + payload_len;

    /* Allocate buffer for header + payload */
    evpl_iovec_alloc(evpl, alloc_len, 1, 1, 0, &iov);
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

    /* Add to the framed-output ring (ready to write), never the raw send ring. */
    evpl_iovec_ring_add(&bind->iovec_send_framed, &iov);
} /* tcp_rdma_queue_message */

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
    struct evpl_iovec       iov;
    char                   *buf;
    int                     i;

    /* Allocate buffer for header only */
    evpl_iovec_alloc(evpl, TCP_RDMA_HEADER_SIZE, 1, 1, 0, &iov);
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

    /* Add header + payload to the framed-output ring (ready to write). */
    evpl_iovec_ring_add(&bind->iovec_send_framed, &iov);

    for (i = 0; i < niov; i++) {
        evpl_iovec_ring_add_clone(&bind->iovec_send_framed, &payload_iov[i]);
    }
} /* tcp_rdma_queue_message_iov */

/*
 * Message handlers
 */
static void
tcp_rdma_handle_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    uint32_t          length)
{
    struct evpl_notify notify;
    struct evpl_iovec *iovec;
    int                niov;

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
} /* tcp_rdma_handle_send */

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
    uint32_t                     read_len_payload = 0;
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
} /* tcp_rdma_handle_read_request */

static void
tcp_rdma_handle_read_reply(
    struct evpl                 *evpl,
    struct evpl_bind            *bind,
    struct evpl_tcp_rdma_socket *ts,
    struct tcp_rdma_header      *hdr)
{
    struct tcp_rdma_pending_op *op;
    int                         i, remaining, chunk;

    /* TCP guarantees in-order delivery, so the reply is for the tail op */
    op = tcp_rdma_pending_tail(ts);
    if (!op) {
        /* Unexpected reply - discard */
        evpl_iovec_ring_consume(evpl, &bind->iovec_recv,
                                TCP_RDMA_HEADER_SIZE + hdr->length);
        return;
    }

    /* Skip header */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, TCP_RDMA_HEADER_SIZE);

    if (hdr->length != (uint32_t) op->length) {
        evpl_close(evpl, bind);
        return;
    }
    /* Keep a single source offset across all destination buffers. */
    remaining = hdr->length;
    for (i = 0; i < op->niov && remaining > 0; i++) {
        chunk = op->iov[i].length;
        if (chunk > remaining) {
            chunk = remaining;
        }
        tcp_rdma_peek_bytes(&bind->iovec_recv, op->iov[i].data,
                            hdr->length - remaining, chunk);
        remaining -= chunk;
    }

    /* Consume payload from ring */
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, hdr->length);

    /* Invoke callback */
    if (op->callback) {
        op->callback(0, op->private_data);
    }

    tcp_rdma_pending_complete(evpl, ts);
} /* tcp_rdma_handle_read_reply */

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
        int   remaining = req_hdr->length;
        int   copied    = 0;
        char *dst       = ptr;

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
                evpl_iovec_release_internal(evpl, src_iov);
                bind->iovec_recv.tail = (bind->iovec_recv.tail + 1) &
                    bind->iovec_recv.mask;
            } else {
                src_iov->data    = (char *) src_iov->data + chunk;
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
} /* tcp_rdma_handle_write_request */

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

    /* TCP guarantees in-order delivery, so the reply is for the tail op */
    op = tcp_rdma_pending_tail(ts);
    if (!op) {
        return;
    }

    /* Invoke callback */
    if (op->callback) {
        op->callback(0, op->private_data);
    }

    tcp_rdma_pending_complete(evpl, ts);
} /* tcp_rdma_handle_write_reply */

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

    /* TCP guarantees in-order delivery, so the error is for the tail op */
    op = tcp_rdma_pending_tail(ts);
    if (!op) {
        return;
    }

    /* Invoke callback with error */
    if (op->callback) {
        op->callback(hdr->length, op->private_data); /* length contains error code */
    }

    tcp_rdma_pending_complete(evpl, ts);
} /* tcp_rdma_handle_error */

/* The framing and RDMA operation state are independent of the byte transport.
 * A child TCP bind owns native I/O and retains this bind until it disconnects. */
static void
evpl_tcp_rdma_wire_notify(
    struct evpl        *evpl,
    struct evpl_bind   *wire,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct evpl_bind            *bind = private_data;
    struct evpl_tcp_rdma_socket *ts   = evpl_bind_private(bind);
    struct evpl_iovec           *iov;
    struct tcp_rdma_header       hdr;
    uint64_t                     msg_len;

    if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        ts->wire = NULL;
        evpl_bind_operation_end(bind);
        evpl_close(evpl, bind);
        return;
    }
    if (bind->flags & (EVPL_BIND_PENDING_CLOSED | EVPL_BIND_CLOSE_DEFERRED)) {
        return;
    }
    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            if (bind->local) {
                evpl_address_release(bind->local);
            }
            bind->local = wire->local;
            if (bind->local) {
                evpl_address_incref(bind->local);
            }
            bind->notify_callback(evpl, bind, notify, bind->private_data);
            return;
        case EVPL_NOTIFY_SENT:
            if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
                bind->notify_callback(evpl, bind, notify, bind->private_data);
            }
            return;
        case EVPL_NOTIFY_RECV_DATA:
            while ((iov = evpl_iovec_ring_tail(&wire->iovec_recv)) != NULL) {
                evpl_iovec_ring_add(&bind->iovec_recv, iov);
                evpl_iovec_ring_remove(&wire->iovec_recv);
            }
            break;
        default:
            return;
    } /* switch */
    /* Process complete messages */
    while (!(bind->flags & (EVPL_BIND_PENDING_CLOSED | EVPL_BIND_CLOSE_DEFERRED)) && evpl_iovec_ring_bytes(&bind->
                                                                                                           iovec_recv)
           >= TCP_RDMA_HEADER_SIZE) {
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
            evpl_core_error("Invalid TCP_RDMA magic: 0x%08x", hdr.magic);
            evpl_close(evpl, bind);
            return;
        }

        /* Check if we have complete message */
        if (hdr.length > INT_MAX - TCP_RDMA_HEADER_SIZE ||
            (hdr.opcode == TCP_RDMA_OP_READ_REQUEST && hdr.length != 4) ||
            (hdr.opcode == TCP_RDMA_OP_WRITE_REPLY && hdr.length != 0)) {
            evpl_close(evpl, bind);
            return;
        }
        msg_len = TCP_RDMA_HEADER_SIZE + (hdr.opcode == TCP_RDMA_OP_ERROR ? 0 : hdr.length);
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
                evpl_core_error("Unknown TCP_RDMA opcode: %u", hdr.opcode);
                evpl_close(evpl, bind);
                return;
        } /* switch */
    }

} /* evpl_tcp_rdma_wire_notify */

static struct evpl_bind *
evpl_tcp_rdma_wire(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts = evpl_bind_private(bind);

    tcp_rdma_pending_ring_init(&ts->pending_ring);
    if (bind->local) {
        evpl_address_incref(bind->local);
    }
    if (bind->remote) {
        evpl_address_incref(bind->remote);
    }
    ts->wire                  = evpl_bind_prepare(evpl, &evpl_socket_tcp, bind->local, bind->remote);
    ts->wire->notify_callback = evpl_tcp_rdma_wire_notify;
    ts->wire->private_data    = bind;
    ts->wire->flags          |= EVPL_BIND_SENT_NOTIFY;
    evpl_bind_operation_begin(bind);
    return ts->wire;
} /* evpl_tcp_rdma_wire */

static void
evpl_tcp_rdma_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_socket_tcp.connect(evpl, evpl_tcp_rdma_wire(evpl, bind));
} /* evpl_tcp_rdma_connect */

static void
evpl_tcp_rdma_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    evpl_socket_tcp.attach(evpl, evpl_tcp_rdma_wire(evpl, bind), accepted);
} /* evpl_tcp_rdma_attach */

static void
evpl_tcp_rdma_discard(
    struct evpl *evpl,
    void        *accepted)
{
    evpl_socket_tcp.discard_accepted(evpl, accepted);
} /* evpl_tcp_rdma_discard */

static void
evpl_tcp_rdma_accept(
    struct evpl         *evpl,
    struct evpl_bind    *wire,
    struct evpl_address *remote,
    void                *accepted,
    void                *private_data)
{
    struct evpl_bind *bind = private_data;

    (void) wire;
    bind->accept_callback(evpl, bind, remote, accepted, bind->private_data);
} /* evpl_tcp_rdma_accept */

static int
evpl_tcp_rdma_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts   = evpl_bind_private(bind);
    struct evpl_bind            *wire = evpl_tcp_rdma_wire(evpl, bind);

    wire->accept_callback = evpl_tcp_rdma_accept;
    if (evpl_socket_tcp.listen(evpl, wire)) {
        evpl_bind_abort(evpl, wire);
        ts->wire = NULL;
        evpl_bind_operation_end(bind);
        tcp_rdma_pending_ring_free(&ts->pending_ring);
        return -1;
    }
    return 0;
} /* evpl_tcp_rdma_listen */

static void
evpl_tcp_rdma_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tcp_rdma_socket *ts = evpl_bind_private(bind);

    if (ts->wire) {
        evpl_close(evpl, ts->wire);
    }
} /* evpl_tcp_rdma_pending_close */

static void
evpl_tcp_rdma_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_tcp_rdma_finish */

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
    uint64_t                     id;
    int                          i;


    /* Process RDMA read requests from dgram_read ring */
    while ((dgram = evpl_dgram_ring_tail(&bind->dgram_read)) != NULL) {
        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_READ) {
            /* Extract iovecs from iovec_rdma_read ring */
            iov = alloca(sizeof(struct evpl_iovec) * dgram->niov);
            for (i = 0; i < dgram->niov; i++) {
                struct evpl_iovec *src = evpl_iovec_ring_tail(&bind->iovec_rdma_read);

                evpl_core_abort_if(!src, "src is NULL");

                evpl_iovec_move(&iov[i], src);
                evpl_iovec_ring_remove(&bind->iovec_rdma_read);
            }

            /* Create pending operation - returns ring index as message ID */
            id = tcp_rdma_pending_add(ts, iov, dgram->niov, dgram->length,
                                      dgram->callback, dgram->private_data);

            /* Send read request - payload contains the read length */
            uint32_t read_len_payload = htonl(dgram->length);

            hdr.magic          = TCP_RDMA_MAGIC;
            hdr.opcode         = TCP_RDMA_OP_READ_REQUEST;
            hdr.length         = sizeof(read_len_payload); /* 4-byte payload */
            hdr.remote_key     = dgram->remote_key;
            hdr.remote_address = dgram->remote_address;
            hdr.id             = id;
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

            evpl_core_abort_if(!src, "src is NULL");

            evpl_iovec_move(&iov[i], src);
            evpl_iovec_ring_remove(&bind->iovec_send);
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
        } else if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
            /* Create pending operation - returns ring index as message ID */
            id = tcp_rdma_pending_add(ts, NULL, 0, dgram->length,
                                      dgram->callback, dgram->private_data);

            /* Send write request with data */
            hdr.magic          = TCP_RDMA_MAGIC;
            hdr.opcode         = TCP_RDMA_OP_WRITE_REQUEST;
            hdr.length         = dgram->length;
            hdr.remote_key     = dgram->remote_key;
            hdr.remote_address = dgram->remote_address;
            hdr.id             = id;
            tcp_rdma_queue_message_iov(evpl, bind, &hdr, iov, dgram->niov);
        }

        /* Release iovecs */
        for (i = 0; i < dgram->niov; i++) {
            evpl_iovec_release_internal(evpl, &iov[i]);
        }

        evpl_dgram_ring_remove(&bind->dgram_send);
    }

    /* Transfer framed buffers to the child. It keeps them until the native
     * send completes, including an overlapped send cancelled during close. */
    if (ts->wire && !(bind->flags & (EVPL_BIND_PENDING_CLOSED | EVPL_BIND_CLOSE_DEFERRED))) {
        while ((iov = evpl_iovec_ring_tail(&bind->iovec_send_framed)) != NULL) {
            evpl_sendv(evpl, ts->wire, iov, 1, iov->length, EVPL_SEND_FLAG_TAKE_REF);
            evpl_iovec_ring_remove(&bind->iovec_send_framed);
        }
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_finish(evpl, ts->wire);
        }
    }
} /* evpl_tcp_rdma_flush */

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
    tcp_rdma_pending_clear(evpl, ts);

    /* Free the pending ring */
    tcp_rdma_pending_ring_free(&ts->pending_ring);

    evpl_core_assert(!ts->wire && !bind->outstanding);
} /* evpl_tcp_rdma_close */

/*
 * Framework functions
 */
static void *
tcp_rdma_init(void)
{
    struct evpl_tcp_rdma_global *global = evpl_zalloc(sizeof(*global));

    evpl_rdma_mr_table_init(&global->mr_table);

    return global;
} /* tcp_rdma_init */

static void
tcp_rdma_cleanup(void *private_data)
{
    struct evpl_tcp_rdma_global *global = private_data;

    evpl_rdma_mr_table_cleanup(&global->mr_table);

    evpl_free(global);
} /* tcp_rdma_cleanup */

static void *
tcp_rdma_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_tcp_rdma_global *global   = private_data;
    struct evpl_tcp_rdma        *tcp_rdma = evpl_zalloc(sizeof(*tcp_rdma));

    tcp_rdma->global = global;

    return tcp_rdma;
} /* tcp_rdma_create */

static void
tcp_rdma_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_free(private_data);
} /* tcp_rdma_destroy */

static void *
tcp_rdma_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *framework_private)
{
    struct evpl_tcp_rdma_global *global = framework_private;

    return evpl_rdma_mr_register(&global->mr_table, buffer, size,
                                 buffer_private);
} /* tcp_rdma_register_memory */

static void
tcp_rdma_unregister_memory(
    void *buffer_private,
    void *framework_private)
{
    struct evpl_tcp_rdma_global *global = framework_private;

    evpl_rdma_mr_unregister(&global->mr_table, buffer_private);
} /* tcp_rdma_unregister_memory */

static void
tcp_rdma_get_rdma_address(
    struct evpl_bind  *bind,
    struct evpl_iovec *iov,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct evpl_rdma_mr *mr = evpl_memory_framework_private(iov,
                                                            EVPL_FRAMEWORK_TCP_RDMA);

    if (mr) {
        *r_key     = mr->rkey;
        *r_address = (uint64_t) iov->data;
    } else {
        *r_key     = 0;
        *r_address = 0;
    }
} /* tcp_rdma_get_rdma_address */

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

struct evpl_protocol  evpl_tcp_rdma_datagram = {
    .id               = EVPL_DATAGRAM_TCP_RDMA,
    .connected        = 1,
    .stream           = 0,
    .rdma             = 1,
    .name             = "DATAGRAM_TCP_RDMA",
    .framework        = &evpl_framework_tcp_rdma,
    .connect          = evpl_tcp_rdma_connect,
    .listen           = evpl_tcp_rdma_listen,
    .discard_accepted = evpl_tcp_rdma_discard,
    .attach           = evpl_tcp_rdma_attach,
    .pending_close    = evpl_tcp_rdma_pending_close,
    .close            = evpl_tcp_rdma_close,
    .flush            = evpl_tcp_rdma_flush,
    .finish           = evpl_tcp_rdma_finish,
};
