// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>   /* alloca */
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <utlist.h>

#include "core/macros.h"
#include "core/logging.h"
#include "core/allocator.h"
#include "core/address.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/rdma_mr.h"
#include "core/evpl.h"
#include "core/inproc/inproc.h"

/*
 * In-process transport: two evpl threads in the same address space.
 *
 * There is no kernel object in the data path.  A connection is a pair of
 * queues, one per direction, each a (iovec_ring, dgram_ring) pair -- the same
 * two structures a bind already stages its own sends in -- behind a mutex, with
 * an eventfd doorbell to wake the consumer when it is asleep in the event loop.
 *
 * The shape deliberately mirrors the socket backends rather than inventing a
 * new one, so that the listener machinery, the accept handoff and the close
 * sequence are all reused verbatim:
 *
 *      TCP                                inproc
 *      bind() + listen() on a port        insert name into the registry
 *      the kernel's accept queue          listener->pending
 *      listening socket becomes readable  ring the listener's doorbell
 *      accept()                           pop a pending connection
 *      listen_bind->accept_callback()     identical
 *
 * Two things are worth knowing before changing anything here:
 *
 *  - A payload cannot simply be handed to the peer thread.  A default iovec is
 *    thread-local: its refcount is non-atomic and its buffer is freed to the
 *    releasing thread's list.  See evpl_inproc_share_message().
 *
 *  - RDMA read and write never touch the queues at all.  They are one-sided
 *    operations, and in one address space that means the initiator does the
 *    memcpy itself.  See evpl_inproc_rdma_xfer().
 */

#define evpl_inproc_debug(...) evpl_debug("inproc", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_inproc_info(...)  evpl_info("inproc", __FILE__, __LINE__, \
                                         __VA_ARGS__)
#define evpl_inproc_error(...) evpl_error("inproc", __FILE__, __LINE__, \
                                          __VA_ARGS__)

#define evpl_inproc_abort_if(cond, ...) \
        evpl_abort_if(cond, "inproc", __FILE__, __LINE__, __VA_ARGS__)

/*
 * Queue message types.  These live in evpl_dgram::dgram_type, which the core
 * only interprets for the rings owned by a bind; a channel queue is ours, so
 * the numbering is independent of EVPL_DGRAM_TYPE_*.
 */
#define EVPL_INPROC_MSG_DATA 0
#define EVPL_INPROC_MSG_FIN  1

#define evpl_inproc_peer(end)  ((end) ^ 1)

/*
 * One direction of a channel.  The producer is the peer thread and the
 * consumer is the thread that owns the bind this queue feeds.
 */
struct evpl_inproc_queue {
    pthread_mutex_t        lock;

    /* Positionally paired, exactly as a bind's iovec_send/dgram_send are: the
     * Nth dgram owns the next dgram->niov iovecs. */
    struct evpl_iovec_ring iovec;
    struct evpl_dgram_ring dgram;

    /* The consumer's doorbell, or NULL.  A pointer rather than the doorbell
     * itself, so that it lives in the consuming bind's private area alongside
     * every other backend's event rather than in this shared, heap-freed
     * channel -- the doorbell is owned by one thread's event loop, and putting
     * it in memory the peer also reaches only invites confusion about who may
     * retire it.
     *
     * doorbell_valid is what makes the producer's ring safe: both sides touch
     * it under this lock, and the consumer clears it before calling
     * evpl_remove_doorbell(), so a producer can never write to an eventfd that
     * has already been closed.  It also starts clear on the accepting end,
     * which is what lets a send that arrives before the accept has run simply
     * skip the wakeup -- evpl_inproc_attach() drains once unconditionally to
     * pick it up. */
    struct evpl_doorbell  *doorbell;
    int                    doorbell_valid;

    /* Rung and not yet drained.  Suppresses the wakeup on every message after
     * the first, so a busy producer pays one eventfd write per batch. */
    int                    notified;
};

struct evpl_inproc_channel {
    /* 2 while both ends live.  The last one out releases anything still
     * queued and frees the channel. */
    atomic_int               refcnt;

    /* q[i] is the queue the end numbered i CONSUMES, and therefore the one
     * end i^1 produces into. */
    struct evpl_inproc_queue q[2];
};

/* A connection that has been created but not yet accepted -- the analogue of a
 * completed handshake sitting in the kernel's accept queue. */
struct evpl_inproc_pending {
    struct evpl_inproc_channel *chan;
    struct evpl_address        *local;   /* the acceptor's local address  */
    struct evpl_address        *remote;  /* the connecting end's address  */
    struct evpl_inproc_pending *prev;
    struct evpl_inproc_pending *next;
};

/* A registered name.  Reachable from the registry list and from the listen
 * bind's private state. */
struct evpl_inproc_listener {
    char                         name[EVPL_INPROC_NAME_MAX];
    struct evpl_bind            *bind;

    /* Points into the listen bind's private area, for the same reason a
     * queue's doorbell pointer does.  Rung by a connecting thread under the
     * registry lock. */
    struct evpl_doorbell        *doorbell;

    struct evpl_inproc_pending  *pending;
    struct evpl_inproc_listener *prev;
    struct evpl_inproc_listener *next;
};

/* Protocol-private state, in the bind's private area.  evpl_bind_prepare()
 * memsets that area for every bind, including recycled ones, so every field
 * here is reliably zero for a fresh bind -- which is why `listener` can double
 * as the "this is a listen bind" flag.  bind->accept_callback could not: it is
 * not reset on recycle. */
struct evpl_inproc_bind {
    /* Must be first: the doorbell callbacks recover the bind from this with
     * evpl_private2bind(), which assumes the private area starts here. */
    struct evpl_doorbell         doorbell;

    struct evpl_inproc_channel  *chan;
    struct evpl_inproc_listener *listener;
    int                          end;
    int                          connected;   /* CONNECTED emitted  */
    int                          fin;         /* peer's FIN drained */
};

/* Process-global state, created by the framework's init(). */
struct evpl_inproc_global {
    struct evpl_rdma_mr_table    mr_table;

    /* Guards the listener list and every listener's pending list.  Never held
     * across an accept callback -- see evpl_inproc_accept(). */
    pthread_mutex_t              lock;
    struct evpl_inproc_listener *listeners;
    uint32_t                     next_id;
};

/* Per-thread state; carries the global pointer the way tcp_rdma's does. */
struct evpl_inproc_thread {
    struct evpl_inproc_global *global;
};

static inline struct evpl_inproc_global *
evpl_inproc_global(struct evpl *evpl)
{
    struct evpl_inproc_thread *thread = evpl_framework_private(
        evpl, EVPL_FRAMEWORK_INPROC);

    return thread->global;
} /* evpl_inproc_global */

static void evpl_inproc_drain(
    struct evpl      *evpl,
    struct evpl_bind *bind);

/*
 * Addresses
 */

static struct evpl_address *
evpl_inproc_address_alloc(
    const char *name,
    uint32_t    id)
{
    struct evpl_sockaddr_inproc sinp;
    size_t                      len;

    memset(&sinp, 0, sizeof(sinp));

    sinp.family = EVPL_AF_INPROC;
    sinp.id     = id;

    /* Bounded copy rather than strncpy: the terminator comes from the memset,
    * and strncpy(dst, src, sizeof - 1) trips -Wstringop-truncation at -O3. */
    len = strnlen(name, sizeof(sinp.name) - 1);
    memcpy(sinp.name, name, len);

    return evpl_address_init((struct sockaddr *) &sinp, sizeof(sinp));
} /* evpl_inproc_address_alloc */

static inline const char *
evpl_inproc_address_name(struct evpl_address *address)
{
    return ((struct evpl_sockaddr_inproc *) address->addr)->name;
} /* evpl_inproc_address_name */

/*
 * Channel
 */

static struct evpl_inproc_channel *
evpl_inproc_channel_alloc(void)
{
    struct evpl_inproc_channel *chan = evpl_zalloc(sizeof(*chan));
    int                         i;

    atomic_init(&chan->refcnt, 2);

    for (i = 0; i < 2; ++i) {
        pthread_mutex_init(&chan->q[i].lock, NULL);

        evpl_iovec_ring_alloc(&chan->q[i].iovec,
                              evpl_shared->config->iovec_ring_size,
                              evpl_shared->config->page_size);

        evpl_dgram_ring_alloc(&chan->q[i].dgram,
                              evpl_shared->config->dgram_ring_size,
                              evpl_shared->config->page_size);
    }

    return chan;
} /* evpl_inproc_channel_alloc */

static void
evpl_inproc_channel_release(
    struct evpl                *evpl,
    struct evpl_inproc_channel *chan)
{
    int i;

    if (atomic_fetch_sub(&chan->refcnt, 1) > 1) {
        return;
    }

    for (i = 0; i < 2; ++i) {
        /* Anything still here was sent to an end that went away without
         * draining it.  evpl may legitimately be NULL: the last reference can
         * be dropped by a thread that has no business releasing into its own
         * caches, and evpl_buffer_free() handles that by going straight to the
         * global allocator. */
        evpl_iovec_ring_clear(evpl, &chan->q[i].iovec);
        evpl_iovec_ring_free(&chan->q[i].iovec);
        evpl_dgram_ring_free(&chan->q[i].dgram);
        pthread_mutex_destroy(&chan->q[i].lock);
    }

    evpl_free(chan);
} /* evpl_inproc_channel_release */

/* Register the consumer end's doorbell.  Must run on the consumer's thread. */
static void
evpl_inproc_queue_arm(
    struct evpl              *evpl,
    struct evpl_inproc_queue *q,
    struct evpl_inproc_bind  *ib,
    evpl_doorbell_callback_t  callback)
{
    evpl_add_doorbell(evpl, &ib->doorbell, callback);

    pthread_mutex_lock(&q->lock);
    q->doorbell       = &ib->doorbell;
    q->doorbell_valid = 1;
    pthread_mutex_unlock(&q->lock);
} /* evpl_inproc_queue_arm */

/* Retire the consumer end's doorbell.  Must run on the consumer's thread, and
 * must happen before that thread's evpl is destroyed. */
static void
evpl_inproc_queue_disarm(
    struct evpl              *evpl,
    struct evpl_inproc_queue *q,
    struct evpl_inproc_bind  *ib)
{
    int armed;

    pthread_mutex_lock(&q->lock);
    armed             = q->doorbell_valid;
    q->doorbell_valid = 0;
    q->doorbell       = NULL;
    pthread_mutex_unlock(&q->lock);

    /* The producer observes doorbell_valid under the same lock, so once the
     * store above is visible no further ring can be issued and the eventfd is
     * ours to close. */
    if (armed) {
        evpl_remove_doorbell(evpl, &ib->doorbell);
    }
} /* evpl_inproc_queue_disarm */

/* Wake the consumer if it is not already awake.  Called with q->lock held,
 * which is what guarantees the eventfd is still open: the consumer clears
 * doorbell_valid under this same lock before closing it. */
static inline void
evpl_inproc_queue_notify(struct evpl_inproc_queue *q)
{
    if (!q->notified && q->doorbell_valid) {
        q->notified = 1;
        evpl_ring_doorbell(q->doorbell);
    }
} /* evpl_inproc_queue_notify */

/*
 * Send path
 */

/*
 * Give one staged message's payload a reference the peer thread may safely
 * release, rewriting the send ring in place.  Operates on the niov entries at
 * the ring's tail, which is where the message about to be enqueued lives.
 *
 * This is a correctness requirement, not an optimization.  A default iovec is
 * thread-local by omission: its refcount is a plain non-atomic decrement, and
 * evpl_buffer_free_local() returns the buffer to the *releasing* thread's free
 * list.  Handing one to a peer that later releases it races on both counts,
 * and an EVPL_IOVEC_TRACE build aborts on exactly that.  A SHARED reference
 * has an atomic count and releases through evpl_buffer_free(), which is built
 * for buffers migrating between threads' caches.
 *
 * So a SHARED payload crosses by reference and costs nothing, and anything else
 * is copied into a shared buffer allocated here, on the sending thread.  An
 * application that cares can therefore opt into a genuinely zero-copy send just
 * by allocating with EVPL_IOVEC_FLAG_SHARED.
 *
 * GLOBAL buffers are copied even though they are also SHARED: their refcount is
 * inert by design, so nothing would stop the owner freeing one while the peer
 * still had it queued.
 *
 * Deliberately done per message from inside the send loop rather than as a
 * single pass over the whole ring beforehand.  A completion callback fired
 * mid-loop -- an RDMA write's, say -- is entitled to call evpl_send(), and what
 * it appends lands behind any pre-pass and would otherwise cross to the peer
 * unconverted.
 */
static void
evpl_inproc_share_message(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               niov)
{
    struct evpl_iovec *iovec, tmp;
    unsigned int       flags, len;
    int                pos = bind->iovec_send.tail;
    int                i, rc;

    for (i = 0; i < niov; ++i) {

        iovec = &bind->iovec_send.iovec[pos];
        pos   = (pos + 1) & bind->iovec_send.mask;

        flags = evpl_iovec_get_ref(iovec)->flags;

        if ((flags & EVPL_IOVEC_FLAG_SHARED) &&
            !(flags & EVPL_IOVEC_FLAG_GLOBAL)) {
            continue;
        }

        len = iovec->length;

        /* A zero-length entry is out of contract for a send ring
         * (evpl_iovec_ring_iov asserts against it) but it still carries a
         * reference, so it has to be re-homed rather than skipped. */
        rc = evpl_iovec_alloc(evpl, len ? len : 1, 0, 1,
                              EVPL_IOVEC_FLAG_SHARED, &tmp);

        evpl_inproc_abort_if(rc != 1,
                             "failed to allocate %u byte shared buffer for send",
                             len);

        if (len) {
            memcpy(tmp.data, iovec->data, len);
        }

        tmp.length = len;

        evpl_iovec_release_internal(evpl, iovec);
        evpl_iovec_move(iovec, &tmp);
    }
} /* evpl_inproc_share_message */

/*
 * One-sided RDMA, performed entirely on the initiator.
 *
 * A real RDMA read or write does not involve the target's CPU, and inside a
 * single address space that is simply a memcpy done here -- so this is closer
 * to the semantics of the hardware than TCP_RDMA's request/reply emulation is,
 * as well as very much cheaper.  The peer thread is never woken and nothing is
 * queued.
 *
 * The peer's (rkey, address) pair reached us through a message, which passed
 * through a queue mutex and an eventfd, so its buffer's contents are ordered
 * before anything we read here.
 *
 * Pops dgram->niov iovecs from `ring`, which is the send ring for a write and
 * the rdma-read ring for a read.
 */
static void
evpl_inproc_rdma_xfer(
    struct evpl            *evpl,
    struct evpl_bind       *bind,
    struct evpl_dgram      *dgram,
    struct evpl_iovec_ring *ring,
    int                     is_write)
{
    struct evpl_inproc_global *global = evpl_inproc_global(evpl);
    struct evpl_iovec         *iovec;
    char                      *remote = NULL;
    int                        i, rc;

    rc = evpl_rdma_mr_validate(&global->mr_table, dgram->remote_key,
                               dgram->remote_address, dgram->length,
                               (void **) &remote);

    if (unlikely(rc)) {
        evpl_inproc_error(
            "rdma %s: rkey %u address 0x%lx length %u does not name registered memory",
            is_write ? "write" : "read", dgram->remote_key,
            dgram->remote_address, dgram->length);
    }

    for (i = 0; i < dgram->niov; ++i) {
        iovec = evpl_iovec_ring_tail(ring);

        evpl_inproc_abort_if(!iovec, "rdma transfer short of its iovecs");

        if (likely(!rc)) {
            if (is_write) {
                memcpy(remote, iovec->data, iovec->length);
            } else {
                memcpy(iovec->data, remote, iovec->length);
            }
            remote += iovec->length;
        }

        /* The library's own reference: taken by evpl_rdma_read/_write when the
         * operation was staged, and released here now it has completed.  Both
         * the take and this release happen on this thread. */
        evpl_iovec_release_internal(evpl, iovec);
        evpl_iovec_ring_remove(ring);
    }

    if (dgram->callback) {
        dgram->callback(rc ? EINVAL : 0, dgram->private_data);
    }
} /* evpl_inproc_rdma_xfer */

static void
evpl_inproc_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_inproc_bind  *ib = evpl_bind_private(bind);
    struct evpl_inproc_queue *q;
    struct evpl_dgram        *dgram, *out, cur;
    struct evpl_iovec        *iovec;
    struct evpl_notify        notify;
    unsigned long             bytes = 0, msgs = 0;
    int                       i;

    /* A connect that found no listener never got a channel; it has already
     * been closed and there is nothing to send it. */
    if (unlikely(!ib->chan)) {
        return;
    }

    /* RDMA reads first, and entirely locally: they are staged in their own
     * pair of rings and never reach the peer. */
    while ((dgram = evpl_dgram_ring_tail(&bind->dgram_read)) != NULL) {
        cur = *dgram;

        if (cur.dgram_type == EVPL_DGRAM_TYPE_RDMA_READ) {
            evpl_inproc_rdma_xfer(evpl, bind, &cur, &bind->iovec_rdma_read, 0);
        }

        evpl_dgram_ring_remove(&bind->dgram_read);
    }

    q = &ib->chan->q[evpl_inproc_peer(ib->end)];

    while ((dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {

        /* Taken by value: a completion callback below may send, and a send
         * that grows the dgram ring reallocates it out from under this
         * pointer. */
        cur = *dgram;

        if (cur.dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
            /* Stays on this thread.  Its completion callback runs with no
             * queue lock held, so it is free to send or close. */
            evpl_inproc_rdma_xfer(evpl, bind, &cur, &bind->iovec_send, 1);
            evpl_dgram_ring_remove(&bind->dgram_send);
            continue;
        }

        /* Outside the lock: this is the one part of the batch that can
         * allocate, and holding the peer's queue across it would stall its
         * drain for the length of a copy. */
        evpl_inproc_share_message(evpl, bind, cur.niov);

        pthread_mutex_lock(&q->lock);

        for (i = 0; i < cur.niov; ++i) {
            iovec = evpl_iovec_ring_tail(&bind->iovec_send);

            evpl_inproc_abort_if(!iovec, "send short of its iovecs");

            evpl_iovec_ring_add(&q->iovec, iovec);
            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        out             = evpl_dgram_ring_add(&q->dgram);
        out->dgram_type = EVPL_INPROC_MSG_DATA;
        out->niov       = cur.niov;
        out->length     = cur.length;

        evpl_inproc_queue_notify(q);

        pthread_mutex_unlock(&q->lock);

        bytes += cur.length;
        msgs++;

        evpl_dgram_ring_remove(&bind->dgram_send);
    }

    /* Everything handed to the queue is, from this end's point of view, sent. */
    if (msgs && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = bytes;
        notify.sent.msgs     = msgs;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    /* evpl_finish() only closes if the send ring was already empty when it was
     * called, which it is not when an application sends and then finishes in
     * one callback.  The socket backends re-check this once the write drains;
     * there is no write event here, so the flush is where it has to happen.
     * Without it evpl_finish() never completes. */
    if ((bind->flags & EVPL_BIND_FINISH) &&
        evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_close(evpl, bind);
    }
} /* evpl_inproc_flush */

/*
 * Receive path
 */

static void
evpl_inproc_deliver_stream(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_notify notify;
    struct evpl_iovec *iovec;
    int                length, niov;

    /* Byte-for-byte the tail of evpl_socket_tcp_read(): once bytes are in
     * iovec_recv, framing is the core's business and not the transport's. */
    if (bind->segment_callback) {

        iovec = alloca(sizeof(struct evpl_iovec) *
                       evpl_shared->config->max_num_iovec);

        while (1) {

            length = bind->segment_callback(evpl, bind, bind->private_data);

            /* Must precede the ring-bytes comparison: that comparison promotes
             * length to an unsigned type, so a negative value would compare as
             * huge and break out of the loop before being seen. */
            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                return;
            }

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < (uint64_t) length) {
                break;
            }

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv, length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_inproc_deliver_stream */

static void
evpl_inproc_deliver_msg(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    unsigned int      length)
{
    struct evpl_notify notify;
    struct evpl_iovec *iovec;
    int                niov;

    iovec = alloca(sizeof(struct evpl_iovec) *
                   evpl_shared->config->max_num_iovec);

    niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv, length);

    notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
    notify.recv_msg.iovec  = iovec;
    notify.recv_msg.niov   = niov;
    notify.recv_msg.length = length;
    notify.recv_msg.addr   = bind->remote;

    bind->notify_callback(evpl, bind, &notify, bind->private_data);
} /* evpl_inproc_deliver_msg */

/*
 * Move everything the peer has queued into this bind's receive ring and hand it
 * to the application.
 *
 * The queue lock is taken per message and never held across a callback: an
 * application is entitled to call evpl_close() from its receive callback, and
 * that path takes this same lock.
 */
static void
evpl_inproc_drain(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_inproc_bind  *ib = evpl_bind_private(bind);
    struct evpl_inproc_queue *q;
    struct evpl_dgram        *dgram;
    struct evpl_iovec        *iovec;
    struct evpl_notify        notify;
    unsigned int              type, length;
    int                       i, niov, got = 0;

    if (unlikely(!ib->chan)) {
        return;
    }

    q = &ib->chan->q[ib->end];

    /* A connecting end rings its own doorbell once so that this runs, which is
     * how CONNECTED reaches the application without being dispatched from
     * inside evpl_connect() before it has even returned the bind. */
    if (!ib->connected) {
        ib->connected = 1;

        notify.notify_type   = EVPL_NOTIFY_CONNECTED;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    while (!ib->fin) {

        pthread_mutex_lock(&q->lock);

        q->notified = 0;

        dgram = evpl_dgram_ring_tail(&q->dgram);

        if (!dgram) {
            pthread_mutex_unlock(&q->lock);
            break;
        }

        type   = dgram->dgram_type;
        length = dgram->length;
        niov   = dgram->niov;

        for (i = 0; i < niov; ++i) {
            iovec = evpl_iovec_ring_tail(&q->iovec);

            evpl_inproc_abort_if(!iovec, "queued message short of its iovecs");

            evpl_iovec_ring_add(&bind->iovec_recv, iovec);
            evpl_iovec_ring_remove(&q->iovec);
        }

        evpl_dgram_ring_remove(&q->dgram);

        pthread_mutex_unlock(&q->lock);

        if (type == EVPL_INPROC_MSG_FIN) {
            /* Carried in band rather than as a flag, so it is seen strictly
             * after everything the peer sent before closing.  A side-channel
             * flag consulted first would drop the last message -- which is
             * precisely what an application that sends and then calls
             * evpl_finish() in one callback produces. */
            ib->fin = 1;
            break;
        }

        got = 1;

        if (!bind->protocol->stream) {
            evpl_inproc_deliver_msg(evpl, bind, length);

            /* The callback is allowed to close; stop before touching a channel
             * that the close path has already let go of. */
            if (unlikely(!ib->chan || evpl_bind_is_closing(bind))) {
                return;
            }
        }
    }

    if (got && bind->protocol->stream) {
        evpl_inproc_deliver_stream(evpl, bind);

        if (unlikely(!ib->chan || evpl_bind_is_closing(bind))) {
            return;
        }
    }

    if (ib->fin) {
        /* The peer is done sending; report it the way a read-side FIN is
         * reported on a stream socket. */
        evpl_close(evpl, bind);
    }
} /* evpl_inproc_drain */

static void
evpl_inproc_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_inproc_bind *ib = container_of(doorbell,
                                               struct evpl_inproc_bind,
                                               doorbell);

    evpl_inproc_drain(evpl, evpl_private2bind(ib));
} /* evpl_inproc_doorbell */

/*
 * Listen and accept
 */

/* Drop a pending connection that will never be accepted. */
static void
evpl_inproc_pending_discard(
    struct evpl                *evpl,
    struct evpl_inproc_pending *pending)
{
    /* The connecting end still holds its own reference and will find out when
     * it sees no reply; releasing ours leaves it owning the channel alone. */
    evpl_inproc_channel_release(evpl, pending->chan);

    evpl_address_release(pending->local);
    evpl_address_release(pending->remote);

    evpl_free(pending);
} /* evpl_inproc_pending_discard */

static void
evpl_inproc_accept(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_inproc_bind     *ib = container_of(
        doorbell, struct evpl_inproc_bind, doorbell);
    struct evpl_inproc_listener *listener    = ib->listener;
    struct evpl_inproc_global   *global      = evpl_inproc_global(evpl);
    struct evpl_bind            *listen_bind = evpl_private2bind(ib);
    struct evpl_inproc_pending  *pending, *tmp, *list;

    pthread_mutex_lock(&global->lock);
    list              = listener->pending;
    listener->pending = NULL;
    pthread_mutex_unlock(&global->lock);

    /*
     * The registry lock is released before the callback, and must be: the
     * callback is evpl_listener_accept(), which takes EvplListenerLock, while
     * evpl_inproc_listen() is reached from evpl_listener_callback() with
     * EvplListenerLock already held and takes the registry lock.  Taking them
     * in this order too would close the cycle.
     */
    DL_FOREACH_SAFE(list, pending, tmp)
    {
        DL_DELETE(list, pending);

        /* The remote address reference passes to the accepting bind. */
        listen_bind->accept_callback(evpl, listen_bind, pending->remote,
                                     pending, listen_bind->private_data);
    }
} /* evpl_inproc_accept */

static int
evpl_inproc_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_inproc_bind     *ib     = evpl_bind_private(listen_bind);
    struct evpl_inproc_global   *global = evpl_inproc_global(evpl);
    struct evpl_inproc_listener *listener, *cur;
    const char                  *name;
    size_t                       len;

    name = evpl_inproc_address_name(listen_bind->local);

    listener = evpl_zalloc(sizeof(*listener));

    len = strnlen(name, sizeof(listener->name) - 1);
    memcpy(listener->name, name, len);

    listener->bind     = listen_bind;
    listener->doorbell = &ib->doorbell;

    /* Armed before the name is published, so a connect that finds the entry
     * always has something to ring.  ib->listener has to be set before the
     * doorbell can fire, since the accept callback reads it back. */
    ib->listener = listener;

    evpl_add_doorbell(evpl, &ib->doorbell, evpl_inproc_accept);

    pthread_mutex_lock(&global->lock);

    DL_FOREACH(global->listeners, cur)
    {
        if (strcmp(cur->name, listener->name) == 0) {
            pthread_mutex_unlock(&global->lock);

            evpl_remove_doorbell(evpl, &ib->doorbell);
            evpl_free(listener);
            ib->listener = NULL;

            /* The EADDRINUSE analogue.  An operating condition rather than a
             * programming error, so it is reported through evpl_listen()
             * rather than being fatal. */
            evpl_inproc_error("inproc name '%s' is already in use", name);
            return -1;
        }
    }

    DL_APPEND(global->listeners, listener);

    pthread_mutex_unlock(&global->lock);

    return 0;
} /* evpl_inproc_listen */

/*
 * Connect and attach
 */

static void
evpl_inproc_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_inproc_bind     *ib     = evpl_bind_private(bind);
    struct evpl_inproc_global   *global = evpl_inproc_global(evpl);
    struct evpl_inproc_listener *listener = NULL, *cur;
    struct evpl_inproc_channel  *chan;
    struct evpl_inproc_pending  *pending;
    struct evpl_address         *conn_addr;
    const char                  *name;
    uint32_t                     id;

    name = evpl_inproc_address_name(bind->remote);

    pthread_mutex_lock(&global->lock);

    DL_FOREACH(global->listeners, cur)
    {
        if (strcmp(cur->name, name) == 0) {
            listener = cur;
            break;
        }
    }

    if (!listener) {
        pthread_mutex_unlock(&global->lock);

        /* Nobody is listening on that name.  Reported the way a refused TCP
         * connection is -- the bind exists and the application learns of it
         * through EVPL_NOTIFY_DISCONNECTED -- rather than by aborting or by
         * giving the connect callback a return value it alone would use. */
        evpl_inproc_debug("no listener for inproc name '%s'", name);
        evpl_close(evpl, bind);
        return;
    }

    id = ++global->next_id;

    chan = evpl_inproc_channel_alloc();

    ib->chan = chan;
    ib->end  = 0;

    /* The connecting end is the one with a serial, the way a TCP client is the
     * one with an ephemeral port. */
    conn_addr   = evpl_inproc_address_alloc(name, id);
    bind->local = conn_addr;

    pending       = evpl_zalloc(sizeof(*pending));
    pending->chan = chan;

    evpl_address_incref(conn_addr);
    pending->remote = conn_addr;

    /* The acceptor's local address is the listening name, which is exactly
     * what this end resolved as its remote. */
    evpl_address_incref(bind->remote);
    pending->local = bind->remote;

    DL_APPEND(listener->pending, pending);

    /* Rung with the registry lock held.  The listener removes itself from the
     * registry under this lock and only then retires its doorbell, so holding
     * it is what guarantees the eventfd is still open. */
    evpl_ring_doorbell(listener->doorbell);

    pthread_mutex_unlock(&global->lock);

    evpl_inproc_queue_arm(evpl, &chan->q[0], ib, evpl_inproc_doorbell);

    /* Wake ourselves once so the first drain emits CONNECTED.  Dispatching it
     * here would run the application's callback before evpl_connect() had
     * returned the bind it refers to. */
    evpl_ring_doorbell(&ib->doorbell);
} /* evpl_inproc_connect */

static void
evpl_inproc_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_inproc_bind    *ib      = evpl_bind_private(bind);
    struct evpl_inproc_pending *pending = accepted;

    ib->chan = pending->chan;
    ib->end  = 1;

    /* evpl_listener_accept() leaves the local address for the protocol to
     * fill in, since a socket backend can only learn it from getsockname(). */
    bind->local = pending->local;

    evpl_free(pending);

    evpl_inproc_queue_arm(evpl, &ib->chan->q[1], ib, evpl_inproc_doorbell);

    /* Emits CONNECTED, and picks up anything the peer sent before this end
     * existed -- those enqueues found no armed doorbell and skipped the
     * wakeup, so nothing else would deliver them. */
    evpl_inproc_drain(evpl, bind);
} /* evpl_inproc_attach */

/*
 * Teardown
 */

static void
evpl_inproc_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_inproc_bind     *ib       = evpl_bind_private(bind);
    struct evpl_inproc_listener *listener = ib->listener;
    struct evpl_inproc_global   *global;
    struct evpl_inproc_queue    *q;
    struct evpl_inproc_pending  *pending, *tmp, *list;
    struct evpl_dgram           *fin;

    if (listener) {
        global = evpl_inproc_global(evpl);

        pthread_mutex_lock(&global->lock);

        DL_DELETE(global->listeners, listener);

        list              = listener->pending;
        listener->pending = NULL;

        pthread_mutex_unlock(&global->lock);

        /* Unpublished first, so no connect can still be holding this listener
         * and about to ring a doorbell we are about to close. */
        evpl_remove_doorbell(evpl, &ib->doorbell);

        DL_FOREACH_SAFE(list, pending, tmp)
        {
            DL_DELETE(list, pending);
            evpl_inproc_pending_discard(evpl, pending);
        }

        evpl_free(listener);

        ib->listener = NULL;
        return;
    }

    if (!ib->chan) {
        /* A connect that never found a listener. */
        return;
    }

    /* Tell the peer, in band behind anything already queued. */
    q = &ib->chan->q[evpl_inproc_peer(ib->end)];

    pthread_mutex_lock(&q->lock);

    fin             = evpl_dgram_ring_add(&q->dgram);
    fin->dgram_type = EVPL_INPROC_MSG_FIN;
    fin->niov       = 0;
    fin->length     = 0;

    evpl_inproc_queue_notify(q);

    pthread_mutex_unlock(&q->lock);

    /* Stop taking wakeups.  Anything the peer queues from here on stays in the
     * ring and is released when the channel goes. */
    evpl_inproc_queue_disarm(evpl, &ib->chan->q[ib->end], ib);
} /* evpl_inproc_pending_close */

static void
evpl_inproc_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_inproc_bind *ib = evpl_bind_private(bind);

    if (!ib->chan) {
        return;
    }

    evpl_inproc_channel_release(evpl, ib->chan);

    ib->chan = NULL;
} /* evpl_inproc_close */

/*
 * Framework
 */

static void *
evpl_inproc_init(void)
{
    struct evpl_inproc_global *global = evpl_zalloc(sizeof(*global));

    pthread_mutex_init(&global->lock, NULL);

    evpl_rdma_mr_table_init(&global->mr_table);

    return global;
} /* evpl_inproc_init */

static void
evpl_inproc_cleanup(void *private_data)
{
    struct evpl_inproc_global *global = private_data;

    evpl_rdma_mr_table_cleanup(&global->mr_table);

    pthread_mutex_destroy(&global->lock);

    evpl_free(global);
} /* evpl_inproc_cleanup */

static void *
evpl_inproc_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_inproc_thread *thread = evpl_zalloc(sizeof(*thread));

    thread->global = private_data;

    return thread;
} /* evpl_inproc_create */

static void
evpl_inproc_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_free(private_data);
} /* evpl_inproc_destroy */

static void *
evpl_inproc_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *framework_private)
{
    struct evpl_inproc_global *global = framework_private;

    return evpl_rdma_mr_register(&global->mr_table, buffer, size,
                                 buffer_private);
} /* evpl_inproc_register_memory */

static void
evpl_inproc_unregister_memory(
    void *buffer_private,
    void *framework_private)
{
    struct evpl_inproc_global *global = framework_private;

    evpl_rdma_mr_unregister(&global->mr_table, buffer_private);
} /* evpl_inproc_unregister_memory */

static void
evpl_inproc_get_rdma_address(
    struct evpl_bind  *bind,
    struct evpl_iovec *iov,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct evpl_rdma_mr *mr = evpl_memory_framework_private(
        iov, EVPL_FRAMEWORK_INPROC);

    if (mr) {
        *r_key = mr->rkey;

        /* Same address space, so the peer can use the pointer as it stands --
         * which is the whole reason one-sided operations reduce to a memcpy
         * here. */
        *r_address = (uint64_t) iov->data;
    } else {
        *r_key     = 0;
        *r_address = 0;
    }
} /* evpl_inproc_get_rdma_address */

struct evpl_framework evpl_framework_inproc = {
    .id                = EVPL_FRAMEWORK_INPROC,
    .name              = "INPROC",
    .init              = evpl_inproc_init,
    .cleanup           = evpl_inproc_cleanup,
    .create            = evpl_inproc_create,
    .destroy           = evpl_inproc_destroy,
    .register_memory   = evpl_inproc_register_memory,
    .unregister_memory = evpl_inproc_unregister_memory,
    .get_rdma_address  = evpl_inproc_get_rdma_address,
};

struct evpl_protocol  evpl_inproc_stream = {
    .id            = EVPL_STREAM_INPROC,
    .connected     = 1,
    .stream        = 1,
    .rdma          = 0,
    .endpoint_kind = EVPL_ENDPOINT_INPROC,
    .name          = "STREAM_INPROC",
    .framework     = &evpl_framework_inproc,
    .connect       = evpl_inproc_connect,
    .listen        = evpl_inproc_listen,
    .attach        = evpl_inproc_attach,
    .pending_close = evpl_inproc_pending_close,
    .close         = evpl_inproc_close,
    .flush         = evpl_inproc_flush,
};

/* Message oriented, and the one that carries RDMA -- mirroring the
 * STREAM_SOCKET_TCP / DATAGRAM_TCP_RDMA split, which rpc2 relies on: it selects
 * its RDMA framing from evpl_bind_is_rdma() and bypasses the segment callback
 * entirely when it is set, so the two are alternatives rather than a pair. */
struct evpl_protocol  evpl_inproc_datagram = {
    .id            = EVPL_DATAGRAM_INPROC,
    .connected     = 1,
    .stream        = 0,
    .rdma          = 1,
    .endpoint_kind = EVPL_ENDPOINT_INPROC,
    .name          = "DATAGRAM_INPROC",
    .framework     = &evpl_framework_inproc,
    .connect       = evpl_inproc_connect,
    .listen        = evpl_inproc_listen,
    .attach        = evpl_inproc_attach,
    .pending_close = evpl_inproc_pending_close,
    .close         = evpl_inproc_close,
    .flush         = evpl_inproc_flush,
};
