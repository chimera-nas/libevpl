/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#ifndef __EVENTPOLL_BUFFER_H__
#define __EVENTPOLL_BUFFER_H__

#include <sys/uio.h>

#include "eventpoll.h"
#include "eventpoll_internal.h"

struct eventpoll_buffer {
    void *data;
    int refcnt;
    unsigned int used;
    unsigned int size;
    struct eventpoll_buffer *next;
};

struct eventpoll_bvec_ring {
    struct eventpoll_bvec *bvec;
    int size;
    int mask;
    int alignment;
    int head;
    int tail;
};

void eventpoll_buffer_release(
    struct eventpoll *eventpoll,
    struct eventpoll_buffer *buffer);

static inline void
eventpoll_bvec_decref(
    struct eventpoll *eventpoll,
    struct eventpoll_bvec *bvec)
{
    struct eventpoll_buffer *buffer = bvec->buffer;

    --buffer->refcnt;

    if (buffer->refcnt == 0) {
        eventpoll_buffer_release(eventpoll, buffer);
    }
}

static inline void
eventpoll_bvec_incref(
    struct eventpoll_bvec *bvec)
{
    ++bvec->buffer->refcnt;
}



static inline unsigned int
eventpoll_buffer_left(struct eventpoll_buffer *buffer)
{
    return buffer->size - buffer->used;
}

static inline unsigned int
eventpoll_buffer_pad(struct eventpoll_buffer *buffer, unsigned int alignment)
{
    return (alignment - (buffer->used & (alignment - 1))) & (alignment - 1);
}

static inline void
eventpoll_bvec_ring_alloc(
    struct eventpoll_bvec_ring *ring,
    int size,
    int alignment)
{
    ring->bvec = eventpoll_valloc(size, 64);

    ring->size = size;
    ring->mask = size - 1;
    ring->alignment = alignment;
    ring->head = 0;
    ring->tail = 0;

}

static inline void
eventpoll_bvec_ring_free(struct eventpoll_bvec_ring *ring)
{
    eventpoll_free(ring->bvec);
}

static inline void
eventpoll_bvec_ring_resize(struct eventpoll_bvec_ring *ring)
{
    int new_size = ring->size << 1;
    struct eventpoll_bvec *new_bvec = eventpoll_valloc(
        new_size * sizeof(struct eventpoll_bvec), ring->alignment);

    if (ring->head > ring->tail) {
        memcpy(new_bvec, &ring->bvec[ring->tail], (ring->head - ring->tail) * sizeof(struct eventpoll_bvec));
    } else {
        memcpy(new_bvec, &ring->bvec[ring->tail], (ring->size - ring->tail) * sizeof(struct eventpoll_bvec));
        memcpy(&new_bvec[ring->size - ring->tail], ring->bvec, ring->head * sizeof(struct eventpoll_bvec));
    }

    ring->head = ring->size - 1;
    ring->tail = 0;

    eventpoll_free(ring->bvec);

    ring->bvec = new_bvec;
    ring->size = new_size;
    ring->mask = new_size - 1;
}

static inline int
eventpoll_bvec_ring_is_empty(const struct eventpoll_bvec_ring *ring)
{
    return ring->head == ring->tail;
}

static inline int
eventpoll_bvec_ring_is_full(const struct eventpoll_bvec_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
}

static inline struct eventpoll_bvec *
eventpoll_bvec_ring_head(struct eventpoll_bvec_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->bvec[ring->head];
    }
}

static inline struct eventpoll_bvec *
eventpoll_bvec_ring_add(struct eventpoll_bvec_ring *ring, const struct eventpoll_bvec *bvec)
{
    struct eventpoll_bvec *res;

    if (eventpoll_bvec_ring_is_full(ring)) {
        eventpoll_bvec_ring_resize(ring);
    }

    res = &ring->bvec[ring->head];

    ring->bvec[ring->head] = *bvec;
    ring->head = (ring->head + 1) & ring->mask;

    return res;
}

static inline void
eventpoll_bvec_ring_remove(struct eventpoll_bvec_ring *ring)
{
    ring->tail = (ring->tail + 1) & ring->mask;
}

static inline void
eventpoll_bvec_ring_clear(struct eventpoll_bvec_ring *ring)
{
    ring->head = 0;
    ring->tail = 0;
}


static inline int
eventpoll_bvec_ring_iov(
    ssize_t *r_total,
    struct iovec *iov,
    int max_iov,
    struct eventpoll_bvec_ring *ring)
{
    struct eventpoll_bvec *bvec;
    int niov = 0;
    int pos = ring->tail;
    int total = 0;

    while (niov < max_iov && pos != ring->head) {
        bvec = &ring->bvec[pos];

        iov[niov].iov_base = bvec->data;
        iov[niov].iov_len = bvec->length;
        niov++;
        total += bvec->length;

        pos = (pos + 1) & ring->mask;
    }

    *r_total = total;

    return niov;
}

static inline void
eventpoll_bvec_ring_consume(
    struct eventpoll *eventpoll,
    struct eventpoll_bvec_ring *ring,
    size_t length)
{
    struct eventpoll_bvec *bvec;

    while (length > 0 && ring->tail != ring->head) {

        bvec = &ring->bvec[ring->tail];

        if (bvec->length <= length) {
            eventpoll_bvec_release(eventpoll, bvec);
            length -= bvec->length;
            ring->tail = (ring->tail + 1) & ring->mask;
        } else {
            bvec->data   += length;
            bvec->length -= length;

            length = 0;
        }
    }
}
static inline void
eventpoll_bvec_ring_append(
    struct eventpoll *eventpoll,
    struct eventpoll_bvec_ring *ring,
    struct eventpoll_bvec *append,
    int length)
{
    struct eventpoll_bvec *head;

    head = eventpoll_bvec_ring_head(ring);

    if (head && head->data + head->length == append->data) {
        head->length += length;
    } else {
        eventpoll_info("incrementing refcnt on buffer");
        eventpoll_bvec_incref(append);
        head = eventpoll_bvec_ring_add(ring, append);
        head->length = length;
    }

    append->data   += length;
    append->length -= length;

    if (append->length == 0) {
        eventpoll_bvec_decref(eventpoll, append);
    }
}

#endif
