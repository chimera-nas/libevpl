/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include <sys/uio.h>

#include "core/evpl.h"
#include "core/internal.h"
#include "core/buffer.h"

struct evpl_bvec_ring {
    struct evpl_bvec *bvec;
    int               size;
    int               mask;
    int               alignment;
    int               head;
    int               tail;
    int               bytes;
    uint64_t          length;
};

static inline void
evpl_bvec_ring_alloc(
    struct evpl_bvec_ring *ring,
    int                    size,
    int                    alignment)
{
    ring->bvec = evpl_valloc(size * sizeof(struct evpl_bvec), alignment);

    ring->size      = size;
    ring->mask      = size - 1;
    ring->alignment = alignment;
    ring->head      = 0;
    ring->tail      = 0;
    ring->length    = 0;

} // evpl_bvec_ring_alloc

static inline void
evpl_bvec_ring_free(struct evpl_bvec_ring *ring)
{
    evpl_free(ring->bvec);
} // evpl_bvec_ring_free

static inline void
evpl_bvec_ring_check(const struct evpl_bvec_ring *ring)
{
    struct evpl_bvec *bvec;
    int               cur   = ring->tail;
    uint64_t          bytes = 0;

    while (cur != ring->head) {
        bvec = &ring->bvec[cur];

        bytes += bvec->length;

        evpl_core_abort_if(bvec->length < 1, "zero length bvec in ring");
        evpl_core_abort_if(bvec->buffer->refcnt < 1,
                           "bvec in ring with no refcnt!");

        cur = (cur + 1) & ring->mask;
    }

    evpl_core_abort_if(bytes != ring->length,
                       "ring length %lu does not match actual length %lu",
                       ring->length, bytes);
} // evpl_bvec_ring_check


static inline void
evpl_bvec_ring_resize(struct evpl_bvec_ring *ring)
{
    int               new_size = ring->size << 1;
    struct evpl_bvec *new_bvec = evpl_valloc(
        new_size * sizeof(struct evpl_bvec), ring->alignment);

    if (ring->head > ring->tail) {
        memcpy(new_bvec, &ring->bvec[ring->tail], (ring->head - ring->tail) *
               sizeof(struct evpl_bvec));
    } else {
        memcpy(new_bvec, &ring->bvec[ring->tail], (ring->size - ring->tail) *
               sizeof(struct evpl_bvec));
        memcpy(&new_bvec[ring->size - ring->tail], ring->bvec, ring->head *
               sizeof(struct evpl_bvec));
    }

    ring->head = ring->size - 1;
    ring->tail = 0;

    evpl_free(ring->bvec);

    ring->bvec = new_bvec;
    ring->size = new_size;
    ring->mask = new_size - 1;
} // evpl_bvec_ring_resize

static inline int
evpl_bvec_ring_is_empty(const struct evpl_bvec_ring *ring)
{
    return ring->head == ring->tail;
} // evpl_bvec_ring_is_empty

static inline int
evpl_bvec_ring_is_full(const struct evpl_bvec_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
} // evpl_bvec_ring_is_full

static inline uint64_t
evpl_bvec_ring_elements(const struct evpl_bvec_ring *ring)
{
    return ((ring->head + ring->size) - ring->tail) & ring->mask;
} // evpl_bvec_ring_elements

static inline uint64_t
evpl_bvec_ring_bytes(const struct evpl_bvec_ring *ring)
{
    return ring->length;
} // evpl_bvec_ring_bytes

static inline struct evpl_bvec *
evpl_bvec_ring_head(struct evpl_bvec_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->bvec[(ring->head + ring->size - 1) & ring->mask];
    }
} // evpl_bvec_ring_head

static inline struct evpl_bvec *
evpl_bvec_ring_tail(struct evpl_bvec_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->bvec[ring->tail];
    }
} // evpl_bvec_ring_tail

static inline struct evpl_bvec *
evpl_bvec_ring_next(
    struct evpl_bvec_ring *ring,
    struct evpl_bvec      *cur)
{
    int index = ((cur - ring->bvec) + 1) & ring->mask;

    if (index == ring->head) {
        return NULL;
    }

    return &ring->bvec[index];
} // evpl_bvec_ring_next

static inline struct evpl_bvec *
evpl_bvec_ring_add(
    struct evpl_bvec_ring  *ring,
    const struct evpl_bvec *bvec)
{
    struct evpl_bvec *res;

    if (evpl_bvec_ring_is_full(ring)) {
        evpl_bvec_ring_resize(ring);
    }

    res = &ring->bvec[ring->head];

    ring->bvec[ring->head] = *bvec;
    ring->head             = (ring->head + 1) & ring->mask;

    ring->length += bvec->length;

    return res;
} // evpl_bvec_ring_add

static inline struct evpl_bvec *
evpl_bvec_ring_add_new(struct evpl_bvec_ring *ring)
{
    struct evpl_bvec *res;

    if (evpl_bvec_ring_is_full(ring)) {
        evpl_bvec_ring_resize(ring);
    }

    res = &ring->bvec[ring->head];


    ring->head = (ring->head + 1) & ring->mask;

    return res;
} // evpl_bvec_ring_add


static inline void
evpl_bvec_ring_remove(struct evpl_bvec_ring *ring)
{
    struct evpl_bvec *cur = &ring->bvec[ring->tail];

    ring->length -= cur->length;

    ring->tail = (ring->tail + 1) & ring->mask;
} // evpl_bvec_ring_remove

static inline void
evpl_bvec_ring_clear(
    struct evpl           *evpl,
    struct evpl_bvec_ring *ring)
{
    struct evpl_bvec *bvec;

    while (ring->tail != ring->head) {
        bvec = &ring->bvec[ring->tail];
        evpl_bvec_release(evpl, bvec);
        ring->tail = (ring->tail + 1) & ring->mask;
    }

    ring->head   = 0;
    ring->tail   = 0;
    ring->length = 0;
} // evpl_bvec_ring_clear


static inline int
evpl_bvec_ring_iov(
    ssize_t               *r_total,
    struct iovec          *iov,
    int                    max_iov,
    struct evpl_bvec_ring *ring)
{
    struct evpl_bvec *bvec;
    int               niov  = 0;
    int               pos   = ring->tail;
    int               total = 0;

    while (niov < max_iov && pos != ring->head) {
        bvec = &ring->bvec[pos];

        iov[niov].iov_base = bvec->data;
        iov[niov].iov_len  = bvec->length;
        niov++;
        total += bvec->length;

        pos = (pos + 1) & ring->mask;
    }

    *r_total = total;

    return niov;
} // evpl_bvec_ring_iov

static inline void
evpl_bvec_ring_consume(
    struct evpl           *evpl,
    struct evpl_bvec_ring *ring,
    size_t                 length)
{
    struct evpl_bvec *bvec;

    ring->length -= length;

    while (length > 0 && ring->tail != ring->head) {

        bvec = &ring->bvec[ring->tail];

        if (bvec->length <= length) {
            length -= bvec->length;
            evpl_bvec_release(evpl, bvec);
            ring->tail = (ring->tail + 1) & ring->mask;
        } else {
            bvec->data   += length;
            bvec->length -= length;

            length = 0;
        }
    }

} // evpl_bvec_ring_consume

static inline int
evpl_bvec_ring_copyv(
    struct evpl           *evpl,
    struct evpl_bvec      *out,
    struct evpl_bvec_ring *ring,
    int                    length)
{
    struct evpl_bvec *bvec;
    int               left = length, chunk, nbvec = 0;

    while (left) {

        bvec = &ring->bvec[ring->tail];

        if (left < bvec->length) {
            chunk = left;
            evpl_bvec_addref(evpl, bvec);
            bvec->data   += left;
            bvec->length -= left;
        } else {
            chunk      = bvec->length;
            ring->tail = (ring->tail + 1) & ring->mask;
        }

        out[nbvec].buffer = bvec->buffer;
        out[nbvec].data   = bvec->data;
        out[nbvec].length = chunk;

        nbvec++;

        left -= chunk;
    }

    ring->length -= length;

    return nbvec;
} // evpl_bvec_ring_copyv


static inline void
evpl_bvec_ring_consumev(
    struct evpl           *evpl,
    struct evpl_bvec_ring *ring,
    int                    nbvec)
{
    struct evpl_bvec *bvec;

    while (nbvec > 0 && ring->tail != ring->head) {

        bvec = &ring->bvec[ring->tail];

        ring->length -= bvec->length;

        evpl_bvec_release(evpl, bvec);
        ring->tail = (ring->tail + 1) & ring->mask;

        nbvec--;

    }
} // evpl_bvec_ring_consumev

static inline void
evpl_bvec_ring_append(
    struct evpl           *evpl,
    struct evpl_bvec_ring *ring,
    struct evpl_bvec      *append,
    int                    length)
{
    struct evpl_bvec *head;

    head = evpl_bvec_ring_head(ring);

    if (head && head->data + head->length == append->data) {
        head->length += length;
    } else {
        head         = evpl_bvec_ring_add_new(ring);
        head->data   = append->data;
        head->buffer = append->buffer;
        head->length = length;
        evpl_bvec_incref(evpl, head);
    }

    append->data   += length;
    append->length -= length;

    if (append->length == 0) {
        evpl_bvec_decref(evpl, append);
    }

    ring->length += length;

} // evpl_bvec_ring_append
