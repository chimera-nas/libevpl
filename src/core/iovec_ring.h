// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include <string.h>
#include <sys/uio.h>

#include "core/internal.h"
#include "evpl/evpl.h"
#include "core/buffer.h"

struct evpl_iovec_ring {
    struct evpl_iovec *iovec;
    int                size;
    int                mask;
    int                alignment;
    int                head;
    int                tail;
    uint64_t           length;
};

static inline void
evpl_iovec_ring_alloc(
    struct evpl_iovec_ring *ring,
    int                     size,
    int                     alignment)
{
    ring->iovec = evpl_valloc(size * sizeof(struct evpl_iovec), alignment);

    ring->size      = size;
    ring->mask      = size - 1;
    ring->alignment = alignment;
    ring->head      = 0;
    ring->tail      = 0;
    ring->length    = 0;

} // evpl_iovec_ring_alloc

static inline void
evpl_iovec_ring_free(struct evpl_iovec_ring *ring)
{
    evpl_free(ring->iovec);
} // evpl_iovec_ring_free

static inline void
evpl_iovec_ring_check(const struct evpl_iovec_ring *ring)
{
    struct evpl_iovec *iovec;
    int                cur   = ring->tail;
    uint64_t           bytes = 0;

    while (cur != ring->head) {
        iovec = &ring->iovec[cur];

        bytes += iovec->length;

        evpl_core_abort_if(iovec->length < 1, "zero length iovec in ring");
        evpl_core_abort_if(evpl_iovec_buffer(iovec)->refcnt < 1,
                           "iovec in ring with no refcnt!");

        cur = (cur + 1) & ring->mask;
    }

    evpl_core_abort_if(bytes != ring->length,
                       "ring length %lu does not match actual length %lu",
                       ring->length, bytes);
} // evpl_iovec_ring_check


static inline void
evpl_iovec_ring_resize(struct evpl_iovec_ring *ring)
{
    int                new_size  = ring->size << 1;
    struct evpl_iovec *new_iovec = evpl_valloc(
        new_size * sizeof(struct evpl_iovec), ring->alignment);

    if (ring->head > ring->tail) {
        memcpy(new_iovec, &ring->iovec[ring->tail], (ring->head - ring->tail) *
               sizeof(struct evpl_iovec));
    } else {
        memcpy(new_iovec, &ring->iovec[ring->tail], (ring->size - ring->tail) *
               sizeof(struct evpl_iovec));
        memcpy(&new_iovec[ring->size - ring->tail], ring->iovec, ring->head *
               sizeof(struct evpl_iovec));
    }

    ring->head = ring->size - 1;
    ring->tail = 0;

    evpl_free(ring->iovec);

    ring->iovec = new_iovec;
    ring->size  = new_size;
    ring->mask  = new_size - 1;
} // evpl_iovec_ring_resize

static inline int
evpl_iovec_ring_is_empty(const struct evpl_iovec_ring *ring)
{
    return ring->head == ring->tail;
} // evpl_iovec_ring_is_empty

static inline int
evpl_iovec_ring_is_full(const struct evpl_iovec_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
} // evpl_iovec_ring_is_full

static inline uint64_t
evpl_iovec_ring_elements(const struct evpl_iovec_ring *ring)
{
    return ((ring->head + ring->size) - ring->tail) & ring->mask;
} // evpl_iovec_ring_elements

static inline uint64_t
evpl_iovec_ring_bytes(const struct evpl_iovec_ring *ring)
{
    return ring->length;
} // evpl_iovec_ring_bytes

static inline struct evpl_iovec *
evpl_iovec_ring_head(struct evpl_iovec_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->iovec[(ring->head + ring->size - 1) & ring->mask];
    }
} // evpl_iovec_ring_head

static inline struct evpl_iovec *
evpl_iovec_ring_tail(struct evpl_iovec_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->iovec[ring->tail];
    }
} // evpl_iovec_ring_tail

static inline struct evpl_iovec *
evpl_iovec_ring_next(
    struct evpl_iovec_ring *ring,
    struct evpl_iovec      *cur)
{
    int index = ((cur - ring->iovec) + 1) & ring->mask;

    if (index == ring->head) {
        return NULL;
    }

    return &ring->iovec[index];
} // evpl_iovec_ring_next

static inline struct evpl_iovec *
evpl_iovec_ring_add(
    struct evpl_iovec_ring  *ring,
    const struct evpl_iovec *iovec)
{
    struct evpl_iovec *res;

    if (unlikely(evpl_iovec_ring_is_full(ring))) {
        evpl_iovec_ring_resize(ring);
    }

    res = &ring->iovec[ring->head];

    ring->iovec[ring->head] = *iovec;
    ring->head              = (ring->head + 1) & ring->mask;

    ring->length += iovec->length;

    return res;
} // evpl_iovec_ring_add

static inline struct evpl_iovec *
evpl_iovec_ring_add_new(struct evpl_iovec_ring *ring)
{
    struct evpl_iovec *res;

    if (unlikely(evpl_iovec_ring_is_full(ring))) {
        evpl_iovec_ring_resize(ring);
    }

    res = &ring->iovec[ring->head];


    ring->head = (ring->head + 1) & ring->mask;

    return res;
} // evpl_iovec_ring_add


static inline void
evpl_iovec_ring_remove(struct evpl_iovec_ring *ring)
{
    struct evpl_iovec *cur = &ring->iovec[ring->tail];

    ring->length -= cur->length;

    ring->tail = (ring->tail + 1) & ring->mask;
} // evpl_iovec_ring_remove

static inline void
evpl_iovec_ring_clear(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring)
{
    struct evpl_iovec *iovec;

    while (ring->tail != ring->head) {
        iovec = &ring->iovec[ring->tail];
        evpl_iovec_release(iovec);
        ring->tail = (ring->tail + 1) & ring->mask;
    }

    ring->head   = 0;
    ring->tail   = 0;
    ring->length = 0;
} // evpl_iovec_ring_clear


static inline int
evpl_iovec_ring_iov(
    ssize_t                *r_total,
    struct iovec           *iov,
    int                     max_iov,
    struct evpl_iovec_ring *ring)
{
    struct evpl_iovec *iovec;
    int                niov  = 0;
    int                pos   = ring->tail;
    int                total = 0;

    while (niov < max_iov && pos != ring->head) {
        iovec = &ring->iovec[pos];

        iov[niov].iov_base = iovec->data;
        iov[niov].iov_len  = iovec->length;
        niov++;
        total += iovec->length;

        pos = (pos + 1) & ring->mask;
    }

    *r_total = total;

    return niov;
} // evpl_iovec_ring_iov

static inline int
evpl_iovec_ring_consume(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring,
    size_t                  length)
{
    struct evpl_iovec *iovec;
    int                n = 0;

    ring->length -= length;

    while (length > 0 && ring->tail != ring->head) {

        iovec = &ring->iovec[ring->tail];

        if (iovec->length <= length) {
            length -= iovec->length;
            evpl_iovec_release(iovec);
            ring->tail = (ring->tail + 1) & ring->mask;
            n++;
        } else {
            iovec->data   += length;
            iovec->length -= length;

            length = 0;
        }
    }

    return n;
} // evpl_iovec_ring_consume

static inline int
evpl_iovec_ring_copyv(
    struct evpl            *evpl,
    struct evpl_iovec      *out,
    struct evpl_iovec_ring *ring,
    int                     length)
{
    struct evpl_iovec *iovec;
    int                left = length, chunk, niov = 0;

    while (left) {

        iovec = &ring->iovec[ring->tail];

        out[niov].private = iovec->private;
        out[niov].data    = iovec->data;

        if (left < iovec->length) {
            chunk = left;
            evpl_iovec_incref(iovec);
            iovec->data   += left;
            iovec->length -= left;
        } else {
            chunk      = iovec->length;
            ring->tail = (ring->tail + 1) & ring->mask;
        }

        out[niov].length = chunk;

        niov++;

        left -= chunk;
    }

    ring->length -= length;

    return niov;
} // evpl_iovec_ring_copyv


static inline void
evpl_iovec_ring_consumev(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring,
    int                     niov)
{
    struct evpl_iovec *iovec;

    while (niov > 0 && ring->tail != ring->head) {

        iovec = &ring->iovec[ring->tail];

        ring->length -= iovec->length;

        evpl_iovec_release(iovec);
        ring->tail = (ring->tail + 1) & ring->mask;

        niov--;

    }
} // evpl_iovec_ring_consumev

static inline void
evpl_iovec_ring_append(
    struct evpl            *evpl,
    struct evpl_iovec_ring *ring,
    struct evpl_iovec      *append,
    int                     length)
{
    struct evpl_iovec *head;

    head = evpl_iovec_ring_head(ring);

    if (head && head->data + head->length == append->data) {
        head->length += length;
    } else {
        head          = evpl_iovec_ring_add_new(ring);
        head->data    = append->data;
        head->private = append->private;
        head->length  = length;
        evpl_iovec_incref(head);
    }

    append->data   += length;
    append->length -= length;

    if (append->length == 0) {
        evpl_iovec_decref(append);
    }

    ring->length += length;

} // evpl_iovec_ring_append
