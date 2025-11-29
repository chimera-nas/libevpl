// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "core/evpl.h"
#include "core/iovec.h"

enum evpl_rdma_request_type {
    EVPL_RDMA_READ,
    EVPL_RDMA_WRITE,
};

struct evpl_rdma_request {
    enum evpl_rdma_request_type type;
    uint32_t                    remote_key;
    uint64_t                    remote_address;
    struct evpl_iovec          *iov;
    int                         niov;
    void                        (*callback)(
        int   status,
        void *private_data);
    void                       *private_data;
};

struct evpl_rdma_request_ring {
    struct evpl_rdma_request *request;
    int                       size;
    int                       mask;
    int                       head;
    int                       tail;
    int                       alignment;
};



static inline void
evpl_rdma_request_ring_alloc(
    struct evpl_rdma_request_ring *ring,
    int                            size,
    int                            alignment)
{
    ring->request = evpl_valloc(size * sizeof(struct evpl_rdma_request), alignment);

    ring->size      = size;
    ring->mask      = size - 1;
    ring->head      = 0;
    ring->tail      = 0;
    ring->alignment = alignment;
} // evpl_rdma_request_ring_alloc

static inline void
evpl_rdma_request_ring_free(struct evpl_rdma_request_ring *ring)
{
    evpl_free(ring->request);
} // evpl_rdma_request_ring_free

static inline void
evpl_rdma_request_ring_resize(struct evpl_rdma_request_ring *ring)
{
    int                       new_size    = ring->size << 1;
    struct evpl_rdma_request *new_request = evpl_valloc(
        new_size * sizeof(struct evpl_rdma_request), ring->alignment);

    evpl_core_assert(ring->request);

    if (ring->head > ring->tail) {
        memcpy(new_request, &ring->request[ring->tail], (ring->head - ring->tail) *
               sizeof(struct evpl_rdma_request));
    } else {
        memcpy(new_request, &ring->request[ring->tail], (ring->size - ring->tail) *
               sizeof(struct evpl_rdma_request));
        memcpy(&new_request[ring->size - ring->tail], ring->request, ring->head *
               sizeof(struct evpl_rdma_request));
    }

    ring->head = ring->size - 1;
    ring->tail = 0;

    evpl_free(ring->request);

    ring->request = new_request;
    ring->size    = new_size;
    ring->mask    = new_size - 1;
} // evpl_rdma_request_ring_resize


static inline void
evpl_rdma_request_ring_clear(
    struct evpl                   *evpl,
    struct evpl_rdma_request_ring *ring)
{
    struct evpl_rdma_request *request;
    int                       i;

    while (ring->tail != ring->head) {

        request = &ring->request[ring->tail];

        for (i = 0; i < request->niov; i++) {
            evpl_iovec_release(&request->iov[i]);
        }

        ring->tail = (ring->tail + 1) & ring->mask;
    }

    ring->head = 0;
    ring->tail = 0;
} // evpl_rdma_request_ring_clear

static inline struct evpl_rdma_request *
evpl_rdma_request_ring_head(struct evpl_rdma_request_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->request[(ring->head + ring->size - 1) & ring->mask];
    }
} // evpl_rdma_request_ring_head

static inline struct evpl_rdma_request *
evpl_rdma_request_ring_tail(struct evpl_rdma_request_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->request[ring->tail];
    }
} // evpl_rdma_request_ring_tail


static inline int
evpl_rdma_request_ring_is_empty(const struct evpl_rdma_request_ring *ring)
{
    return ring->head == ring->tail;
} // evpl_rdma_request_ring_is_empty

static inline int
evpl_rdma_request_ring_is_full(const struct evpl_rdma_request_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
} // evpl_rdma_request_ring_is_full

static inline uint64_t
evpl_rdma_request_ring_elements(const struct evpl_rdma_request_ring *ring)
{
    return ((ring->head + ring->size) - ring->tail) & ring->mask;
} // evpl_rdma_request_ring_elements

static inline struct evpl_rdma_request *
evpl_rdma_request_ring_add(
    struct evpl_rdma_request_ring *ring,
    enum evpl_rdma_request_type    type,
    uint32_t                       remote_key,
    uint64_t                       remote_address,
    struct evpl_iovec             *iov,
    int                            niov,
    void (                        *callback )(
        int   status,
        void *private_data),
    void                          *private_data)
{
    struct evpl_rdma_request *res;

    if (unlikely(evpl_rdma_request_ring_is_full(ring))) {
        evpl_rdma_request_ring_resize(ring);
    }

    res = &ring->request[ring->head];

    res->type           = type;
    res->remote_key     = remote_key;
    res->remote_address = remote_address;
    res->iov            = iov;
    res->niov           = niov;
    res->callback       = callback;
    res->private_data   = private_data;

    ring->head = (ring->head + 1) & ring->mask;

    return res;
} // evpl_rdma_request_ring_add


static inline void
evpl_rdma_request_ring_remove(struct evpl_rdma_request_ring *ring)
{
    ring->tail = (ring->tail + 1) & ring->mask;
} // evpl_rdma_request_ring_remove