// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_memory.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_iovec_ref;

struct evpl_iovec_ref {
    unsigned int      refcnt;
    struct evpl_slab *slab;
    void              (*release)(
        struct evpl_iovec_ref *ref);
};

struct evpl_iovec {
    void                  *data;
    unsigned int           length;
    unsigned int           pad;
    struct evpl_iovec_ref *ref;
};

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


static inline void
evpl_iovec_ref_release(struct evpl_iovec_ref *ref)
{
    --ref->refcnt;
    if (ref->refcnt == 0) {
        ref->release(ref);
    }
} // evpl_iovec_release

static inline void
evpl_iovecs_release(
    struct evpl_iovec *iov,
    int                niov)
{
    for (int i = 0; i < niov; i++) {
        evpl_iovec_ref_release(iov[i].ref);
    }
} // evpl_iovecs_release

static inline void
evpl_iovec_release(struct evpl_iovec *iovec)
{
    evpl_iovec_ref_release(iovec->ref);
} // evpl_iovec_release

static inline void *
evpl_iovec_data(const struct evpl_iovec *iovec)
{
    return iovec->data;
} /* evpl_iovec_data */

static inline unsigned int
evpl_iovec_length(const struct evpl_iovec *iovec)
{
    return iovec->length;
} /* evpl_iovec_length */

static inline void
evpl_iovec_set_length(
    struct evpl_iovec *iovec,
    unsigned int       length)
{
    iovec->length = length;
} /* evpl_iovec_set_length */

static inline void
evpl_iovec_addref(struct evpl_iovec *iovec)
{
    ++iovec->ref->refcnt;
} // evpl_iovec_addref

void *
evpl_slab_alloc(
    void);