// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_memory.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_buffer;

struct evpl_iovec {
    void        *data;
    unsigned int length;
    unsigned int pad;
    void        *private_data; /* for internal use by livbevpl only */
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

void evpl_iovec_release(
    struct evpl_iovec *iovec);

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

void evpl_iovec_addref(
    struct evpl_iovec *iovec);

void *
evpl_slab_alloc(
    void);