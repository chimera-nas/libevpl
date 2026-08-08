// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

/*
 * Memory registration for transports that emulate RDMA inside one address
 * space -- TCP_RDMA between two processes, and the inproc transport between
 * two threads.
 *
 * There is no hardware to program, so a "registration" is just a table entry
 * recording an extent, and the rkey is the table index.  What it buys is
 * validation: a peer hands over an (rkey, address, length) triple, and this is
 * what turns that back into a pointer only if it really does name registered
 * memory.  Both transports exist largely so RDMA-using code can be tested
 * without RDMA hardware, and a bad key surfacing as an error rather than a
 * wild pointer is most of the value.
 *
 * Registrations are expected to be few and large: libevpl registers whole
 * allocator slabs, not individual buffers.
 */

struct evpl_rdma_mr {
    void    *base;
    size_t   size;
    uint32_t rkey;   /* table index, kept so unregister can find its slot */
};

struct evpl_rdma_mr_table {
    struct evpl_rdma_mr **entries;    /* NULL slot == unused */
    uint32_t              size;       /* power of two */
    uint32_t              next_rkey;  /* slots are never reused */
    pthread_mutex_t       lock;
};

void
evpl_rdma_mr_table_init(
    struct evpl_rdma_mr_table *table);

/* Frees every remaining registration along with the table's storage. */
void
evpl_rdma_mr_table_cleanup(
    struct evpl_rdma_mr_table *table);

/*
 * Register an extent, or hand back an existing registration unchanged.
 *
 * Shaped to drop straight into a framework's register_memory callback, which
 * may be invoked again on a buffer it has already seen (see the comment on
 * evpl_framework::register_memory).
 */
struct evpl_rdma_mr *
evpl_rdma_mr_register(
    struct evpl_rdma_mr_table *table,
    void                      *buffer,
    int                        size,
    struct evpl_rdma_mr       *existing);

void
evpl_rdma_mr_unregister(
    struct evpl_rdma_mr_table *table,
    struct evpl_rdma_mr       *mr);

/*
 * Turn a peer-supplied (rkey, address, length) into a pointer.
 *
 * Returns 0 and stores the pointer if the range lies wholly inside a live
 * registration, otherwise -EINVAL.  Never trust the triple without this: it
 * arrived over the wire (or over a queue) and nothing else checks it.
 */
int
evpl_rdma_mr_validate(
    struct evpl_rdma_mr_table *table,
    uint32_t                   rkey,
    uint64_t                   address,
    uint32_t                   length,
    void                     **out_ptr);
