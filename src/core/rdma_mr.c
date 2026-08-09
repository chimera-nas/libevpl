// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>
#include <string.h>

#include "core/evpl.h"
#include "core/rdma_mr.h"

#define EVPL_RDMA_MR_TABLE_INITIAL_SIZE 1024

void
evpl_rdma_mr_table_init(struct evpl_rdma_mr_table *table)
{
    pthread_mutex_init(&table->lock, NULL);

    table->size = EVPL_RDMA_MR_TABLE_INITIAL_SIZE;

    /* rkey 0 is reserved so that a zeroed (rkey, address) pair -- what
     * evpl_rdma_get_address() reports for unregistered memory -- can never
     * validate against a real registration. */
    table->next_rkey = 1;
    table->entries   = evpl_zalloc(table->size * sizeof(struct evpl_rdma_mr *));
} /* evpl_rdma_mr_table_init */

void
evpl_rdma_mr_table_cleanup(struct evpl_rdma_mr_table *table)
{
    uint32_t i;

    /* Slots are never reused, so nothing above next_rkey was ever handed
     * out. */
    for (i = 1; i < table->next_rkey && i < table->size; i++) {
        if (table->entries[i]) {
            evpl_free(table->entries[i]);
        }
    }

    evpl_free(table->entries);
    pthread_mutex_destroy(&table->lock);

    table->entries = NULL;
    table->size    = 0;
} /* evpl_rdma_mr_table_cleanup */

/* Grow to the next power of two.  Called with the table lock held. */
static void
evpl_rdma_mr_table_resize(struct evpl_rdma_mr_table *table)
{
    uint32_t              new_size = table->size << 1;
    struct evpl_rdma_mr **new_entries;

    new_entries = evpl_zalloc(new_size * sizeof(struct evpl_rdma_mr *));

    memcpy(new_entries, table->entries,
           table->size * sizeof(struct evpl_rdma_mr *));

    evpl_free(table->entries);

    table->entries = new_entries;
    table->size    = new_size;
} /* evpl_rdma_mr_table_resize */

struct evpl_rdma_mr *
evpl_rdma_mr_register(
    struct evpl_rdma_mr_table *table,
    void                      *buffer,
    int                        size,
    struct evpl_rdma_mr       *existing)
{
    struct evpl_rdma_mr *mr;
    uint32_t             rkey;

    if (existing) {
        return existing;
    }

    mr = evpl_zalloc(sizeof(*mr));

    mr->base = buffer;
    mr->size = size;

    pthread_mutex_lock(&table->lock);

    /* Slots are not reused: memory is unregistered only at process shutdown,
     * so a monotonic key costs nothing and makes a stale rkey from a freed
     * registration fail to validate rather than alias a new one. */
    rkey = table->next_rkey++;

    while (rkey >= table->size) {
        evpl_rdma_mr_table_resize(table);
    }

    mr->rkey             = rkey;
    table->entries[rkey] = mr;

    pthread_mutex_unlock(&table->lock);

    return mr;
} /* evpl_rdma_mr_register */

void
evpl_rdma_mr_unregister(
    struct evpl_rdma_mr_table *table,
    struct evpl_rdma_mr       *mr)
{
    pthread_mutex_lock(&table->lock);

    if (mr->rkey < table->size) {
        table->entries[mr->rkey] = NULL;
    }

    pthread_mutex_unlock(&table->lock);

    evpl_free(mr);
} /* evpl_rdma_mr_unregister */

int
evpl_rdma_mr_validate(
    struct evpl_rdma_mr_table *table,
    uint32_t                   rkey,
    uint64_t                   address,
    uint32_t                   length,
    void                     **out_ptr)
{
    struct evpl_rdma_mr *mr = NULL;
    uint64_t             base, end;

    pthread_mutex_lock(&table->lock);

    if (rkey < table->size) {
        mr = table->entries[rkey];
    }

    if (!mr) {
        pthread_mutex_unlock(&table->lock);
        return -EINVAL;
    }

    base = (uint64_t) mr->base;
    end  = base + mr->size;

    /* Compared against the extent's own end rather than by adding length to
     * address, so a length chosen to wrap cannot pass. */
    if (address < base || address > end || length > end - address) {
        pthread_mutex_unlock(&table->lock);
        return -EINVAL;
    }

    pthread_mutex_unlock(&table->lock);

    *out_ptr = (void *) address;

    return 0;
} /* evpl_rdma_mr_validate */
