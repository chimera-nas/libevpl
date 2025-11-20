// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <pthread.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <unistd.h>
#include <utlist.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/allocator.h"
#include "core/protocol.h"
#include "core/macros.h"


extern struct evpl_shared *evpl_shared;


struct evpl_slab {
    void                  *data;
    struct evpl_allocator *allocator;
    uint64_t               refcnt;
    uint64_t               size      : 63;
    uint64_t               hugepages : 1;
    struct evpl_buffer    *buffers;
    void                  *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_slab      *next;
};

struct evpl_allocator *
evpl_allocator_create()
{
    struct evpl_allocator *allocator = evpl_zalloc(sizeof(*allocator));

    pthread_mutex_init(&allocator->lock, NULL);

    allocator->hugepages = evpl_shared->config->huge_pages;

    return allocator;

} /* evpl_allocator_create */

void
evpl_allocator_destroy(struct evpl_allocator *allocator)
{
    struct evpl_slab      *slab;
    struct evpl_buffer    *buffer;
    struct evpl_framework *framework;
    int                    i;

    while (allocator->free_buffers) {
        buffer = allocator->free_buffers;
        LL_DELETE(allocator->free_buffers, buffer);
        buffer->slab->refcnt--;
    }

    while (allocator->slabs) {
        slab = allocator->slabs;

        if (slab->refcnt && slab->buffers) {
            for (int i = 0; i < slab->size / evpl_shared->config->buffer_size; i++) {
                buffer = &slab->buffers[i];
                evpl_core_abort_if(buffer->refcnt != 0,
                                   "evpl_allocator_destroy: buffer %p has %d leaked references",
                                   buffer, buffer->refcnt);
            }
        }

        evpl_core_abort_if(slab->refcnt != 0,
                           "evpl_allocator_destroy: slab %p has %d leaked references",
                           slab, slab->refcnt);


        LL_DELETE(allocator->slabs, slab);

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {

            framework = evpl_shared->framework[i];

            if (!framework || !framework->unregister_memory ||
                !evpl_shared->framework_private[i]) {
                continue;
            }

            framework->unregister_memory(
                slab->framework_private[i],
                evpl_shared->framework_private[i]);

        }

        if (slab->hugepages) {
            munmap(slab->data, evpl_shared->config->slab_size);
        } else {
            evpl_free(slab->data);
        }

        if (slab->buffers) {
            /* Slabs we gave out whole will not have buffers associated with them */
            evpl_free(slab->buffers);
        }

        evpl_free(slab);
    }


    evpl_free(allocator);
} /* evpl_allocator_destroy */

static struct evpl_slab *
evpl_allocator_create_slab(struct evpl_allocator *allocator)
{
    struct evpl_slab      *slab;
    struct evpl_framework *framework;
    int                    i;

    slab            = evpl_zalloc(sizeof(*slab));
    slab->size      = evpl_shared->config->slab_size;
    slab->allocator = allocator;

 again:

    if (allocator->hugepages) {

        slab->data = mmap(NULL, evpl_shared->config->slab_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);

        if (slab->data == MAP_FAILED) {
            evpl_core_info("Could not allocate huge pages, disabling...");
            allocator->hugepages = 0;
            goto again;
        }

        *(uint64_t *) slab->data = 0;

        slab->hugepages = 1;
    } else {

        slab->data = evpl_valloc(evpl_shared->config->slab_size,
                                 evpl_shared->config->page_size);

    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {

        framework = evpl_shared->framework[i];

        if (!framework || !framework->register_memory ||
            !evpl_shared->framework_private[i]) {
            continue;
        }

        slab->framework_private[i] = framework->register_memory(
            slab->data, slab->size,
            slab->framework_private[i],
            evpl_shared->framework_private[i]);

    }

    LL_PREPEND(allocator->slabs, slab);

    return slab;
} /* evpl_allocator_create_slab */

struct evpl_buffer *
evpl_allocator_alloc(struct evpl_allocator *allocator)
{
    struct evpl_global_config *config = evpl_shared->config;
    struct evpl_slab          *slab;
    struct evpl_buffer        *buffer;
    int                        num_buffers;

    pthread_mutex_lock(&allocator->lock);

    if (!allocator->free_buffers) {

        slab = evpl_allocator_create_slab(allocator);

        num_buffers = slab->size / config->buffer_size;

        slab->buffers = evpl_zalloc(num_buffers * sizeof(*slab->buffers));

        for (int i = 0; i < num_buffers; i++) {
            buffer            = &slab->buffers[i];
            buffer->data      = slab->data + i * config->buffer_size;
            buffer->slab      = slab;
            buffer->allocator = allocator;
            buffer->used      = 0;
            buffer->size      = config->buffer_size;

            slab->refcnt++;

            LL_PREPEND(allocator->free_buffers, buffer);
        }
    }

    buffer = allocator->free_buffers;
    LL_DELETE(allocator->free_buffers, buffer);

    pthread_mutex_unlock(&allocator->lock);

    return buffer;

} /* evpl_allocator_alloc */

void
evpl_allocator_reregister(struct evpl_allocator *allocator)
{
    struct evpl_slab      *slab;
    struct evpl_framework *framework;
    int                    i;

    pthread_mutex_lock(&allocator->lock);

    LL_FOREACH(allocator->slabs, slab)
    {

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {

            framework = evpl_shared->framework[i];

            if (!framework || !framework->register_memory ||
                !evpl_shared->framework_private[i]) {
                continue;
            }

            slab->framework_private[i] = framework->register_memory(
                slab->data, slab->size,
                slab->framework_private[i],
                evpl_shared->framework_private[i]);
        }
    }

    pthread_mutex_unlock(&allocator->lock);

} /* evpl_allocator_reregister */

SYMBOL_EXPORT void
evpl_allocator_free(
    struct evpl_allocator *allocator,
    struct evpl_buffer    *buffer)
{
    pthread_mutex_lock(&allocator->lock);
    LL_PREPEND(allocator->free_buffers, buffer);
    pthread_mutex_unlock(&allocator->lock);
} /* evpl_allocator_free */

void *
evpl_allocator_alloc_slab(struct evpl_allocator *allocator)
{
    struct evpl_slab *slab;

    pthread_mutex_lock(&allocator->lock);
    slab = evpl_allocator_create_slab(allocator);
    pthread_mutex_unlock(&allocator->lock);

    return slab->data;

} /* evpl_allocator_alloc_slab */


void *
evpl_buffer_framework_private(
    struct evpl_buffer *buffer,
    int                 framework_id)
{
    return buffer->slab->framework_private[framework_id];
} // evpl_buffer_framework_private
