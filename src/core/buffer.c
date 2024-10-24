#define _GNU_SOURCE
#include <pthread.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <unistd.h>

#include "utlist.h"

#include "core/internal.h"
#include "core/evpl.h"
#include "core/evpl_shared.h"
#include "core/buffer.h"
#include "core/protocol.h"


extern struct evpl_shared *evpl_shared;

struct evpl_allocator *
evpl_allocator_create()
{
    struct evpl_allocator *allocator = evpl_zalloc(sizeof(*allocator));

    pthread_mutex_init(&allocator->lock, NULL);

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
        evpl_free(buffer);
    }

    while (allocator->slabs) {
        slab = allocator->slabs;
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

        munmap(slab->data, evpl_shared->config->slab_size);
        //evpl_free(slab->data);
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

    slab       = evpl_zalloc(sizeof(*slab));
    slab->size = evpl_shared->config->slab_size;

    slab->data = mmap(NULL, evpl_shared->config->slab_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                      -1, 0);

    if (slab->data == MAP_FAILED) {
        evpl_core_fatal("Failed to allocate huge pages");
    }

    *(uint64_t *) slab->data = 1;

    //slab->data = evpl_valloc(slab->size, config->page_size);

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
    struct evpl_config *config = evpl_shared->config;
    struct evpl_slab   *slab;
    struct evpl_buffer *buffer;
    void               *ptr;

    pthread_mutex_lock(&allocator->lock);

    if (!allocator->free_buffers) {

        slab = evpl_allocator_create_slab(allocator);

        ptr = slab->data;

        while (ptr + config->buffer_size <= slab->data + slab->size) {

            buffer       = evpl_zalloc(sizeof(*buffer));
            buffer->data = ptr;
            buffer->slab = slab;
            buffer->used = 0;
            buffer->size = config->buffer_size;

            ptr += config->buffer_size;

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

void
evpl_allocator_free(
    struct evpl_allocator *allocator,
    struct evpl_buffer    *buffers)
{
    pthread_mutex_lock(&allocator->lock);
    LL_CONCAT(allocator->free_buffers, buffers);
    pthread_mutex_unlock(&allocator->lock);
} /* evpl_allocator_free */

void *
evpl_allocator_alloc_slab(struct evpl_allocator *allocator)
{
    struct evpl_slab *slab;

    slab = evpl_allocator_create_slab(allocator);

    return slab->data;

} /* evpl_allocator_alloc_slab */
