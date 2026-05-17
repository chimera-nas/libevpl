// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <unistd.h>
#include <time.h>
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
} __attribute__((aligned(64)));

static void *
evpl_allocator_prealloc_thread(
    void *arg);

struct evpl_allocator *
evpl_allocator_create()
{
    struct evpl_allocator *allocator = evpl_zalloc(sizeof(*allocator));
    unsigned int           slabs, threads;
    int                    i;

    pthread_mutex_init(&allocator->lock, NULL);
    pthread_cond_init(&allocator->producer_cv, NULL);
    pthread_cond_init(&allocator->consumer_cv, NULL);

    allocator->hugepages = evpl_shared->config->huge_pages;

    allocator->buffers_per_slab = evpl_shared->config->slab_size /
        evpl_shared->config->buffer_size;

    slabs   = evpl_shared->config->preallocate_slabs;
    threads = evpl_shared->config->preallocate_threads;

    if (slabs > 0 && threads == 0) {
        threads = 1;
    }

    allocator->target_buffers       = slabs * allocator->buffers_per_slab;
    allocator->num_prealloc_threads = threads;

    if (threads > 0) {
        allocator->prealloc_threads = evpl_zalloc(threads * sizeof(pthread_t));

        for (i = 0; i < (int) threads; i++) {
            pthread_create(&allocator->prealloc_threads[i], NULL,
                           evpl_allocator_prealloc_thread, allocator);
        }

        /* Seed initial fill so target is reached before first consumer.
         * Issued under the lock; producers will pick the wakeups up once
         * the framework registration callbacks are wired (after
         * evpl_init returns), but the slab inventory builds up at startup
         * either way.
         */
        pthread_mutex_lock(&allocator->lock);
        allocator->outstanding_slabs = slabs;
        allocator->wakeup_credits    = slabs;
        for (i = 0; i < (int) slabs; i++) {
            pthread_cond_signal(&allocator->producer_cv);
        }
        pthread_mutex_unlock(&allocator->lock);
    }

    return allocator;

} /* evpl_allocator_create */

void
evpl_allocator_destroy(struct evpl_allocator *allocator)
{
    struct evpl_slab      *slab;
    struct evpl_buffer    *buffer;
    struct evpl_framework *framework;
    int                    i;

    if (allocator->num_prealloc_threads > 0) {
        pthread_mutex_lock(&allocator->lock);
        allocator->shutdown = 1;
        pthread_cond_broadcast(&allocator->producer_cv);
        pthread_mutex_unlock(&allocator->lock);

        for (i = 0; i < allocator->num_prealloc_threads; i++) {
            pthread_join(allocator->prealloc_threads[i], NULL);
        }

        evpl_free(allocator->prealloc_threads);
    }

    while (allocator->free_buffers) {
        buffer = allocator->free_buffers;
        LL_DELETE(allocator->free_buffers, buffer);
        buffer->ref.slab->refcnt--;
    }

    while (allocator->slabs) {
        slab = allocator->slabs;

        if (slab->refcnt && slab->buffers) {
            for (int i = 0; i < slab->size / evpl_shared->config->buffer_size; i++) {
                buffer = &slab->buffers[i];
#if defined(EVPL_IOVEC_TRACE)
                if (buffer->ref.refcnt != 0) {
                    evpl_core_error("evpl_allocator_destroy: buffer %p has %d leaked references",
                                    buffer, buffer->ref.refcnt);
                }
#else  /* if defined(EVPL_IOVEC_TRACE) */
                evpl_core_abort_if(buffer->ref.refcnt != 0,
                                   "evpl_allocator_destroy: buffer %p has %d leaked references",
                                   buffer, buffer->ref.refcnt);
#endif /* if defined(EVPL_IOVEC_TRACE) */

            }
        }

#if defined(EVPL_IOVEC_TRACE)
        if (slab->refcnt != 0) {
            evpl_core_error("evpl_allocator_destroy: slab %p has %d leaked references",
                            slab, slab->refcnt);
        }
#else  /* if defined(EVPL_IOVEC_TRACE) */
        evpl_core_abort_if(slab->refcnt != 0,
                           "evpl_allocator_destroy: slab %p has %d leaked references",
                           slab, slab->refcnt);
#endif /* if defined(EVPL_IOVEC_TRACE) */


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

/* The heavy part: mmap + register, NO mutation of allocator state.
 * Safe to call without holding allocator->lock.  Caller is responsible
 * for linking the returned slab into allocator->slabs under the lock.
 */
static struct evpl_slab *
evpl_allocator_build_slab(struct evpl_allocator *allocator)
{
    struct evpl_slab      *slab;
    struct evpl_framework *framework;
    int                    i;
    int                    hugepages;

    slab            = evpl_zalloc(sizeof(*slab));
    slab->size      = evpl_shared->config->slab_size;
    slab->allocator = allocator;

    /* hugepages is set at create time and only flipped 1->0 inside this
     * function under fallback.  Reading without the lock is fine; the
     * worst case is two threads racing the same fallback, both
     * subsequently succeeding via valloc.
     */
    hugepages = allocator->hugepages;

 again:

    if (hugepages) {

        slab->data = mmap(NULL, evpl_shared->config->slab_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);

        if (slab->data == MAP_FAILED) {
            evpl_core_info("Could not allocate huge pages, disabling...");
            allocator->hugepages = 0;
            hugepages            = 0;
            goto again;
        }

        slab->hugepages = 1;
    } else {

        slab->data = evpl_valloc(evpl_shared->config->slab_size,
                                 evpl_shared->config->page_size);

    }

    /* Pre-fault every page so consumers don't pay first-touch fault
     * latency in the IO hot path.  This runs in a preallocator thread
     * (or the inline-fallback caller), never on the steady-state hot
     * path.
     */
    memset(slab->data, 0, slab->size);

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

    return slab;
} /* evpl_allocator_build_slab */

/* Carve a built slab into buffers and link both into the allocator.
 * Caller MUST hold allocator->lock.  Returns the number of buffers
 * added to free_buffers.
 */
static int
evpl_allocator_install_slab(
    struct evpl_allocator *allocator,
    struct evpl_slab      *slab)
{
    struct evpl_global_config *config = evpl_shared->config;
    struct evpl_buffer        *buffer;
    int                        num_buffers, i;

    LL_PREPEND(allocator->slabs, slab);

    num_buffers   = slab->size / config->buffer_size;
    slab->buffers = evpl_zalloc(num_buffers * sizeof(*slab->buffers));

    for (i = 0; i < num_buffers; i++) {
        buffer           = &slab->buffers[i];
        buffer->data     = slab->data + i * config->buffer_size;
        buffer->ref.slab = slab;
        buffer->used     = 0;
        buffer->size     = config->buffer_size;

        slab->refcnt++;

        LL_PREPEND(allocator->free_buffers, buffer);
    }

    allocator->free_buffer_count += num_buffers;

    return num_buffers;
} /* evpl_allocator_install_slab */

/* Legacy entry point used by evpl_allocator_alloc_slab (whole-slab
 * out-loan for XLIO's mem_alloc callback).  Builds and links a slab
 * but does not carve it into buffers.  Caller MUST hold the lock.
 */
static struct evpl_slab *
evpl_allocator_create_slab(struct evpl_allocator *allocator)
{
    struct evpl_slab *slab = evpl_allocator_build_slab(allocator);

    LL_PREPEND(allocator->slabs, slab);
    return slab;
} /* evpl_allocator_create_slab */

/* Decide how many slab-creation requests to issue based on the
 * current deficit.  Caller MUST hold allocator->lock.
 */
static void
evpl_allocator_maybe_signal(struct evpl_allocator *allocator)
{
    int deficit_buffers;
    int deficit_slabs;
    int in_flight;
    int max_new, wake;

    if (allocator->num_prealloc_threads == 0) {
        return;
    }

    in_flight       = allocator->outstanding_slabs * allocator->buffers_per_slab;
    deficit_buffers = allocator->target_buffers -
        allocator->free_buffer_count - in_flight;

    if (deficit_buffers <= 0) {
        return;
    }

    deficit_slabs = (deficit_buffers + allocator->buffers_per_slab - 1) /
        allocator->buffers_per_slab;

    /* Cap concurrent in-flight slabs at the thread count — extra
     * signals would just queue producer wakeups with no thread to
     * service them.
     */
    max_new = allocator->num_prealloc_threads - allocator->outstanding_slabs;

    if (max_new <= 0) {
        return;
    }

    wake = deficit_slabs < max_new ? deficit_slabs : max_new;

    allocator->outstanding_slabs += wake;
    allocator->wakeup_credits    += wake;

    if (allocator->m_outstanding_slabs) {
        prometheus_gauge_set(allocator->m_outstanding_slabs,
                             allocator->outstanding_slabs);
    }

    while (wake-- > 0) {
        pthread_cond_signal(&allocator->producer_cv);
    }
} /* evpl_allocator_maybe_signal */

static void *
evpl_allocator_prealloc_thread(void *arg)
{
    struct evpl_allocator *allocator = arg;
    struct evpl_slab      *slab;

    for ( ; ;) {

        pthread_mutex_lock(&allocator->lock);

        while (allocator->wakeup_credits == 0 && !allocator->shutdown) {
            pthread_cond_wait(&allocator->producer_cv, &allocator->lock);
        }

        if (allocator->shutdown) {
            pthread_mutex_unlock(&allocator->lock);
            break;
        }

        allocator->wakeup_credits--;

        pthread_mutex_unlock(&allocator->lock);

        /* Heavy lifting (mmap + ibv_reg_mr) outside the lock so
         * consumers can keep draining free_buffers in parallel.
         */
        slab = evpl_allocator_build_slab(allocator);

        pthread_mutex_lock(&allocator->lock);

        evpl_allocator_install_slab(allocator, slab);

        allocator->outstanding_slabs--;

        if (allocator->m_slabs_prealloc) {
            prometheus_counter_increment(allocator->m_slabs_prealloc);
        }
        if (allocator->m_outstanding_slabs) {
            prometheus_gauge_set(allocator->m_outstanding_slabs,
                                 allocator->outstanding_slabs);
        }
        if (allocator->m_free_buffers) {
            prometheus_gauge_set(allocator->m_free_buffers,
                                 allocator->free_buffer_count);
        }
        if (allocator->m_total_slabs) {
            prometheus_gauge_add(allocator->m_total_slabs, 1);
        }

        pthread_cond_broadcast(&allocator->consumer_cv);

        pthread_mutex_unlock(&allocator->lock);
    }

    return NULL;
} /* evpl_allocator_prealloc_thread */

struct evpl_buffer *
evpl_allocator_alloc(struct evpl_allocator *allocator)
{
    struct evpl_buffer *buffer;
    struct evpl_slab   *slab;
    struct timespec     wait_start, wait_end;
    int                 did_wait = 0;

    pthread_mutex_lock(&allocator->lock);

    /* Top up the pool first; any deficit (including from this
     * allocation about to happen) wakes a producer.
     */
    evpl_allocator_maybe_signal(allocator);

    while (!allocator->free_buffers) {

        if (allocator->num_prealloc_threads > 0) {
            /* Wait for a producer to deliver — heavy work is off the
             * hot path entirely.
             */
            if (!did_wait) {
                did_wait = 1;
                clock_gettime(CLOCK_MONOTONIC, &wait_start);
            }
            pthread_cond_wait(&allocator->consumer_cv, &allocator->lock);
            continue;
        }

        /* No pool configured — fall back to inline slab create. */
        pthread_mutex_unlock(&allocator->lock);
        slab = evpl_allocator_build_slab(allocator);
        pthread_mutex_lock(&allocator->lock);
        evpl_allocator_install_slab(allocator, slab);
        if (allocator->m_slabs_inline) {
            prometheus_counter_increment(allocator->m_slabs_inline);
        }
        if (allocator->m_total_slabs) {
            prometheus_gauge_add(allocator->m_total_slabs, 1);
        }
    }

    if (did_wait) {
        clock_gettime(CLOCK_MONOTONIC, &wait_end);
        uint64_t ns = (wait_end.tv_sec - wait_start.tv_sec) * 1000000000ULL +
            (wait_end.tv_nsec - wait_start.tv_nsec);
        if (allocator->m_consumer_waits) {
            prometheus_counter_increment(allocator->m_consumer_waits);
        }
        if (allocator->m_consumer_wait_ns) {
            prometheus_counter_add(allocator->m_consumer_wait_ns, ns);
        }
    }

    buffer = allocator->free_buffers;
    LL_DELETE(allocator->free_buffers, buffer);
    allocator->free_buffer_count--;
    if (allocator->m_free_buffers) {
        prometheus_gauge_set(allocator->m_free_buffers,
                             allocator->free_buffer_count);
    }

    /* Re-check after the consume — if we just dropped below target,
     * fire another wake so the next consumer doesn't have to wait.
     */
    evpl_allocator_maybe_signal(allocator);

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
    allocator->free_buffer_count++;
    if (allocator->m_free_buffers) {
        prometheus_gauge_set(allocator->m_free_buffers,
                             allocator->free_buffer_count);
    }
    pthread_mutex_unlock(&allocator->lock);
} /* evpl_allocator_free */

void *
evpl_allocator_alloc_slab(
    struct evpl_allocator *allocator,
    void                 **slab_private)
{
    struct evpl_slab *slab;

    pthread_mutex_lock(&allocator->lock);
    slab = evpl_allocator_create_slab(allocator);
    /* Whole-slab loanouts (e.g. XLIO mem_alloc callback) count under
     * "inline" since they synchronously stall the caller exactly like
     * an inline alloc fallback would.
     */
    if (allocator->m_slabs_inline) {
        prometheus_counter_increment(allocator->m_slabs_inline);
    }
    if (allocator->m_total_slabs) {
        prometheus_gauge_add(allocator->m_total_slabs, 1);
    }
    pthread_mutex_unlock(&allocator->lock);

    *slab_private = slab;

    return slab->data;

} /* evpl_allocator_alloc_slab */

SYMBOL_EXPORT void
evpl_set_allocator_metrics(const struct evpl_allocator_metrics *m)
{
    struct evpl_allocator *allocator;
    struct evpl_slab      *slab;
    uint64_t               total_slabs = 0;

    __evpl_init();

    allocator = evpl_shared->allocator;

    pthread_mutex_lock(&allocator->lock);

    allocator->m_slabs_inline      = m->slabs_inline;
    allocator->m_slabs_prealloc    = m->slabs_prealloc;
    allocator->m_consumer_waits    = m->consumer_waits;
    allocator->m_consumer_wait_ns  = m->consumer_wait_ns;
    allocator->m_free_buffers      = m->free_buffers;
    allocator->m_outstanding_slabs = m->outstanding_slabs;
    allocator->m_target_buffers    = m->target_buffers;
    allocator->m_total_slabs       = m->total_slabs;

    /* Backfill current state into the gauges so the first scrape
     * shows reality, not zero.
     */
    if (m->free_buffers) {
        prometheus_gauge_set(m->free_buffers, allocator->free_buffer_count);
    }
    if (m->outstanding_slabs) {
        prometheus_gauge_set(m->outstanding_slabs, allocator->outstanding_slabs);
    }
    if (m->target_buffers) {
        prometheus_gauge_set(m->target_buffers, allocator->target_buffers);
    }
    if (m->total_slabs) {
        LL_FOREACH(allocator->slabs, slab)
        {
            total_slabs++;
        }
        prometheus_gauge_set(m->total_slabs, total_slabs);
    }

    pthread_mutex_unlock(&allocator->lock);
} /* evpl_set_allocator_metrics */


void *
evpl_memory_framework_private(
    const struct evpl_iovec *iov,
    int                      framework_id)
{
    struct evpl_iovec_ref *ref = evpl_iovec_get_ref(iov);

    return ref->slab->framework_private[framework_id];
} // evpl_buffer_framework_private


static void
evpl_buffer_free(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct evpl_buffer *buffer = container_of(ref, struct evpl_buffer, ref);

    if (evpl) {
        /* Park on the releasing thread's shared free list rather than
         * going through the global allocator lock.  Buffers are fungible
         * so it doesn't matter which thread allocated them — what
         * matters is they end up cached somewhere a future alloc on this
         * thread can pick them up lock-free.  Returned to the global
         * allocator at evpl_destroy time.
         */
        LL_PREPEND(evpl->free_shared_buffers, buffer);
    } else {
        /* No evpl context (e.g. during module shutdown) — bypass the
         * cache and go straight to the global allocator.
         */
        evpl_allocator_free(buffer->ref.slab->allocator, buffer);
    }
} /* evpl_buffer_free */


static void
evpl_buffer_free_local(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct evpl_buffer *buffer = container_of(ref, struct evpl_buffer, ref);

    if (evpl) {
        /* Append to the thread-local free list instead of returning to allocator */
        LL_PREPEND(evpl->free_local_buffers, buffer);
    } else {
        /* No evpl context (e.g., during module shutdown), return to allocator */
        evpl_allocator_free(buffer->ref.slab->allocator, buffer);
    }
} /* evpl_buffer_free_local */


struct evpl_buffer *
evpl_buffer_alloc(
    struct evpl *evpl,
    unsigned int flags)
{
    struct evpl_buffer *buffer;

    if (flags & EVPL_IOVEC_FLAG_SHARED) {
        if (evpl && evpl->free_shared_buffers) {
            /* Try thread-local shared cache first (no global lock) */
            buffer = evpl->free_shared_buffers;
            LL_DELETE(evpl->free_shared_buffers, buffer);
        } else {
            buffer = evpl_allocator_alloc(evpl_shared->allocator);
        }
    } else if (evpl && evpl->free_local_buffers) {
        /* For LOCAL allocations, try thread-local free list first (no lock) */
        buffer = evpl->free_local_buffers;
        LL_DELETE(evpl->free_local_buffers, buffer);
    } else {
        /* Go to the global allocator */
        buffer = evpl_allocator_alloc(evpl_shared->allocator);
    }

    buffer->ref.refcnt = 1;
    buffer->ref.flags  = flags;
    buffer->used       = 0;
#ifdef EVPL_IOVEC_TRACE
    buffer->ref.owner_thread = pthread_self();
#endif /* ifdef EVPL_IOVEC_TRACE */

    if (flags & EVPL_IOVEC_FLAG_SHARED) {
        buffer->ref.release = evpl_buffer_free;
    } else {
        buffer->ref.release = evpl_buffer_free_local;
    }

    return buffer;
} /* evpl_buffer_alloc */
