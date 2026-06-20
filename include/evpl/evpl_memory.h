// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_memory.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

#include <stdint.h>
#include <stdatomic.h>

/*
 * iovec flags - stored in evpl_iovec_ref.flags
 * 0 (default): Single-threaded access, uses non-atomic refcnt operations
 * EVPL_IOVEC_FLAG_SHARED: Multi-threaded access, uses atomic refcnt operations
 * EVPL_IOVEC_FLAG_GLOBAL: User-managed lifetime.  Internal refcount inc/dec
 *   (evpl_iovec_ref_incr / evpl_iovec_ref_release) are silent no-ops, so the
 *   library never frees the buffer; only the user's explicit evpl_iovec_release
 *   actually returns it to its pool.  See evpl_iovec_alloc_global().  The user
 *   owns exactly one reference and must release it exactly once -- clones are
 *   non-owning borrows that must NOT be released individually.
 */
#define EVPL_IOVEC_FLAG_SHARED 1
#define EVPL_IOVEC_FLAG_GLOBAL 2

#ifdef EVPL_IOVEC_TRACE
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define evpl_iovec_trace_abort(fmt, ...) \
        do { \
            evpl_abort("core", __FILE__, __LINE__, "EVPL IOVEC TRACE ABORT: " fmt "\n", ## __VA_ARGS__); \
        } while (0)

#define evpl_iovec_trace_abort_if(cond, ...) \
        do { \
            if (cond) { \
                evpl_iovec_trace_abort(__VA_ARGS__); \
            } \
        } while (0)

#endif /* ifdef EVPL_IOVEC_TRACE */

#define evpl_memory_abort_if(cond, ...) \
        do { \
            if (cond) { \
                evpl_abort("core", __FILE__, __LINE__, __VA_ARGS__); \
            } \
        } while (0)

struct evpl_iovec_ref;
struct evpl;

struct evpl_iovec_ref {
    union {
        unsigned int refcnt;         /* LOCAL type: non-atomic */
        atomic_uint  refcnt_atomic;  /* SHARED type: atomic */
    };
    unsigned int      flags;
    struct evpl_slab *slab;
    void              (*release)(
        struct evpl           *evpl,
        struct evpl_iovec_ref *ref);
#ifdef EVPL_IOVEC_TRACE
    pthread_t         owner_thread;  /* Thread that allocated this ref (LOCAL only) */
#endif // ifdef EVPL_IOVEC_TRACE
};

struct evpl_iovec {
    void                  *data;
    unsigned int           length;
    unsigned int           pad;
#ifdef EVPL_IOVEC_PROFILE
    uint32_t               profile_site;
#endif /* EVPL_IOVEC_PROFILE */
    struct evpl_iovec_ref *ref;
};

#ifdef EVPL_IOVEC_TRACE

#define EVPL_IOVEC_CANARY_MAGIC 0xCAFEBABE

struct evpl_iovec_canary {
    unsigned int           magic;
    struct evpl_iovec_ref *real_ref;
    struct evpl_iovec     *owner;
};

static inline struct evpl_iovec_canary *
evpl_iovec_canary_get(const struct evpl_iovec *iovec)
{
    return (struct evpl_iovec_canary *) iovec->ref;
} /* evpl_iovec_canary_get */

static inline struct evpl_iovec_ref *
evpl_iovec_real_ref(const struct evpl_iovec *iovec)
{
    const struct evpl_iovec_canary *canary = evpl_iovec_canary_get(iovec);

    evpl_iovec_trace_abort_if(canary->magic != EVPL_IOVEC_CANARY_MAGIC,
                              "iovec canary magic mismatch: expected 0x%x, got 0x%x",
                              EVPL_IOVEC_CANARY_MAGIC, canary->magic);

    return canary->real_ref;
} /* evpl_iovec_real_ref */

static inline void
evpl_iovec_canary_alloc(
    struct evpl_iovec     *iovec,
    struct evpl_iovec_ref *real_ref)
{
    struct evpl_iovec_canary *canary;

    canary = malloc(sizeof(*canary));
    evpl_iovec_trace_abort_if(!canary, "Failed to allocate iovec canary");

    canary->magic    = EVPL_IOVEC_CANARY_MAGIC;
    canary->real_ref = real_ref;
    canary->owner    = iovec;

    iovec->ref = (struct evpl_iovec_ref *) canary;
} /* evpl_iovec_canary_alloc */

static inline void
evpl_iovec_canary_verify(const struct evpl_iovec *iovec)
{
    struct evpl_iovec_canary *canary = evpl_iovec_canary_get(iovec);

    evpl_iovec_trace_abort_if(canary->magic != EVPL_IOVEC_CANARY_MAGIC,
                              "iovec canary magic mismatch: expected 0x%x, got 0x%x",
                              EVPL_IOVEC_CANARY_MAGIC, canary->magic);
    evpl_iovec_trace_abort_if(canary->owner != iovec,
                              "iovec canary owner mismatch: expected %p, got %p",
                              iovec, canary->owner);
} /* evpl_iovec_canary_verify */

static inline void
evpl_iovec_canary_free(struct evpl_iovec *iovec)
{
    struct evpl_iovec_canary *canary = evpl_iovec_canary_get(iovec);

    evpl_iovec_canary_verify(iovec);

    canary->magic = 0xDEADBEEF;
    canary->owner = NULL;

    free(canary);
} /* evpl_iovec_canary_free */

static inline void
evpl_iovec_canary_move(
    struct evpl_iovec       *dst,
    const struct evpl_iovec *src)
{
    struct evpl_iovec_canary *canary = evpl_iovec_canary_get(dst);

    evpl_iovec_trace_abort_if(canary->magic != EVPL_IOVEC_CANARY_MAGIC,
                              "iovec canary magic mismatch on move: expected 0x%x, got 0x%x",
                              EVPL_IOVEC_CANARY_MAGIC, canary->magic);
    evpl_iovec_trace_abort_if(canary->owner != src,
                              "iovec canary owner mismatch on move: expected %p, got %p",
                              src, canary->owner);

    canary->owner = dst;
} /* evpl_iovec_canary_move */

#endif /* EVPL_IOVEC_TRACE */

#ifdef EVPL_IOVEC_PROFILE
uint32_t evpl_iovec_profile_capture(
    void);
void evpl_iovec_profile_ref(
    uint32_t site);
void evpl_iovec_profile_unref(
    uint32_t site);
void evpl_iovec_profile_dump(
    const char *reason);

static inline void
evpl_iovec_profile_assign(struct evpl_iovec *iovec)
{
    uint32_t site = evpl_iovec_profile_capture();

    iovec->profile_site = site;
    evpl_iovec_profile_ref(site);
} /* evpl_iovec_profile_assign */

static inline void
evpl_iovec_profile_release(struct evpl_iovec *iovec)
{
    evpl_iovec_profile_unref(iovec->profile_site);
    iovec->profile_site = 0;
} /* evpl_iovec_profile_release */

static inline void
evpl_iovec_profile_move(
    struct evpl_iovec *dst,
    struct evpl_iovec *src)
{
    dst->profile_site = src->profile_site;
    src->profile_site = 0;
} /* evpl_iovec_profile_move */
#else /* EVPL_IOVEC_PROFILE */
static inline void evpl_iovec_profile_assign(struct evpl_iovec *iovec) { (void) iovec; }
static inline void evpl_iovec_profile_release(struct evpl_iovec *iovec) { (void) iovec; }
static inline void evpl_iovec_profile_move(
    struct evpl_iovec *dst,
    struct evpl_iovec *src) { (void) dst; (void) src; }
/* dump is defined (as an exported no-op) in iovec_profile.c for this branch,
 * so it is only declared here -- defining it static inline as well would
 * collide with that definition inside the iovec_profile.c translation unit. */
void evpl_iovec_profile_dump(
    const char *reason);
#endif /* EVPL_IOVEC_PROFILE */

int evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    unsigned int       flags,
    struct evpl_iovec *r_iovec);

/*
 * Allocate one whole, DMA/RDMA-registered buffer as a single GLOBAL iovec with
 * a user-managed lifetime (1 iovec : 1 dedicated buffer).  Internal libevpl
 * refcount operations on it are no-ops; the caller owns it and must free it
 * exactly once with evpl_iovec_release().  Clones of it are non-owning borrows.
 * Do not sub-carve or otherwise share the buffer behind a GLOBAL iovec.
 */
void evpl_iovec_alloc_global(
    struct evpl       *evpl,
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
evpl_iovec_ref_release(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    unsigned int prev;

    if (ref->flags & EVPL_IOVEC_FLAG_GLOBAL) {
        /* User-managed lifetime: internal release never frees.  Only the
         * public evpl_iovec_release() (the owner's explicit free) frees it. */
        return;
    }

    if (ref->flags & EVPL_IOVEC_FLAG_SHARED) {
        prev = atomic_fetch_sub_explicit(&ref->refcnt_atomic, 1,
                                         memory_order_release);
    } else {
#ifdef EVPL_IOVEC_TRACE
        evpl_iovec_trace_abort_if(!pthread_equal(pthread_self(), ref->owner_thread),
                                  "evpl_iovec_ref_release called on LOCAL iovec from wrong thread "
                                  "(owner=%lu, caller=%lu)",
                                  (unsigned long) ref->owner_thread,
                                  (unsigned long) pthread_self());
#endif // ifdef EVPL_IOVEC_TRACE
        prev = ref->refcnt--;
    }

    if (prev == 1) {
        ref->release(evpl, ref);
    }
} /* evpl_iovec_ref_release */

/*
 * Internal release: drop a library-held reference.  For LOCAL/SHARED this
 * decrements (and frees at zero); for GLOBAL it is a no-op (the borrow was
 * never counted).  All libevpl-internal release sites (send/recv rings, I/O
 * completions, teardown) must use this -- NOT the public evpl_iovec_release --
 * so that a user-owned GLOBAL buffer is never freed out from under the user.
 */
static inline void
evpl_iovec_release_internal(
    struct evpl       *evpl,
    struct evpl_iovec *iovec)
{
    evpl_iovec_profile_release(iovec);
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(iovec);

    evpl_iovec_canary_free(iovec);
    evpl_iovec_ref_release(evpl, real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_ref_release(evpl, iovec->ref);
#endif // ifdef EVPL_IOVEC_TRACE
} /* evpl_iovec_release_internal */

static inline void
evpl_iovecs_release_internal(
    struct evpl       *evpl,
    struct evpl_iovec *iov,
    int                niov)
{
    for (int i = 0; i < niov; i++) {
        evpl_iovec_release_internal(evpl, &iov[i]);
    }
} /* evpl_iovecs_release_internal */

/*
 * Public release: the application's way to drop its reference.  For LOCAL/
 * SHARED it is identical to the internal release.  For a GLOBAL iovec it is
 * the owner's explicit free -- it bypasses the (inert) refcount and returns
 * the buffer to its pool directly, resetting refcnt to 0 so the allocator's
 * destroy-time leak check sees a clean buffer.  The owner must call this
 * exactly once per buffer; clones are non-owning borrows and must not be
 * released here.
 */
static inline void
evpl_iovec_release(
    struct evpl       *evpl,
    struct evpl_iovec *iovec)
{
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *ref = evpl_iovec_real_ref(iovec);
#else // ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *ref = iovec->ref;
#endif // ifdef EVPL_IOVEC_TRACE

    if (ref->flags & EVPL_IOVEC_FLAG_GLOBAL) {
        evpl_iovec_profile_release(iovec);
#ifdef EVPL_IOVEC_TRACE
        evpl_iovec_canary_free(iovec);
#endif // ifdef EVPL_IOVEC_TRACE
        ref->refcnt = 0;
        ref->release(evpl, ref);
        iovec->data = NULL;
        return;
    }

    evpl_iovec_release_internal(evpl, iovec);
} /* evpl_iovec_release */

static inline void
evpl_iovecs_release(
    struct evpl       *evpl,
    struct evpl_iovec *iov,
    int                niov)
{
    for (int i = 0; i < niov; i++) {
        evpl_iovec_release(evpl, &iov[i]);
    }
} /* evpl_iovecs_release */

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
evpl_iovec_ref_incr(struct evpl_iovec_ref *ref)
{
    if (ref->flags & EVPL_IOVEC_FLAG_GLOBAL) {
        /* User-managed lifetime: borrows are not counted. */
        return;
    }

    if (ref->flags & EVPL_IOVEC_FLAG_SHARED) {
        atomic_fetch_add_explicit(&ref->refcnt_atomic, 1, memory_order_relaxed);
    } else {
#ifdef EVPL_IOVEC_TRACE
        evpl_iovec_trace_abort_if(!pthread_equal(pthread_self(), ref->owner_thread),
                                  "evpl_iovec_ref_incr called on LOCAL iovec from wrong thread "
                                  "(owner=%lu, caller=%lu)",
                                  (unsigned long) ref->owner_thread,
                                  (unsigned long) pthread_self());
#endif // ifdef EVPL_IOVEC_TRACE
        ref->refcnt++;
    }
} /* evpl_iovec_ref_incr */

static inline void
evpl_iovec_take_ref(
    struct evpl_iovec     *dst,
    struct evpl_iovec_ref *src)
{
    evpl_iovec_ref_incr(src);
#ifdef EVPL_IOVEC_TRACE
    evpl_iovec_canary_alloc(dst, src);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = src;
#endif // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_profile_assign(dst);
} /* evpl_iovec_take_ref */

/*
 * Let dst be a cloned reference to a portion of src
 */
static inline void
evpl_iovec_clone_segment(
    struct evpl_iovec       *dst,
    const struct evpl_iovec *src,
    unsigned int             offset,
    unsigned int             length)
{
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(src);

    evpl_iovec_ref_incr(real_ref);
    evpl_iovec_canary_alloc(dst, real_ref);
    evpl_iovec_profile_assign(dst);
#else // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_take_ref(dst, src->ref);
#endif // ifdef EVPL_IOVEC_TRACE

    if (offset + length > src->length) {
        evpl_abort("core", __FILE__, __LINE__, "offset + length is greater than src->length");
    }

    dst->data   = src->data + offset;
    dst->length = length;
} /* evpl_iovec_addref_to */

static inline void
evpl_iovec_clone(
    struct evpl_iovec *dst,
    struct evpl_iovec *src)
{
    dst->data   = src->data;
    dst->length = src->length;
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(src);

    evpl_iovec_ref_incr(real_ref);
    evpl_iovec_canary_alloc(dst, real_ref);
    evpl_iovec_profile_assign(dst);
#else // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_take_ref(dst, src->ref);
#endif // ifdef EVPL_IOVEC_TRACE
} /* evpl_iovec_clone */

static inline void
evpl_iovec_move_segment(
    struct evpl_iovec *dst,
    struct evpl_iovec *src,
    unsigned int       offset,
    unsigned int       length)
{
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(src);


    evpl_iovec_canary_free(src);

    dst->data   = src->data;
    dst->length = src->length;
    evpl_iovec_canary_alloc(dst, real_ref);
    evpl_iovec_profile_move(dst, src);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = src->ref;
    evpl_iovec_profile_move(dst, src);
#endif // ifdef EVPL_IOVEC_TRACE

    if (offset + length > src->length) {
        evpl_abort("core", __FILE__, __LINE__, "offset + length is greater than src->length");
    }

    dst->data   = src->data + offset;
    dst->length = length;
} /* evpl_iovec_move_segment */

/*
 * Move ownership of an iovec from src to dst.
 * The src iovec should not be used after this call.
 */
static inline void
evpl_iovec_move(
    struct evpl_iovec *dst,
    struct evpl_iovec *src)
{
    evpl_memory_abort_if(!dst || !src, "evpl_iovec_move: NULL pointer");
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(src);

    evpl_iovec_canary_free(src);

    dst->data   = src->data;
    dst->length = src->length;
    evpl_iovec_canary_alloc(dst, real_ref);
    evpl_iovec_profile_move(dst, src);
#else // ifdef EVPL_IOVEC_TRACE
    *dst = *src;
    evpl_iovec_profile_move(dst, src);
#endif // ifdef EVPL_IOVEC_TRACE
    /* Invalidate source to indicate ownership was transferred */
    src->data = NULL;
} /* evpl_iovec_move */

/*
 * Assign a reference to an iovec.
 * In tracing mode, this allocates a new canary.
 * Used when initializing an iovec with a buffer reference.
 */
static inline void
evpl_iovec_set_ref(
    struct evpl_iovec     *iovec,
    struct evpl_iovec_ref *ref)
{
#ifdef EVPL_IOVEC_TRACE
    evpl_iovec_canary_alloc(iovec, ref);
#else // ifdef EVPL_IOVEC_TRACE
    iovec->ref = ref;
#endif // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_profile_assign(iovec);
} /* evpl_iovec_set_ref */

/*
 * Get the real evpl_iovec_ref from an iovec.
 * In tracing mode, this extracts it from the canary.
 */
static inline struct evpl_iovec_ref *
evpl_iovec_get_ref(const struct evpl_iovec *iovec)
{
#ifdef EVPL_IOVEC_TRACE
    return evpl_iovec_real_ref(iovec);
#else // ifdef EVPL_IOVEC_TRACE
    return iovec->ref;
#endif // ifdef EVPL_IOVEC_TRACE
} /* evpl_iovec_get_ref */

uint64_t evpl_get_slab_size(
    void);

void *
evpl_slab_alloc(
    void **slab_private);

/* The allocator's diagnostic counters and gauges are registered on
 * libevpl's internal metrics registry at startup and exposed through
 * evpl_metrics_scrape() (see evpl_core.h).  No caller registration is
 * required.
 */