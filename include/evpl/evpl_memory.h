// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_memory.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

#include <stdint.h>

#ifdef EVPL_IOVEC_TRACE
#include <stdlib.h>
#include <stdio.h>

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

struct evpl_iovec_ref;

struct evpl_iovec_ref {
    unsigned int      refcnt;
    unsigned int      flags;
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

/*
 * Discard a canary without verification.
 * Used for scratch iovecs whose reference was "moved" (borrowed) to outputs.
 * Does NOT decrement refcount - caller must ensure reference accounting is correct.
 */
static inline void
evpl_iovec_canary_discard(struct evpl_iovec *iovec)
{
    struct evpl_iovec_canary *canary = evpl_iovec_canary_get(iovec);

    evpl_iovec_trace_abort_if(canary->magic != EVPL_IOVEC_CANARY_MAGIC,
                              "iovec canary magic mismatch: expected 0x%x, got 0x%x",
                              EVPL_IOVEC_CANARY_MAGIC, canary->magic);

    canary->magic = 0xDEADBEEF;
    canary->owner = NULL;

    free(canary);
} /* evpl_iovec_canary_discard */

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
evpl_iovec_release(struct evpl_iovec *iovec)
{
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref *real_ref = evpl_iovec_real_ref(iovec);

    evpl_iovec_canary_free(iovec);
    evpl_iovec_ref_release(real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    evpl_iovec_ref_release(iovec->ref);
#endif // ifdef EVPL_IOVEC_TRACE
} /* evpl_iovec_release */

static inline void
evpl_iovecs_release(
    struct evpl_iovec *iov,
    int                niov)
{
    for (int i = 0; i < niov; i++) {
        evpl_iovec_release(&iov[i]);
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
evpl_iovec_take_ref(
    struct evpl_iovec     *dst,
    struct evpl_iovec_ref *src)
{
    src->refcnt++;
#ifdef EVPL_IOVEC_TRACE
    evpl_iovec_canary_alloc(dst, src);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = src;
#endif // ifdef EVPL_IOVEC_TRACE
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

    ++real_ref->refcnt;
    evpl_iovec_canary_alloc(dst, real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = evpl_iovec_take_ref(src->ref);
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

    ++real_ref->refcnt;
    evpl_iovec_canary_alloc(dst, real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = evpl_iovec_take_ref(src->ref);
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
    struct evpl_iovec_ref    *real_ref = evpl_iovec_real_ref(src);
    struct evpl_iovec_canary *canary   = evpl_iovec_canary_get(src);

    /*
     * Only free the source canary if src owns it.
     * If canary->owner != src, this is a borrowed ref (e.g., from XDR move).
     */
    if (canary->owner == src) {
        evpl_iovec_canary_free(src);
    }

    dst->data   = src->data;
    dst->length = src->length;
    evpl_iovec_canary_alloc(dst, real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    dst->ref = src->ref;
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
 * In tracing mode, allocates a new canary for dst. If src owns its canary,
 * the old canary is freed. If src has a borrowed ref (canary owner != src),
 * the canary is left intact and a new one is created for dst.
 */
static inline void
evpl_iovec_move(
    struct evpl_iovec *dst,
    struct evpl_iovec *src)
{
#ifdef EVPL_IOVEC_TRACE
    struct evpl_iovec_ref    *real_ref = evpl_iovec_real_ref(src);
    struct evpl_iovec_canary *canary   = evpl_iovec_canary_get(src);

    /*
     * Only free the source canary if src owns it.
     * If canary->owner != src, this is a borrowed ref (e.g., from XDR move).
     */
    if (canary->owner == src) {
        evpl_iovec_canary_free(src);
    }

    dst->data   = src->data;
    dst->length = src->length;
    evpl_iovec_canary_alloc(dst, real_ref);
#else // ifdef EVPL_IOVEC_TRACE
    *dst = *src;
#endif // ifdef EVPL_IOVEC_TRACE
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