// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE

#include <execinfo.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/evpl.h"
#include "core/logging.h"
#include "core/macros.h"
#include "evpl/evpl.h"

#ifndef EVPL_IOVEC_PROFILE_MAX_SITES
#define EVPL_IOVEC_PROFILE_MAX_SITES 16384
#endif /* EVPL_IOVEC_PROFILE_MAX_SITES */

#ifndef EVPL_IOVEC_PROFILE_STACK_DEPTH
#define EVPL_IOVEC_PROFILE_STACK_DEPTH 12
#endif /* EVPL_IOVEC_PROFILE_STACK_DEPTH */

#ifndef EVPL_IOVEC_PROFILE_TOP
#define EVPL_IOVEC_PROFILE_TOP 40
#endif /* EVPL_IOVEC_PROFILE_TOP */

#ifdef EVPL_IOVEC_PROFILE

struct evpl_iovec_profile_site {
    uint64_t live_refs;
    uint64_t total_refs;
    uint64_t hash;
    int      depth;
    void    *frames[EVPL_IOVEC_PROFILE_STACK_DEPTH];
};

static pthread_mutex_t                evpl_iovec_profile_lock = PTHREAD_MUTEX_INITIALIZER;
static struct evpl_iovec_profile_site evpl_iovec_profile_sites[EVPL_IOVEC_PROFILE_MAX_SITES];
static uint64_t                       evpl_iovec_profile_dropped;
static int                            evpl_iovec_profile_enabled = -1;

static int
evpl_iovec_profile_is_enabled(void)
{
    const char *env;
    int         enabled = __atomic_load_n(&evpl_iovec_profile_enabled, __ATOMIC_RELAXED);

    if (enabled >= 0) {
        return enabled;
    }

    env = getenv("EVPL_IOVEC_PROFILE");
    if (env && (!strcmp(env, "0") || !strcasecmp(env, "false") || !strcasecmp(env, "off"))) {
        enabled = 0;
    } else {
        enabled = 1;
    }

    __atomic_store_n(&evpl_iovec_profile_enabled, enabled, __ATOMIC_RELAXED);
    return enabled;
} /* evpl_iovec_profile_is_enabled */

static uint64_t
evpl_iovec_profile_hash(void **frames, int depth)
{
    uint64_t h = 1469598103934665603ULL;
    int      i;

    for (i = 0; i < depth; i++) {
        uintptr_t v = (uintptr_t) frames[i];
        h ^= v;
        h *= 1099511628211ULL;
    }

    return h ? h : 1;
} /* evpl_iovec_profile_hash */

static int
evpl_iovec_profile_same(const struct evpl_iovec_profile_site *site,
                         uint64_t                                  hash,
                         void                                    **frames,
                         int                                       depth)
{
    return site->hash == hash && site->depth == depth &&
           memcmp(site->frames, frames, depth * sizeof(void *)) == 0;
} /* evpl_iovec_profile_same */

SYMBOL_EXPORT uint32_t
evpl_iovec_profile_capture(void)
{
    void    *raw[EVPL_IOVEC_PROFILE_STACK_DEPTH + 4];
    void    *frames[EVPL_IOVEC_PROFILE_STACK_DEPTH];
    int      raw_depth, depth, i, slot;
    uint64_t hash;

    if (!evpl_iovec_profile_is_enabled()) {
        return 0;
    }

    raw_depth = backtrace(raw, EVPL_IOVEC_PROFILE_STACK_DEPTH + 4);
    if (raw_depth <= 2) {
        return 0;
    }

    depth = raw_depth - 2;
    if (depth > EVPL_IOVEC_PROFILE_STACK_DEPTH) {
        depth = EVPL_IOVEC_PROFILE_STACK_DEPTH;
    }

    for (i = 0; i < depth; i++) {
        frames[i] = raw[i + 2];
    }

    hash = evpl_iovec_profile_hash(frames, depth);

    pthread_mutex_lock(&evpl_iovec_profile_lock);

    slot = (int) (hash % EVPL_IOVEC_PROFILE_MAX_SITES);
    for (i = 0; i < EVPL_IOVEC_PROFILE_MAX_SITES; i++) {
        struct evpl_iovec_profile_site *site = &evpl_iovec_profile_sites[slot];

        if (site->hash == 0) {
            site->hash  = hash;
            site->depth = depth;
            memcpy(site->frames, frames, depth * sizeof(void *));
            pthread_mutex_unlock(&evpl_iovec_profile_lock);
            return (uint32_t) slot + 1;
        }

        if (evpl_iovec_profile_same(site, hash, frames, depth)) {
            pthread_mutex_unlock(&evpl_iovec_profile_lock);
            return (uint32_t) slot + 1;
        }

        slot++;
        if (slot == EVPL_IOVEC_PROFILE_MAX_SITES) {
            slot = 0;
        }
    }

    evpl_iovec_profile_dropped++;
    pthread_mutex_unlock(&evpl_iovec_profile_lock);
    return 0;
} /* evpl_iovec_profile_capture */

SYMBOL_EXPORT void
evpl_iovec_profile_ref(uint32_t site_id)
{
    struct evpl_iovec_profile_site *site;

    if (!site_id) {
        return;
    }

    site = &evpl_iovec_profile_sites[site_id - 1];
    __atomic_add_fetch(&site->live_refs, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&site->total_refs, 1, __ATOMIC_RELAXED);
} /* evpl_iovec_profile_ref */

SYMBOL_EXPORT void
evpl_iovec_profile_unref(uint32_t site_id)
{
    struct evpl_iovec_profile_site *site;

    if (!site_id) {
        return;
    }

    site = &evpl_iovec_profile_sites[site_id - 1];
    __atomic_sub_fetch(&site->live_refs, 1, __ATOMIC_RELAXED);
} /* evpl_iovec_profile_unref */

static int
evpl_iovec_profile_pick_top(int *top, uint64_t *total_live, uint64_t *total_refs)
{
    int count = 0;
    int i, j;

    *total_live = 0;
    *total_refs = 0;

    for (i = 0; i < EVPL_IOVEC_PROFILE_MAX_SITES; i++) {
        struct evpl_iovec_profile_site *site = &evpl_iovec_profile_sites[i];
        uint64_t live = __atomic_load_n(&site->live_refs, __ATOMIC_RELAXED);
        uint64_t total = __atomic_load_n(&site->total_refs, __ATOMIC_RELAXED);

        if (!site->hash) {
            continue;
        }

        *total_live += live;
        *total_refs += total;

        if (!live) {
            continue;
        }

        for (j = 0; j < count; j++) {
            if (live > __atomic_load_n(&evpl_iovec_profile_sites[top[j]].live_refs, __ATOMIC_RELAXED)) {
                break;
            }
        }

        if (j >= EVPL_IOVEC_PROFILE_TOP) {
            continue;
        }

        if (count < EVPL_IOVEC_PROFILE_TOP) {
            count++;
        }

        memmove(&top[j + 1], &top[j], (count - j - 1) * sizeof(top[0]));
        top[j] = i;
    }

    return count;
} /* evpl_iovec_profile_pick_top */

SYMBOL_EXPORT void
evpl_iovec_profile_dump(const char *reason)
{
    int      top[EVPL_IOVEC_PROFILE_TOP];
    int      count, i, j;
    uint64_t total_live, total_refs;

    if (!evpl_iovec_profile_is_enabled()) {
        return;
    }

    pthread_mutex_lock(&evpl_iovec_profile_lock);
    count = evpl_iovec_profile_pick_top(top, &total_live, &total_refs);

    evpl_core_error("EVPL_IOVEC_PROFILE dump reason=%s total_live_refs=%llu total_refs=%llu dropped_sites=%llu",
                    reason ? reason : "unknown",
                    (unsigned long long) total_live,
                    (unsigned long long) total_refs,
                    (unsigned long long) evpl_iovec_profile_dropped);

    for (i = 0; i < count; i++) {
        struct evpl_iovec_profile_site *site = &evpl_iovec_profile_sites[top[i]];
        uint64_t live = __atomic_load_n(&site->live_refs, __ATOMIC_RELAXED);
        uint64_t total = __atomic_load_n(&site->total_refs, __ATOMIC_RELAXED);
        char   **symbols;

        evpl_core_error("EVPL_IOVEC_PROFILE site=%d live_refs=%llu total_refs=%llu depth=%d",
                        top[i] + 1,
                        (unsigned long long) live,
                        (unsigned long long) total,
                        site->depth);

        symbols = backtrace_symbols(site->frames, site->depth);
        if (symbols) {
            for (j = 0; j < site->depth; j++) {
                evpl_core_error("EVPL_IOVEC_PROFILE site=%d frame=%d %s",
                                top[i] + 1, j, symbols[j]);
            }
            free(symbols);
        } else {
            for (j = 0; j < site->depth; j++) {
                evpl_core_error("EVPL_IOVEC_PROFILE site=%d frame=%d %p",
                                top[i] + 1, j, site->frames[j]);
            }
        }
    }

    pthread_mutex_unlock(&evpl_iovec_profile_lock);
} /* evpl_iovec_profile_dump */

#else /* EVPL_IOVEC_PROFILE */

SYMBOL_EXPORT uint32_t
evpl_iovec_profile_capture(void)
{
    return 0;
} /* evpl_iovec_profile_capture */

SYMBOL_EXPORT void
evpl_iovec_profile_ref(uint32_t site)
{
    (void) site;
} /* evpl_iovec_profile_ref */

SYMBOL_EXPORT void
evpl_iovec_profile_unref(uint32_t site)
{
    (void) site;
} /* evpl_iovec_profile_unref */

SYMBOL_EXPORT void
evpl_iovec_profile_dump(const char *reason)
{
    (void) reason;
} /* evpl_iovec_profile_dump */

#endif /* EVPL_IOVEC_PROFILE */
