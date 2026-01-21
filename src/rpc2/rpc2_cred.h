// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <urcu.h>
#include <urcu/urcu-memb.h>

#include "core/macros.h"
#include "rpc2_xdr.h"

/*
 * Maximum number of supplementary groups in AUTH_SYS credentials.
 * Per RFC 1831, this is limited to 16.
 */
#define EVPL_RPC2_AUTH_SYS_MAX_GIDS 16

/*
 * RPC2 credential structure.
 *
 * This structure holds the parsed authentication credentials from an
 * incoming RPC call. It supports AUTH_NONE and AUTH_SYS flavors.
 * Each credential is assigned a unique 64-bit key for caching.
 *
 * For AUTH_SYS, the authsys struct uses simple C types. The gids pointer
 * is managed externally:
 * - Server side: allocated by dbuf during unmarshalling
 * - Client side: points directly to the caller's credential storage
 */
struct evpl_rpc2_cred {
    auth_flavor            flavor;
    uint64_t               key;
    struct evpl_rpc2_cred *next;

    struct {
        uint32_t    uid;
        uint32_t    gid;
        uint32_t    num_gids;
        uint32_t   *gids;
        const char *machinename;
        int         machinename_len;
    } authsys;

    struct rcu_head rcu;
};

/*
 * Cred cache shard structure.
 *
 * Each shard has its own lock, counter, and linked list of entries.
 * Threads cycle through shards using a rotor to distribute load.
 */
struct evpl_rpc2_cred_cache_shard {
    pthread_mutex_t        lock;
    uint32_t               next_id;
    struct evpl_rpc2_cred *entries;
};

/*
 * Cred cache structure.
 *
 * A sharded, RCU-protected cache mapping 64-bit keys to credentials.
 * The cache uses power-of-2 sizing for efficient indexing.
 */
struct evpl_rpc2_cred_cache {
    uint32_t                           num_shards;
    uint32_t                           num_shards_mask;
    uint8_t                            num_shards_bits;
    struct evpl_rpc2_cred_cache_shard *shards;
};

/*
 * Create a credential cache.
 *
 * @param num_shards_bits Log2 of the number of shards
 * @return Newly allocated cache, or NULL on failure
 */
static inline struct evpl_rpc2_cred_cache *
evpl_rpc2_cred_cache_create(uint8_t num_shards_bits)
{
    struct evpl_rpc2_cred_cache       *cache;
    struct evpl_rpc2_cred_cache_shard *shard;
    uint32_t                           i;

    cache = calloc(1, sizeof(*cache));
    if (!cache) {
        return NULL;
    }

    cache->num_shards_bits = num_shards_bits;
    cache->num_shards      = 1U << num_shards_bits;
    cache->num_shards_mask = cache->num_shards - 1;

    cache->shards = calloc(cache->num_shards, sizeof(*cache->shards));
    if (!cache->shards) {
        free(cache);
        return NULL;
    }

    for (i = 0; i < cache->num_shards; i++) {
        shard          = &cache->shards[i];
        shard->next_id = 0;
        shard->entries = NULL;

        pthread_mutex_init(&shard->lock, NULL);
    }

    return cache;
}

/*
 * Free a credential via RCU callback.
 */
static inline void
evpl_rpc2_cred_free_rcu(struct rcu_head *head)
{
    struct evpl_rpc2_cred *cred = container_of(head, struct evpl_rpc2_cred, rcu);

    free(cred);
}

/*
 * Destroy a credential cache.
 *
 * @param cache The cache to destroy
 */
static inline void
evpl_rpc2_cred_cache_destroy(struct evpl_rpc2_cred_cache *cache)
{
    struct evpl_rpc2_cred_cache_shard *shard;
    struct evpl_rpc2_cred             *cred, *next;
    uint32_t                           i;

    if (!cache) {
        return;
    }

    rcu_barrier();

    for (i = 0; i < cache->num_shards; i++) {
        shard = &cache->shards[i];

        cred = shard->entries;
        while (cred) {
            next = cred->next;
            free(cred);
            cred = next;
        }

        pthread_mutex_destroy(&shard->lock);
    }

    free(cache->shards);
    free(cache);
}

/*
 * Insert a credential into the cache.
 *
 * The credential is assigned a unique key based on the shard index
 * and an incrementing counter. The key encoding is:
 *   key = (counter << num_shards_bits) | shard_index
 *
 * @param cache The credential cache
 * @param rotor Pointer to thread-local rotor for shard selection
 * @param cred The credential to insert (will be modified with key)
 * @return 0 on success, -1 on failure
 */
static inline int
evpl_rpc2_cred_cache_insert(
    struct evpl_rpc2_cred_cache *cache,
    uint32_t                    *rotor,
    struct evpl_rpc2_cred       *cred)
{
    struct evpl_rpc2_cred_cache_shard *shard;
    uint32_t                           shard_idx;
    uint64_t                           key;

    shard_idx = *rotor & cache->num_shards_mask;
    shard     = &cache->shards[shard_idx];

    pthread_mutex_lock(&shard->lock);

    /* Generate unique key: counter shifted left, OR'd with shard index */
    key = ((uint64_t) shard->next_id << cache->num_shards_bits) | shard_idx;
    shard->next_id++;

    cred->key = key;

    /* Insert at head of linked list */
    cred->next     = shard->entries;
    shard->entries = cred;

    pthread_mutex_unlock(&shard->lock);

    /* Advance rotor for next insertion */
    (*rotor)++;

    return 0;
}

/*
 * Lookup a credential by key.
 *
 * @param cache The credential cache
 * @param key The key to look up
 * @return Pointer to credential if found (RCU protected), NULL otherwise
 *
 * Note: Caller must be in an RCU read-side critical section.
 */
static inline struct evpl_rpc2_cred *
evpl_rpc2_cred_cache_lookup(
    struct evpl_rpc2_cred_cache *cache,
    uint64_t                     key)
{
    struct evpl_rpc2_cred_cache_shard *shard;
    struct evpl_rpc2_cred             *cred;
    uint32_t                           shard_idx;

    shard_idx = key & cache->num_shards_mask;
    shard     = &cache->shards[shard_idx];

    cred = rcu_dereference(shard->entries);

    while (cred) {
        if (cred->key == key) {
            return cred;
        }
        cred = rcu_dereference(cred->next);
    }

    return NULL;
}

/*
 * Allocate and initialize a credential structure.
 *
 * @return Newly allocated credential, or NULL on failure
 */
static inline struct evpl_rpc2_cred *
evpl_rpc2_cred_alloc(void)
{
    return calloc(1, sizeof(struct evpl_rpc2_cred));
}

/*
 * Initialize a credential from AUTH_SYS parameters.
 *
 * Converts from the XDR authsys_parms structure to the simple C types
 * used in evpl_rpc2_cred. The gids and machinename pointers are copied
 * directly (they point to dbuf-allocated storage from unmarshalling).
 *
 * @param cred The credential to initialize
 * @param parms The authsys_parms structure from XDR unmarshalling
 */
static inline void
evpl_rpc2_cred_init_authsys(
    struct evpl_rpc2_cred      *cred,
    const struct authsys_parms *parms)
{
    cred->flavor = AUTH_SYS;

    cred->authsys.uid             = parms->uid;
    cred->authsys.gid             = parms->gid;
    cred->authsys.num_gids        = parms->num_gids;
    cred->authsys.gids            = parms->gids;
    cred->authsys.machinename     = parms->machinename.str;
    cred->authsys.machinename_len = parms->machinename.len;

    /* Clamp gids count to max allowed */
    if (cred->authsys.num_gids > EVPL_RPC2_AUTH_SYS_MAX_GIDS) {
        cred->authsys.num_gids = EVPL_RPC2_AUTH_SYS_MAX_GIDS;
    }
}
