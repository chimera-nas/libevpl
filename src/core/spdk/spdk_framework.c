// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * EVPL_FRAMEWORK_SPDK: registers libevpl's slab buffers with SPDK's memory
 * translation (spdk_mem_register) so evpl iovecs are DMA-safe for SPDK
 * NVMe/bdev I/O in the host application.
 *
 * Guest-mode contract: the host owns the SPDK env; this framework never
 * initializes or finalizes it.  The framework is attached lazily by the
 * first evpl_create() under EVPL_CORE_MECH_SPDK -- the one point where a
 * live host env is guaranteed -- and evpl_allocator_reregister then walks
 * every existing slab through register_memory.
 *
 * Slabs are 2 MiB-aligned when SPDK support is compiled in (see
 * evpl_shared_init), which satisfies every SPDK release; v25.09 itself only
 * requires 4 KiB alignment, so spdk_mem_register's return code is treated as
 * authoritative rather than pre-asserting an alignment here.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <spdk/env.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/protocol.h"
#include "core/evpl_shared.h"
#include "core/spdk/spdk_sock_common.h"

#define evpl_spdk_error(...) evpl_error("spdk", __FILE__, __LINE__, \
                                        __VA_ARGS__)
#define evpl_spdk_abort_if(cond, ...) \
        evpl_abort_if(cond, "spdk", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_spdk_shared {
    int attached;
};

struct evpl_spdk_memreg {
    void  *vaddr;
    size_t len;
};

static void *
evpl_spdk_init(void)
{
    struct evpl_spdk_shared *shared;

    /* Only reached when something attaches the framework (first SPDK-mode
     * evpl_create), so a loud failure here always indicates a host that did
     * not bring up the SPDK env. */
    evpl_spdk_abort_if(spdk_env_get_core_count() == 0,
                       "SPDK framework attach requires the host application to "
                       "have initialized the SPDK env");

    shared = evpl_zalloc(sizeof(*shared));

    shared->attached = 1;

    return shared;
} /* evpl_spdk_init */

static void
evpl_spdk_cleanup(void *private_data)
{
    /* Never spdk_env_fini/spdk_thread_lib_fini: the host owns them. */
    evpl_free(private_data);
} /* evpl_spdk_cleanup */

static void *
evpl_spdk_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_spdk_thread *ctx;

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->shared     = private_data;
    ctx->evpl       = evpl;
    ctx->max_active = 256;
    ctx->active     = evpl_zalloc(ctx->max_active * sizeof(*ctx->active));

    /* The sock group, poll and interrupt registration are created lazily by
     * spdk/tcp.c on first socket use. */
    return ctx;
} /* evpl_spdk_create */

static void
evpl_spdk_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_spdk_thread *ctx = private_data;

    evpl_spdk_sock_thread_destroy(evpl, ctx);

    evpl_free(ctx->active);
    evpl_free(ctx);
} /* evpl_spdk_destroy */

static void *
evpl_spdk_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *thread_private)
{
    struct evpl_spdk_memreg *reg;
    int                      rc;

    /* evpl_allocator_reregister re-walks every slab on each late framework
     * attach; an already-registered slab keeps its token. */
    if (buffer_private) {
        return buffer_private;
    }

    rc = spdk_mem_register(buffer, size);

    evpl_spdk_abort_if(rc,
                       "spdk_mem_register(%p, %d) failed: %s "
                       "(slabs must be page-aligned; older SPDK releases "
                       "require 2 MiB alignment)",
                       buffer, size, strerror(-rc));

    reg = evpl_zalloc(sizeof(*reg));

    reg->vaddr = buffer;
    reg->len   = (size_t) size;

    return reg;
} /* evpl_spdk_register_memory */

static void
evpl_spdk_unregister_memory(
    void *buffer_private,
    void *thread_private)
{
    struct evpl_spdk_memreg *reg = buffer_private;
    int                      rc;

    if (!reg) {
        return;
    }

    /* Runs from evpl_cleanup at atexit, which can be after the host has
     * finalized its SPDK env; failure is logged, not fatal, and process
     * exit reclaims any remaining DMA mappings. */
    rc = spdk_mem_unregister(reg->vaddr, reg->len);

    if (rc) {
        evpl_spdk_error("spdk_mem_unregister(%p, %zu) failed: %s",
                        reg->vaddr, reg->len, strerror(-rc));
    }

    evpl_free(reg);
} /* evpl_spdk_unregister_memory */

struct evpl_framework evpl_framework_spdk = {
    .id                = EVPL_FRAMEWORK_SPDK,
    .name              = "spdk",
    .init              = evpl_spdk_init,
    .cleanup           = evpl_spdk_cleanup,
    .create            = evpl_spdk_create,
    .destroy           = evpl_spdk_destroy,
    .register_memory   = evpl_spdk_register_memory,
    .unregister_memory = evpl_spdk_unregister_memory,
};
