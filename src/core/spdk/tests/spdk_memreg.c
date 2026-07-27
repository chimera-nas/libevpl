// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Validates the EVPL_FRAMEWORK_SPDK memory registration path: the first
 * SPDK-mode evpl_create attaches the framework, every slab is registered
 * with spdk_mem_register as it is built, and slabs are 2 MiB aligned.
 * Verified by allocating an iovec (forcing a slab) on an SPDK evpl thread,
 * then walking SPDK's existing registrations via the notify pass that
 * spdk_mem_map_alloc performs, checking the iovec's buffer is covered.
 */

#include <stddef.h>
#include <stdint.h>

#include "spdk_test_harness.h"

static void        *iovec_addr;
static volatile int covered;
static volatile int covered_aligned;

static void *
memreg_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_iovec iovec;
    int               niov;

    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &iovec);

    evpl_test_abort_if(niov < 1, "evpl_iovec_alloc failed");

    iovec_addr = evpl_iovec_data(&iovec);

    evpl_iovec_release(evpl, &iovec);

    return private_data;
} /* memreg_init */

static int
memreg_notify(
    void                           *cb_ctx,
    struct spdk_mem_map            *map,
    enum spdk_mem_map_notify_action action,
    void                           *vaddr,
    size_t                          size)
{
    if (action != SPDK_MEM_MAP_NOTIFY_REGISTER) {
        return 0;
    }

    /* Alignment is asserted only for the region covering our slab: SPDK
     * registers its own EAL heap regions too, and those need not be 2 MiB
     * aligned (e.g. the no-huge heap). */
    if ((uintptr_t) iovec_addr >= (uintptr_t) vaddr &&
        (uintptr_t) iovec_addr < (uintptr_t) vaddr + size) {
        covered = 1;

        covered_aligned = ((uintptr_t) vaddr &
                           (2 * 1024 * 1024 - 1)) == 0;
    }

    return 0;
} /* memreg_notify */

int
main(
    int   argc,
    char *argv[])
{
    static const struct spdk_mem_map_ops ops = {
        .notify_cb      = memreg_notify,
        .are_contiguous = NULL,
    };
    struct evpl_thread                  *thread;
    struct spdk_mem_map                 *map;

    evpl_spdk_test_init(2);

    evpl_spdk_test_config();

    /* Blocks until memreg_init allocated the iovec on the worker. */
    thread = evpl_thread_create(NULL, memreg_init, NULL, NULL);

    /* Allocation walks all existing registrations through memreg_notify. */
    map = spdk_mem_map_alloc(0, &ops, NULL);

    evpl_test_abort_if(!map, "spdk_mem_map_alloc failed");

    spdk_mem_map_free(&map);

    evpl_test_abort_if(!covered,
                       "slab containing the iovec was not registered with SPDK");

    evpl_test_abort_if(!covered_aligned,
                       "the slab's registered region was not 2 MiB aligned");

    evpl_test_info("iovec buffer %p is SPDK-registered and aligned",
                   iovec_addr);

    evpl_thread_destroy(thread);

    return 0;
} /* main */
