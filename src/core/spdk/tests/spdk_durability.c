// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <errno.h>
#include "spdk_test_harness.h"
#include "spdk_bdev_test_common.h"

static struct evpl_block_device *device;
static struct evpl_block_queue  *queue;
static struct evpl_iovec         data;
static atomic_int                done;
static int                       stage;

static void
closed(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    evpl_test_abort_if(status, "close failed");
    atomic_store(&done, 1);
} /* closed */

static void
completion(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    evpl_test_abort_if(status != ENOTSUP, "unsupported durability acknowledged: %d", status);
    if (!stage++) {
        evpl_block_flush(evpl, queue, completion, NULL);
    } else {
        evpl_iovec_release(evpl, &data);
        evpl_block_close_queue(evpl, queue);
        evpl_block_close_device(evpl, device, closed, NULL);
    }
} /* completion */

static void
opened(
    struct evpl              *evpl,
    struct evpl_block_device *bdev,
    int                       status,
    void                     *arg)
{
    evpl_test_abort_if(status, "open failed");
    device = bdev;
    queue  = evpl_block_open_queue(evpl, device);
    evpl_test_abort_if(evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &data) != 1, "alloc failed");
    evpl_block_write(evpl, queue, &data, 1, 0, 1, completion, NULL);
} /* opened */

static void *
start(
    struct evpl *evpl,
    void        *arg)
{
    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_SPDK_BDEV, "Malloc0", opened, NULL);
    return NULL;
} /* start */

int
main(void)
{
    struct evpl_thread *thread;

    evpl_spdk_test_init(2);
    evpl_spdk_bdev_test_up(EVPL_SPDK_BDEV_TEST_MALLOC_JSON);
    evpl_spdk_test_config();
    thread = evpl_thread_create(NULL, start, NULL, NULL);
    while (!atomic_load(&done)) {
        usleep(1000);
    }
    evpl_thread_destroy(thread);
    evpl_spdk_bdev_test_down();
    return 0;
} /* main */
