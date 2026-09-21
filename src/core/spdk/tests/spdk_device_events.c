// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <errno.h>
#include <spdk/bdev_module.h>
#include "spdk_test_harness.h"
#include "spdk_bdev_test_common.h"

struct worker_state {
    struct evpl             *evpl;
    struct evpl_block_queue *queue;
    struct evpl_iovec        buffer;
    struct evpl_deferral     next;
};
static struct worker_state       workers[2];
static struct evpl_thread       *threads[2];
static struct evpl_block_device *device;
static struct evpl              *owner;
static struct spdk_thread       *owner_thread;
static struct evpl_timer         trigger;
static atomic_int                ready, removed, stopped, closed, unregistered;
static int                       resize_seen;

static void issue(
    struct evpl *evpl,
    void        *arg);

static void
queue_stopped(void *arg)
{
    atomic_fetch_add(&stopped, 1);
} /* queue_stopped */

static void
io_done(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    struct worker_state *worker = arg;

    evpl_test_abort_if(status && status != ENODEV && status != EIO,
                       "unexpected I/O error: %d", status);
    if (atomic_load(&removed)) {
        evpl_iovec_release(evpl, &worker->buffer);
        evpl_block_close_queue(evpl, worker->queue);
        spdk_thread_send_msg(owner_thread, queue_stopped, NULL);
    } else {
        evpl_defer(evpl, &worker->next);
    }
} /* io_done */

static void
issue(
    struct evpl *evpl,
    void        *arg)
{
    struct worker_state *worker = arg;

    evpl_test_abort_if(!evpl_block_size(device), "device size disappeared");
    evpl_block_read(evpl, worker->queue, &worker->buffer, 1, 0, io_done, worker);
} /* issue */

static void *
worker_start(
    struct evpl *evpl,
    void        *arg)
{
    struct worker_state *worker = arg;

    worker->evpl  = evpl;
    worker->queue = evpl_block_open_queue(evpl, device);
    evpl_test_abort_if(evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &worker->buffer) != 1,
                       "allocation failed");
    evpl_deferral_init(&worker->next, issue, worker);
    evpl_defer(evpl, &worker->next);
    atomic_fetch_add(&ready, 1);
    return arg;
} /* worker_start */

static void
unregistered_cb(
    void *arg,
    int   rc)
{
    evpl_test_abort_if(rc, "unregister failed: %d", rc);
    atomic_store(&unregistered, 1);
} /* unregistered_cb */

static void
device_closed(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    evpl_test_abort_if(status, "close failed: %d", status);
    atomic_store(&closed, 1);
} /* device_closed */

static void
event_cb(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    enum evpl_block_event     event,
    void                     *arg)
{
    evpl_test_abort_if(evpl != owner || spdk_get_thread() != owner_thread,
                       "device event on wrong owner");
    if (event == EVPL_BLOCK_EVENT_RESIZE) {
        evpl_test_abort_if(evpl_block_size(dev) != 32768ULL * 4096, "resize not published");
        resize_seen = 1;
        spdk_bdev_unregister(spdk_bdev_get_by_name("Malloc0"), unregistered_cb, NULL);
    } else {
        atomic_store(&removed, 1);
    }
} /* event_cb */

static void
tick(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    if (!resize_seen && atomic_load(&ready) == 2) {
        evpl_test_abort_if(spdk_bdev_notify_blockcnt_change(spdk_bdev_get_by_name("Malloc0"), 32768),
                           "resize failed");
    }
    if (atomic_load(&stopped) == 2) {
        evpl_block_close_device(evpl, device, device_closed, NULL);
    } else {
        evpl_add_oneshot_timer(evpl, timer, tick, 1000);
    }
} /* tick */

static void
opened(
    struct evpl              *evpl,
    struct evpl_block_device *bdev,
    int                       status,
    void                     *arg)
{
    evpl_test_abort_if(status, "open failed");
    owner        = evpl;
    owner_thread = spdk_get_thread();
    device       = bdev;
    evpl_block_set_event_callback(device, event_cb, NULL);
    for (int i = 0; i < 2; i++) {
        threads[i] = evpl_thread_create_async(NULL, worker_start, NULL, &workers[i]);
    }
    evpl_add_oneshot_timer(evpl, &trigger, tick, 1000);
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
    struct evpl_thread *opener;

    evpl_spdk_test_init(3);
    evpl_spdk_bdev_test_up(EVPL_SPDK_BDEV_TEST_MALLOC_JSON);
    evpl_spdk_test_config();
    opener = evpl_thread_create(NULL, start, NULL, NULL);
    while (!atomic_load(&closed) || !atomic_load(&unregistered)) {
        usleep(1000);
    }
    for (int i = 0; i < 2; i++) {
        evpl_thread_destroy(threads[i]);
    }
    evpl_thread_destroy(opener);
    evpl_spdk_bdev_test_down();
    return 0;
} /* main */
