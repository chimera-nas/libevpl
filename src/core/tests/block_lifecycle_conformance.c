// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <errno.h>
#include <spdk/bdev_module.h>
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "core/spdk/tests/spdk_bdev_test_common.h"
#include "block_lifecycle_cases.h"

static struct evpl              *owner;
static struct evpl_block_device *device;
static struct evpl_block_queue  *queue;
static atomic_int                done, unregistered;
static int                       status, resizes, removes, remove_started;

static void
complete(
    struct evpl *evpl,
    int          rc,
    void        *arg)
{
    evpl_test_abort_if(evpl != owner, "block completion on wrong context");
    status = rc;
    atomic_fetch_add(&done, 1);
} /* complete */
static void
opened(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    int                       rc,
    void                     *arg)
{
    device = dev;
    complete(evpl, rc, arg);
} /* opened */
static void
event_cb(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    enum evpl_block_event     event,
    void                     *arg)
{
    evpl_test_abort_if(evpl != owner || dev != device, "block event on wrong owner");
    if (event == EVPL_BLOCK_EVENT_RESIZE) {
        resizes++;
    } else {
        removes++;
    }
} /* event_cb */
static void
removed_cb(
    void *arg,
    int   rc)
{
    evpl_test_abort_if(rc, "bdev unregister failed");
    atomic_store(&unregistered, 1);
} /* removed_cb */
static void
pump(void)
{
    test_mbt_continue(owner);
    sched_yield();
} /* pump */
static void
wait_done(void)
{
    int n;

    for (n = 0; n < 1000000 && !atomic_load(&done); n++) {
        pump();
    }
    evpl_test_abort_if(atomic_load(&done) != 1, "block operation missing or duplicated completion");
} /* wait_done */
static void
close_device(void)
{
    if (!device) {
        return;
    }
    evpl_block_close_queue(owner, queue);
    done = 0;
    evpl_block_close_device(owner, device, complete, NULL);
    wait_done();
    evpl_test_abort_if(status, "device close failed");
    device = NULL; queue = NULL;
} /* close_device */
static void
reset_device(void)
{
    struct spdk_bdev *bdev = spdk_bdev_get_by_name("ModelDisk");

    if (bdev && !remove_started) {
        remove_started = 1;
        unregistered   = 0;
        spdk_bdev_unregister(bdev, removed_cb, NULL);
    }
    close_device();
    for (int n = 0; remove_started && !atomic_load(&unregistered) && n < 1000000; n++) {
        pump();
    }
    evpl_test_abort_if(remove_started && !atomic_load(&unregistered), "bdev removal did not complete");
    remove_started = 0;
} /* reset_device */
int
main(void)
{
    const char                *json = "{\"subsystems\":[{\"subsystem\":\"bdev\",\"config\":["
        "{\"method\":\"bdev_malloc_create\",\"params\":{\"name\":\"ModelDisk\",\"num_blocks\":16,\"block_size\":4096}}]}]}";
    struct evpl_global_config *config = evpl_global_config_init();

    test_evpl_set_core_mech(config);
    evpl_spdk_bdev_test_up("{\"subsystems\":[]}");
    evpl_init(config);
    owner = test_mbt_create(NULL);
    for (size_t i = 0; i < sizeof(block_lifecycle_steps) / sizeof(block_lifecycle_steps[0]); i++) {
        const struct block_lifecycle_step *s    = &block_lifecycle_steps[i];
        struct spdk_bdev                  *bdev = spdk_bdev_get_by_name("ModelDisk");
        switch (s->op) {
            case block_lifecycle_Reset: {
                reset_device();
                struct evpl_spdk_bdev_test_json cfg = { json, strlen(json) };
                evpl_spdk_bdev_test_step(evpl_spdk_bdev_test_load_msg, &cfg, "create model disk");
                resizes = removes = 0;
                break;
            }
            case block_lifecycle_Open:
                done = 0;
                evpl_block_open_device(owner, EVPL_BLOCK_PROTOCOL_SPDK_BDEV, "ModelDisk", opened, NULL);
                evpl_test_abort_if(done, "open completed inline");
                wait_done();
                evpl_test_abort_if(status || !device, "device open failed");
                evpl_block_set_event_callback(device, event_cb, NULL);
                queue = evpl_block_open_queue(owner, device);
                break;
            case block_lifecycle_Close: close_device(); break;
            case block_lifecycle_Resize:
                evpl_test_abort_if(spdk_bdev_notify_blockcnt_change(bdev, s->blocks), "resize failed");
                for (int n = 0; resizes != s->resizes && n < 1000000; n++) {
                    pump();
                }
                break;
            case block_lifecycle_Remove:
                remove_started = 1;
                unregistered   = 0;
                spdk_bdev_unregister(bdev, removed_cb, NULL);
                for (int n = 0; removes != s->removes && n < 1000000; n++) {
                    pump();
                }
                break;
            case block_lifecycle_Read:
            case block_lifecycle_ReadRemoved: {
                struct evpl_iovec iov;
                evpl_test_abort_if(evpl_iovec_alloc(owner, 4096, 4096, 1, 0, &iov) != 1, "allocate read");
                done = 0;
                evpl_block_read(owner, queue, &iov, 1, 0, complete, NULL);
                wait_done();
                evpl_test_abort_if((status == 0) != s->online, "read outcome disagrees with device state");
                if (!status) {
                    for (unsigned int j = 0; j < iov.length; j++) {
                        evpl_test_abort_if(((unsigned char *) iov.data)[j], "malloc disk read was not zero");
                    }
                }
                evpl_iovec_release(owner, &iov);
                break;
            }
            case block_lifecycle_Inspect: break;
            default: abort();
        } /* switch */
        for (int n = 0; n < 8; n++) {
            pump();
        }
        evpl_test_abort_if(resizes != s->resizes || removes != s->removes,
                           "block step %zu: lifecycle event count differs from model", i);
        if (device) {
            evpl_test_abort_if(evpl_block_size(device) != (uint64_t) s->blocks * 4096,
                               "device capacity differs from model");
        }
    }
    reset_device();
    test_mbt_destroy(owner);
    evpl_spdk_bdev_test_down();
    return 0;
} /* main */
