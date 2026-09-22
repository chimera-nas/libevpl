// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#define _GNU_SOURCE
#include "core/os.h"
#include <dlfcn.h>
#include <errno.h>
#include <spdk/bdev_module.h>
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "core/spdk/tests/spdk_bdev_test_common.h"
#include "block_retry_cases.h"

/* Only resource availability is controlled. Successful submissions use the
 * real malloc bdev. Hold the wait entry until the model permits its callback,
 * so close/remove races do not depend on sleeps or machine load. */
#define EXPORTED __attribute__((visibility("default")))
static struct spdk_bdev_io_wait_entry *waiting;
static int                             exhaust, queued, retries, issued;
static struct iovec                   *submitted;
static void                           *submitted_base;
static size_t                          submitted_length;
static struct evpl                    *owner;
static struct evpl_block_device       *device;
static struct evpl_block_queue        *queue;
static struct evpl_iovec               active;
static int                             active_held, opened, completions, errors, closes, removes, removed, closing;
static int                             last_status, removed_done;

EXPORTED size_t
spdk_bdev_get_buf_align(const struct spdk_bdev *bdev)
{
    return 4096;
} /* spdk_bdev_get_buf_align */

static int
submit(
    int                        write,
    struct spdk_bdev_desc     *desc,
    struct spdk_io_channel    *ch,
    struct iovec              *iov,
    int                        niov,
    uint64_t                   offset,
    uint64_t                   length,
    spdk_bdev_io_completion_cb cb,
    void                      *arg)
{
    evpl_test_abort_if(niov != 1 || iov[0].iov_base == active.data ||
                       (uintptr_t) iov[0].iov_base % 4096, "expected one aligned bounce vector");
    if (submitted) {
        evpl_test_abort_if(iov != submitted || iov[0].iov_base != submitted_base ||
                           iov[0].iov_len != submitted_length, "retry lost its submitted vector");
    }
    if (exhaust) {
        exhaust          = 0;
        submitted        = iov;
        submitted_base   = iov[0].iov_base;
        submitted_length = iov[0].iov_len;
        return -ENOMEM;
    }
    int (*real)(
        struct spdk_bdev_desc *,
        struct spdk_io_channel *,
        struct iovec *,
        int,
        uint64_t,
        uint64_t,
        spdk_bdev_io_completion_cb,
        void *) =
        dlsym(RTLD_NEXT, write ? "spdk_bdev_writev" : "spdk_bdev_readv");
    evpl_test_abort_if(!real, "SPDK submission interposition failed");
    return real(desc, ch, iov, niov, offset, length, cb, arg);
} /* submit */

EXPORTED int
spdk_bdev_readv(
    struct spdk_bdev_desc     *desc,
    struct spdk_io_channel    *ch,
    struct iovec              *iov,
    int                        niov,
    uint64_t                   offset,
    uint64_t                   length,
    spdk_bdev_io_completion_cb cb,
    void                      *arg)
{
    return submit(0, desc, ch, iov, niov, offset, length, cb, arg);
} /* spdk_bdev_readv */

EXPORTED int
spdk_bdev_writev(
    struct spdk_bdev_desc     *desc,
    struct spdk_io_channel    *ch,
    struct iovec              *iov,
    int                        niov,
    uint64_t                   offset,
    uint64_t                   length,
    spdk_bdev_io_completion_cb cb,
    void                      *arg)
{
    return submit(1, desc, ch, iov, niov, offset, length, cb, arg);
} /* spdk_bdev_writev */

EXPORTED int
spdk_bdev_queue_io_wait(
    struct spdk_bdev               *bdev,
    struct spdk_io_channel         *ch,
    struct spdk_bdev_io_wait_entry *entry)
{
    evpl_test_abort_if(waiting, "wait entry queued twice");
    waiting = entry;
    queued++;
    return 0;
} /* spdk_bdev_queue_io_wait */

static void
complete(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    evpl_test_abort_if(evpl != owner, "completion on wrong reactor");
    completions++;
    errors     += status != 0;
    last_status = status;
} /* complete */

static void
open_cb(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    int                       status,
    void                     *arg)
{
    evpl_test_abort_if(evpl != owner || status || !dev, "open failed");
    device = dev;
    opened = 1;
} /* open_cb */

static void
close_cb(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    evpl_test_abort_if(evpl != owner || status, "close failed");
    evpl_test_abort_if(waiting || completions != issued, "device closed before pending I/O completed");
    device = NULL;
    opened = closing = 0;
    closes++;
} /* close_cb */

static void
event_cb(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    enum evpl_block_event     event,
    void                     *arg)
{
    evpl_test_abort_if(evpl != owner || dev != device || event != EVPL_BLOCK_EVENT_REMOVE,
                       "unexpected device event");
    removes++;
} /* event_cb */

static void
removed_cb(
    void *arg,
    int   status)
{
    evpl_test_abort_if(status, "unregister failed");
    removed_done = 1;
} /* removed_cb */

static void
pump(void)
{
    test_mbt_continue(owner);
    sched_yield();
} /* pump */

static void
resume(void *arg)
{
    struct spdk_bdev_io_wait_entry *entry = arg;

    evpl_test_abort_if(!submitted || submitted[0].iov_base != submitted_base ||
                       submitted[0].iov_len != submitted_length, "parked vector expired");
    retries++;
    entry->cb_fn(entry->cb_arg);
} /* resume */

static void
retry_waiter(void)
{
    struct spdk_bdev_io_wait_entry *entry = waiting;

    evpl_test_abort_if(!entry, "model expected a parked request");
    waiting = NULL;
    evpl_test_abort_if(spdk_thread_send_msg(spdk_get_thread(), resume, entry), "queue retry failed");
} /* retry_waiter */

static void
close_device(void)
{
    evpl_block_close_queue(owner, queue);
    queue   = NULL;
    closing = 1;
    evpl_block_close_device(owner, device, close_cb, NULL);
} /* close_device */

static void
reset(void)
{
    if (waiting) {
        int target = completions + 1;
        exhaust = 0;
        retry_waiter();
        for (int n = 0; completions < target && n < 1000000; n++) {
            pump();
        }
        evpl_test_abort_if(completions != target, "cleanup retry did not complete");
    }
    if (active_held) {
        evpl_iovec_release(owner, &active);
        active_held = 0;
    }
    if (device && !closing) {
        close_device();
    }
    for (int n = 0; device && n < 1000000; n++) {
        pump();
    }
    evpl_test_abort_if(device, "cleanup close did not complete");
    struct spdk_bdev *bdev = spdk_bdev_get_by_name("RetryDisk");
    if (bdev && !removed) {
        removed = 1;
        spdk_bdev_unregister(bdev, removed_cb, NULL);
    }
    for (int n = 0; removed && !removed_done && n < 1000000; n++) {
        pump();
    }
    evpl_test_abort_if(removed && !removed_done, "cleanup unregister did not complete");
    removed   = removed_done = removes = completions = errors = closes = retries = queued = issued = 0;
    submitted = NULL;
} /* reset */

static void
start_io(
    int write,
    int value)
{
    struct evpl_iovec original;

    evpl_test_abort_if(evpl_iovec_alloc(owner, 4097, 4096, 1, 0, &original) != 1, "allocate I/O failed");
    evpl_iovec_move_segment(&active, &original, 1, 4096);
    active_held = 1;
    memset(active.data, write ? (value ? 0x5a : 0) : 0xa5, 4096);
    exhaust   = 1;
    submitted = NULL;
    issued++;
    if (write) {
        evpl_block_write(owner, queue, &active, 1, 0, 0, complete, NULL);
    } else {
        evpl_block_read(owner, queue, &active, 1, 0, complete, NULL);
    }
} /* start_io */

int
main(void)
{
    const char                *json =
        "{\"subsystems\":[{\"subsystem\":\"bdev\",\"config\":[{\"method\":\"bdev_malloc_create\",\"params\":{\"name\":\"RetryDisk\",\"num_blocks\":16,\"block_size\":4096}}]}]}";
    struct evpl_global_config *config = evpl_global_config_init();

    test_evpl_set_core_mech(config);
    evpl_spdk_bdev_test_up("{\"subsystems\":[]}");
    evpl_init(config);
    owner = test_mbt_create(NULL);
    for (size_t i = 0; i < sizeof(block_retry_steps) / sizeof(block_retry_steps[0]); i++) {
        const struct block_retry_step *s = &block_retry_steps[i];
        switch (s->op) {
            case block_retry_Reset: {
                reset();
                struct evpl_spdk_bdev_test_json cfg = { json, strlen(json) };
                evpl_spdk_bdev_test_step(evpl_spdk_bdev_test_load_msg, &cfg, "create retry disk");
                break;
            }
            case block_retry_Open:
                evpl_block_open_device(owner, EVPL_BLOCK_PROTOCOL_SPDK_BDEV, "RetryDisk", open_cb, NULL);
                for (int n = 0; !opened && n < 1000000; n++) {
                    pump();
                }
                evpl_test_abort_if(!opened, "open did not complete");
                evpl_block_set_event_callback(device, event_cb, NULL);
                queue = evpl_block_open_queue(owner, device);
                break;
            case block_retry_Read: start_io(0, s->value); break;
            case block_retry_Write: start_io(1, 1 - s->value); break;
            case block_retry_Close: close_device(); break;
            case block_retry_Remove:
                removed = 1;
                spdk_bdev_unregister(spdk_bdev_get_by_name("RetryDisk"), removed_cb, NULL);
                for (int n = 0; !removes && n < 1000000; n++) {
                    pump();
                }
                evpl_test_abort_if(removes != 1, "remove notification missing");
                break;
            case block_retry_RetryAgain:
            case block_retry_Retry:
                exhaust = s->op == block_retry_RetryAgain;
                retry_waiter();
                for (int n = 0; n < 1000000 && (retries < s->retries ||
                                                (s->waiting ? !waiting : completions < s->completions)); n++) {
                    pump();
                }
                if (!s->waiting) {
                    evpl_test_abort_if(last_status != (s->online ? 0 : ENODEV), "retry result differs from model");
                    if (!last_status) {
                        for (unsigned int j = 0; j < 4096; j++) {
                            evpl_test_abort_if(((unsigned char *) active.data)[j] != (s->value ? 0x5a : 0),
                                               "retry bytes differ from model");
                        }
                    }
                    evpl_iovec_release(owner, &active);
                    active_held = 0;
                }
                break;
            case block_retry_Inspect: break;
            default: abort();
        } /* switch */
        for (int n = 0; n < 1000000 && closes < s->closes; n++) {
            pump();
        }
        for (int n = 0; n < 8; n++) {
            pump();
        }
        evpl_test_abort_if(completions != s->completions || errors != s->errors || closes != s->closes ||
                           retries != s->retries || queued != issued + retries - completions ||
                           opened != s->opened || closing != s->closing || !!waiting != s->waiting,
                           "retry step %zu op %d differs from model", i, s->op);
    }
    reset();
    test_mbt_destroy(owner);
    evpl_spdk_bdev_test_down();
    return 0;
} /* main */
