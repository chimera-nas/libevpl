// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#define check(c) do { if (!(c)) abort(); } while (0)
#include <spdk/bdev.h>
#include <spdk/thread.h>

/* Test-only interposition forces the normally conditional bounce/retry paths.
 * Retry is queued to a subsequent host message, retaining the submitted vector
 * pointer past the original call's stack lifetime. */
#define EXPORTED __attribute__((visibility("default")))
static _Thread_local int    retried;
static                      _Thread_local struct iovec *submitted;
static _Thread_local void  *submitted_base;
static _Thread_local size_t submitted_length;

EXPORTED size_t
spdk_bdev_get_buf_align(const struct spdk_bdev *bdev)
{
    return 4096;
} /* spdk_bdev_get_buf_align */

EXPORTED int
spdk_bdev_readv(
    struct spdk_bdev_desc     *desc,
    struct spdk_io_channel    *ch,
    struct iovec              *iov,
    int                        niov,
    uint64_t                   offset,
    uint64_t                   length,
    spdk_bdev_io_completion_cb callback,
    void                      *private_data)
{
    int (*readv_fn)(
        struct spdk_bdev_desc *,
        struct spdk_io_channel *,
        struct iovec *,
        int,
        uint64_t,
        uint64_t,
        spdk_bdev_io_completion_cb,
        void *) =
        dlsym(RTLD_NEXT, "spdk_bdev_readv");
    if (offset == 8192 && !retried) {
        retried          = 1;
        submitted        = iov;
        submitted_base   = iov[0].iov_base;
        submitted_length = iov[0].iov_len;
        return -ENOMEM;
    }
    if (offset == 8192) {
        check(iov == submitted && niov == 1);
        check(iov[0].iov_base == submitted_base && iov[0].iov_len == submitted_length);
    }
    return readv_fn(desc, ch, iov, niov, offset, length, callback, private_data);
} /* spdk_bdev_readv */

static void
retry(void *arg)
{
    struct spdk_bdev_io_wait_entry *entry = arg;

    check(submitted[0].iov_base == submitted_base);
    check(submitted[0].iov_len == submitted_length);
    entry->cb_fn(entry->cb_arg);
} /* retry */

EXPORTED int
spdk_bdev_queue_io_wait(
    struct spdk_bdev               *bdev,
    struct spdk_io_channel         *ch,
    struct spdk_bdev_io_wait_entry *entry)
{
    return spdk_thread_send_msg(spdk_get_thread(), retry, entry);
} /* spdk_bdev_queue_io_wait */

EXPORTED bool
spdk_bdev_has_write_cache(const struct spdk_bdev *bdev)
{
    if (getenv("EVPL_TEST_NO_FLUSH")) {
        return true;
    }
    bool (*fn)(
        const struct spdk_bdev *) = dlsym(RTLD_NEXT, "spdk_bdev_has_write_cache");
    return fn(bdev);
} /* spdk_bdev_has_write_cache */

EXPORTED bool
spdk_bdev_io_type_supported(
    struct spdk_bdev      *bdev,
    enum spdk_bdev_io_type type)
{
    if (type == SPDK_BDEV_IO_TYPE_FLUSH && getenv("EVPL_TEST_NO_FLUSH")) {
        return false;
    }
    bool (*fn)(
        struct spdk_bdev *,
        enum spdk_bdev_io_type) =
        dlsym(RTLD_NEXT, "spdk_bdev_io_type_supported");
    return fn(bdev, type);
} /* spdk_bdev_io_type_supported */
