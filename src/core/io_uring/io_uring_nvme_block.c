#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* ifndef _GNU_SOURCE */
#include "core/os.h"
// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>
#include <liburing.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>


#include "core/io_uring/io_uring.h"
#include "core/io_uring/io_uring_internal.h"

#define EVPL_NVME_CMD_FLUSH 0x00
#define EVPL_NVME_CMD_WRITE 0x01
#define EVPL_NVME_CMD_READ  0x02

#define EVPL_NVME_CDW12_FUA (1U << 30)

static void
evpl_io_uring_nvme_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    int rc;

    if (req->res < 0) {
        rc = -req->res;
    } else if (req->res) {
        rc = EIO;
    } else {
        rc = 0;
    }

    req->block.callback(evpl, rc, req->block.private_data);
} /* evpl_io_uring_nvme_callback */

static inline uint64_t
evpl_io_uring_nvme_iov_size(
    const struct evpl_iovec *iov,
    int                      niov)
{
    uint64_t total = 0;
    int      i;

    for (i = 0; i < niov; i++) {
        total += iov[i].length;
    }

    return total;
} /* evpl_io_uring_nvme_iov_size */

static inline void
evpl_io_uring_nvme_prep_cmd(
    struct nvme_uring_cmd       *cmd,
    struct evpl_io_uring_device *dev,
    uint8_t                      opcode,
    uint64_t                     offset,
    uint64_t                     length,
    uint32_t                     flags)
{
    uint64_t slba = offset / dev->sector_size;
    uint32_t nlb  = length ? (length / dev->sector_size) - 1 : 0;

    memset(cmd, 0, sizeof(*cmd));

    cmd->opcode = opcode;
    cmd->nsid   = dev->nsid;
    cmd->cdw10  = slba & 0xffffffff;
    cmd->cdw11  = slba >> 32;
    cmd->cdw12  = nlb | flags;
} /* evpl_io_uring_nvme_prep_cmd */

static void
evpl_io_uring_nvme_rw(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    uint8_t                  opcode,
    uint32_t                 flags,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct nvme_uring_cmd        *cmd;
    struct io_uring_sqe          *sqe;
    uint64_t                      length;
    int                           i;

    evpl_io_uring_abort_if(niov <= 0 || niov > 64, "invalid NVMe iovec count %d", niov);

    length = evpl_io_uring_nvme_iov_size(iov, niov);

    evpl_io_uring_abort_if(offset % dev->sector_size,
                           "NVMe offset %lu is not aligned to sector size %u",
                           offset, dev->sector_size);
    evpl_io_uring_abort_if(length == 0 || length % dev->sector_size,
                           "NVMe length %lu is not aligned to sector size %u",
                           length, dev->sector_size);

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_BLOCK);

    req->callback           = evpl_io_uring_nvme_callback;
    req->block.callback     = callback;
    req->block.private_data = private_data;
    req->block.niov         = niov;
    req->block.length       = length;

    for (i = 0; i < niov; i++) {
        req->block.iov[i].iov_base = iov[i].data;
        req->block.iov[i].iov_len  = iov[i].length;
    }

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);
    io_uring_prep_uring_cmd(sqe, NVME_URING_CMD_IO_VEC, dev->fd);

    cmd = (struct nvme_uring_cmd *) sqe->cmd;
    evpl_io_uring_nvme_prep_cmd(cmd, dev, opcode, offset, length, flags);

    cmd->addr     = (uintptr_t) req->block.iov;
    cmd->data_len = niov;

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_nvme_rw */

static void
evpl_io_uring_nvme_read(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    evpl_io_uring_nvme_rw(evpl, queue, iov, niov, offset, EVPL_NVME_CMD_READ, 0,
                          callback, private_data);
} /* evpl_io_uring_nvme_read */

static void
evpl_io_uring_nvme_write(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    evpl_io_uring_nvme_rw(evpl, queue, iov, niov, offset, EVPL_NVME_CMD_WRITE,
                          sync ? EVPL_NVME_CDW12_FUA : 0,
                          callback, private_data);
} /* evpl_io_uring_nvme_write */

static void
evpl_io_uring_nvme_flush(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct nvme_uring_cmd        *cmd;
    struct io_uring_sqe          *sqe;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_BLOCK);

    req->callback           = evpl_io_uring_nvme_callback;
    req->block.callback     = callback;
    req->block.private_data = private_data;
    req->block.length       = 0;

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);
    io_uring_prep_uring_cmd(sqe, NVME_URING_CMD_IO, dev->fd);

    cmd = (struct nvme_uring_cmd *) sqe->cmd;
    evpl_io_uring_nvme_prep_cmd(cmd, dev, EVPL_NVME_CMD_FLUSH, 0, 0, 0);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_nvme_flush */

static void
evpl_io_uring_nvme_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    evpl_free(queue);
} /* evpl_io_uring_nvme_close_queue */

static struct evpl_block_queue *
evpl_io_uring_nvme_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev)
{
    struct evpl_block_queue *q;

    q = evpl_zalloc(sizeof(*q));

    q->private_data = bdev->private_data;
    q->close_queue  = evpl_io_uring_nvme_close_queue;
    q->read         = evpl_io_uring_nvme_read;
    q->write        = evpl_io_uring_nvme_write;
    q->flush        = evpl_io_uring_nvme_flush;

    return q;
} /* evpl_io_uring_nvme_open_queue */

static void
evpl_io_uring_nvme_close_device(
    struct evpl                 *evpl,
    struct evpl_block_device    *bdev,
    evpl_block_device_complete_t complete,
    void                        *ctx)
{
    struct evpl_io_uring_device *dev = bdev->private_data;

    close(dev->fd);
    evpl_free(dev);
    evpl_free(bdev);

    complete(evpl, NULL, 0, ctx);
} /* evpl_io_uring_nvme_close_device */

static void
evpl_io_uring_nvme_open_device(
    struct evpl                 *evpl,
    const char                  *uri,
    void                        *private_data,
    evpl_block_device_complete_t complete,
    void                        *ctx)
{
    struct evpl_block_device    *bdev;
    struct evpl_io_uring_device *dev;
    struct stat                  st;
    uint64_t                     bytes;
    int                          sector_size;
    int                          nsid;
    int                          err;
    int                          cmd_fd;
    int                          consumed = 0;
    unsigned int                 controller, instance;
    char                         sysfs[128], resolved[PATH_MAX], command_path[128];
    const char                  *name;

    bdev = evpl_zalloc(sizeof(*bdev));
    dev  = evpl_zalloc(sizeof(*dev));

    dev->fd = open(uri, O_RDWR | O_DIRECT);

    if (dev->fd < 0) {
        err = errno;
        goto out;
    }

    if (fstat(dev->fd, &st) < 0) {
        err = errno;
        goto out;
    }
    if (!S_ISBLK(st.st_mode)) {
        err = ENOTBLK;
        goto out;
    }

    nsid = ioctl(dev->fd, NVME_IOCTL_ID);
    if (nsid < 0) {
        err = errno;
        goto out;
    }

    if (ioctl(dev->fd, BLKGETSIZE64, &bytes) < 0 ||
        ioctl(dev->fd, BLKSSZGET, &sector_size) < 0) {
        err = errno;
        goto out;
    }

    /* Block nodes supply geometry, but NVMe uring_cmd is implemented by the
     * namespace character device. Resolve the kernel name through st_rdev so
     * callers may still use /dev/disk/by-id or other block-device aliases.
     * Reject partitions: passthrough offsets are relative to the namespace. */
    snprintf(sysfs, sizeof(sysfs), "/sys/dev/block/%u:%u",
             major(st.st_rdev), minor(st.st_rdev));
    if (!realpath(sysfs, resolved)) {
        err = errno;
        goto out;
    }
    name = strrchr(resolved, '/');
    if (!name || sscanf(name + 1, "nvme%un%u%n", &controller, &instance, &consumed) != 2 ||
        name[1 + consumed] != '\0') {
        err = ENOTBLK;
        goto out;
    }
    snprintf(command_path, sizeof(command_path), "/dev/ng%un%u", controller, instance);
    cmd_fd = open(command_path, O_RDWR);
    if (cmd_fd < 0) {
        err = errno;
        goto out;
    }
    close(dev->fd);
    dev->fd = cmd_fd;

    dev->nsid        = nsid;
    dev->sector_size = sector_size;

    bdev->private_data     = dev;
    bdev->open_queue       = evpl_io_uring_nvme_open_queue;
    bdev->close_device     = evpl_io_uring_nvme_close_device;
    bdev->size             = bytes;
    bdev->max_request_size = 4 * 1024 * 1024;

    err = 0;

 out:
    if (err) {
        if (dev->fd >= 0) {
            close(dev->fd);
        }
        evpl_free(dev);
        evpl_free(bdev);
        complete(evpl, NULL, err, ctx);
    } else {
        complete(evpl, bdev, 0, ctx);
    }
} /* evpl_io_uring_nvme_open_device */

struct evpl_block_protocol evpl_block_protocol_io_uring_nvme = {
    .id          = EVPL_BLOCK_PROTOCOL_IO_URING_NVME,
    .name        = "io_uring_nvme",
    .framework   = &evpl_framework_io_uring,
    .open_device = evpl_io_uring_nvme_open_device,
};
