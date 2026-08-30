// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Block backend built on plain pread()/pwrite().
 *
 * The other block backends hand the kernel an asynchronous submission
 * interface -- io_uring, libaio, a VFIO-mapped NVMe queue pair -- and are
 * therefore Linux-only.  macOS has no equivalent: POSIX AIO exists but caps
 * in-flight requests per process and cannot deliver completions to kqueue,
 * and libdispatch's dispatch_io is itself a thread pool.  So rather than
 * chase a kernel facility that is not there, this backend builds the
 * asynchrony itself.
 *
 * Each device gets one dedicated thread.  Callers on any number of evpl
 * threads push requests onto the device's single submission queue; the device
 * thread pops them in order and services each one with ordinary blocking
 * pread()/pwrite()/fsync() calls, then posts the finished request back to the
 * completion queue of the evpl thread that issued it and rings that thread's
 * doorbell.  The issuing thread never blocks, so from the caller's side this
 * looks exactly like the async backends: submit, return to the event loop,
 * get a callback.
 *
 * Serving requests one at a time is deliberate.  The point of this backend is
 * portability and correctness on platforms with no async I/O, not peak IOPS;
 * a device that wants depth should use io_uring.  What it does buy, besides
 * running anywhere POSIX does, is that buffered I/O has no alignment rules,
 * so unlike the O_DIRECT backends nothing is ever bounced through a
 * temporary aligned buffer.
 *
 * Threading contract:
 *   - a queue belongs to the evpl thread that opened it, and only that
 *     thread may submit on it or close it
 *   - every request on a queue must have completed before the queue is
 *     closed, and every queue must be closed before the device is
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>
#endif /* ifdef __linux__ */

#ifdef __APPLE__
#include <sys/disk.h>
#endif /* ifdef __APPLE__ */

#include "core/evpl.h"
#include "core/logging.h"
#include "core/macros.h"
#include "core/protocol.h"
#include "core/pthread_util.h"
#include "core/pread/pread.h"

#define evpl_pread_debug(...) evpl_debug("pread", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_pread_info(...)  evpl_info("pread", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_pread_error(...) evpl_error("pread", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_pread_abort_if(cond, ...) \
        evpl_abort_if(cond, "pread", __FILE__, __LINE__, __VA_ARGS__)

/* Requests below this many segments carry their iovec array inline, which
 * covers everything the callers issue in practice; larger ones allocate. */
#define EVPL_PREAD_INLINE_IOV  8

#define EVPL_PREAD_MAX_REQUEST (4 * 1024 * 1024)

enum evpl_pread_opcode {
    EVPL_PREAD_READ = 0,
    EVPL_PREAD_WRITE,
    EVPL_PREAD_FLUSH,
};

struct evpl_pread_queue;

struct evpl_pread_request {
    struct evpl_pread_queue   *queue;
    evpl_block_callback_t      callback;
    void                      *private_data;
    uint64_t                   offset;
    unsigned int               opcode;
    unsigned int               sync;
    int                        status;
    int                        niov;
    struct iovec              *iov;
    struct iovec               iov_inline[EVPL_PREAD_INLINE_IOV];
    struct evpl_pread_request *next;
};

struct evpl_pread_device {
    int                        fd;

    pthread_t                  thread;
    int                        thread_started;

    /* Submission queue, in FIFO order.  Written by any submitting thread,
     * drained by the device thread; both under lock. */
    pthread_mutex_t            lock;
    pthread_cond_t             cond;
    struct evpl_pread_request *submitted;
    struct evpl_pread_request *submitted_tail;
    int                        shutdown;
};

struct evpl_pread_queue {
    /* First member: the core hands back a struct evpl_block_queue *, and the
     * queue callbacks recover this from it. */
    struct evpl_block_queue    base;

    struct evpl_pread_device  *device;
    struct evpl_doorbell       doorbell;

    /* Completion queue.  Appended by the device thread, drained by the
     * owning evpl thread out of the doorbell callback. */
    pthread_mutex_t            lock;
    struct evpl_pread_request *completed;
    struct evpl_pread_request *completed_tail;

    /* Set while a doorbell ring is outstanding, so a run of completions
     * costs one wakeup rather than one per request.  Guarded by lock.
     */
    int                        notified;

    /* Owning-thread-only state: a freelist of retired requests, and the
     * number of requests that have been submitted but whose callbacks have
     * not yet run. */
    struct evpl_pread_request *free_requests;
    uint64_t                   outstanding;
};

static inline struct evpl_pread_queue *
evpl_pread_queue(struct evpl_block_queue *queue)
{
    return (struct evpl_pread_queue *) queue;
} /* evpl_pread_queue */

static struct evpl_pread_request *
evpl_pread_request_alloc(
    struct evpl_pread_queue *pq,
    int                      niov)
{
    struct evpl_pread_request *req = pq->free_requests;

    if (req) {
        pq->free_requests = req->next;
    } else {
        req = evpl_zalloc(sizeof(*req));
    }

    req->queue = pq;
    req->niov  = niov;
    req->next  = NULL;

    if (niov > EVPL_PREAD_INLINE_IOV) {
        req->iov = evpl_malloc(niov * sizeof(struct iovec));
    } else {
        req->iov = req->iov_inline;
    }

    return req;
} /* evpl_pread_request_alloc */

static void
evpl_pread_request_free(
    struct evpl_pread_queue   *pq,
    struct evpl_pread_request *req)
{
    if (req->iov != req->iov_inline) {
        evpl_free(req->iov);
        req->iov = req->iov_inline;
    }

    req->next         = pq->free_requests;
    pq->free_requests = req;
} /* evpl_pread_request_free */

/*
 * Transfer one request's iovec array with ordinary pread()/pwrite() calls.
 *
 * Returns 0, or a positive errno.  A transfer that ends short of what was
 * asked for -- a read that runs off the end of the device, a write the
 * filesystem could not take in full -- reports EIO, matching what the libaio
 * and io_uring backends report when their result is shorter than the request.
 */
static int
evpl_pread_transfer(
    int                        fd,
    struct evpl_pread_request *req,
    int                        is_write)
{
    uint64_t offset = req->offset;
    ssize_t  len;
    char    *base;
    size_t   left;
    int      i;

    for (i = 0; i < req->niov; i++) {
        base = req->iov[i].iov_base;
        left = req->iov[i].iov_len;

        while (left) {
            if (is_write) {
                len = pwrite(fd, base, left, offset);
            } else {
                len = pread(fd, base, left, offset);
            }

            if (len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return errno;
            }

            if (len == 0) {
                /* End of device with bytes still owed. */
                return EIO;
            }

            base   += len;
            left   -= len;
            offset += len;
        }
    }

    return 0;
} /* evpl_pread_transfer */

static int
evpl_pread_sync(int fd)
{
    int rc;

    do {
#ifdef __linux__
        rc = fdatasync(fd);
#else  /* ifdef __linux__ */
        /* macOS has fdatasync but it is a plain fsync underneath, and fsync
         * there does not push the drive's write cache.  Durability on a real
         * disk needs F_FULLFSYNC; fall back to fsync where the fcntl is not
         * supported (it fails with ENOTTY on some filesystems). */
        rc = fcntl(fd, F_FULLFSYNC);

        if (rc < 0 && (errno == ENOTTY || errno == EINVAL ||
                       errno == ENOTSUP)) {
            rc = fsync(fd);
        }
#endif /* ifdef __linux__ */
    } while (rc < 0 && errno == EINTR);

    return rc < 0 ? errno : 0;
} /* evpl_pread_sync */

/*
 * Post a finished request back to the thread that issued it.
 *
 * Runs on the device thread.  The doorbell is only rung when no ring is
 * already outstanding: notified is cleared under the same lock the drain
 * takes, so a completion appended after the drain always finds it clear and
 * rings, and one appended before is picked up by the drain in progress.
 */
static void
evpl_pread_post(struct evpl_pread_request *req)
{
    struct evpl_pread_queue *pq = req->queue;
    int                      ring;

    pthread_mutex_lock(&pq->lock);

    req->next = NULL;

    if (pq->completed_tail) {
        pq->completed_tail->next = req;
    } else {
        pq->completed = req;
    }

    pq->completed_tail = req;

    ring = !pq->notified;

    pq->notified = 1;

    pthread_mutex_unlock(&pq->lock);

    if (ring) {
        evpl_ring_doorbell(&pq->doorbell);
    }
} /* evpl_pread_post */

static void *
evpl_pread_device_thread(void *arg)
{
    struct evpl_pread_device  *dev = arg;
    struct evpl_pread_request *req;

    pthread_mutex_lock(&dev->lock);

    for ( ; ;) {

        while (!dev->submitted && !dev->shutdown) {
            pthread_cond_wait(&dev->cond, &dev->lock);
        }

        /* Shut down only once the queue is drained, so nothing submitted is
         * ever dropped without a completion. */
        if (!dev->submitted) {
            break;
        }

        req            = dev->submitted;
        dev->submitted = req->next;

        if (!dev->submitted) {
            dev->submitted_tail = NULL;
        }

        pthread_mutex_unlock(&dev->lock);

        switch (req->opcode) {
            case EVPL_PREAD_READ:
                req->status = evpl_pread_transfer(dev->fd, req, 0);
                break;
            case EVPL_PREAD_WRITE:
                req->status = evpl_pread_transfer(dev->fd, req, 1);

                if (!req->status && req->sync) {
                    req->status = evpl_pread_sync(dev->fd);
                }
                break;
            case EVPL_PREAD_FLUSH:
                req->status = evpl_pread_sync(dev->fd);
                break;
        } /* switch */

        evpl_pread_post(req);

        pthread_mutex_lock(&dev->lock);
    }

    pthread_mutex_unlock(&dev->lock);

    return NULL;
} /* evpl_pread_device_thread */

static void
evpl_pread_submit(
    struct evpl_pread_queue   *pq,
    struct evpl_pread_request *req)
{
    struct evpl_pread_device *dev = pq->device;

    pq->outstanding++;

    pthread_mutex_lock(&dev->lock);

    if (dev->submitted_tail) {
        dev->submitted_tail->next = req;
    } else {
        dev->submitted = req;
    }

    dev->submitted_tail = req;

    pthread_cond_signal(&dev->cond);

    pthread_mutex_unlock(&dev->lock);
} /* evpl_pread_submit */

/*
 * Drain this thread's completion queue.  The whole list is taken in one
 * lock/unlock so callbacks -- which routinely issue the next request -- run
 * outside the lock the device thread needs to post into it.
 */
static void
evpl_pread_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_pread_queue   *pq = container_of(doorbell, struct evpl_pread_queue, doorbell);
    struct evpl_pread_request *req, *next;
    evpl_block_callback_t      callback;
    void                      *private_data;
    int                        status;

    pthread_mutex_lock(&pq->lock);

    req = pq->completed;

    pq->completed      = NULL;
    pq->completed_tail = NULL;
    pq->notified       = 0;

    pthread_mutex_unlock(&pq->lock);

    while (req) {
        next = req->next;

        /* Retire the request before calling back rather than after.  The last
         * callback of a drain is entitled to close the queue -- nothing is
         * outstanding by then -- so read everything out of the request and the
         * queue first; both may be gone once the callback returns. */
        callback     = req->callback;
        private_data = req->private_data;
        status       = req->status;

        pq->outstanding--;

        evpl_pread_request_free(pq, req);

        callback(evpl, status, private_data);

        req = next;
    }

    evpl_activity(evpl);
} /* evpl_pread_doorbell */

static void
evpl_pread_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_pread_queue   *pq = evpl_pread_queue(queue);
    struct evpl_pread_request *req;
    int                        i;

    req = evpl_pread_request_alloc(pq, niov);

    req->callback     = callback;
    req->private_data = private_data;
    req->offset       = offset;
    req->opcode       = EVPL_PREAD_READ;
    req->sync         = 0;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
    }

    evpl_pread_submit(pq, req);
} /* evpl_pread_read */

static void
evpl_pread_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_pread_queue   *pq = evpl_pread_queue(queue);
    struct evpl_pread_request *req;
    int                        i;

    req = evpl_pread_request_alloc(pq, niov);

    req->callback     = callback;
    req->private_data = private_data;
    req->offset       = offset;
    req->opcode       = EVPL_PREAD_WRITE;
    req->sync         = sync ? 1 : 0;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
    }

    evpl_pread_submit(pq, req);
} /* evpl_pread_write */

static void
evpl_pread_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_pread_queue   *pq = evpl_pread_queue(queue);
    struct evpl_pread_request *req;

    req = evpl_pread_request_alloc(pq, 0);

    req->callback     = callback;
    req->private_data = private_data;
    req->offset       = 0;
    req->opcode       = EVPL_PREAD_FLUSH;
    req->sync         = 0;

    evpl_pread_submit(pq, req);
} /* evpl_pread_flush */

static void
evpl_pread_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    struct evpl_pread_queue   *pq = evpl_pread_queue(queue);
    struct evpl_pread_request *req;

    /* A request still in flight holds a pointer to this queue, and the device
     * thread would post its completion into memory about to be freed.  That
     * is a caller error rather than something to paper over: wait for the
     * callbacks before closing. */
    evpl_pread_abort_if(pq->outstanding,
                        "block queue closed with %lu request(s) still outstanding",
                        (unsigned long) pq->outstanding);

    evpl_remove_doorbell(evpl, &pq->doorbell);

    while ((req = pq->free_requests)) {
        pq->free_requests = req->next;
        evpl_free(req);
    }

    pthread_mutex_destroy(&pq->lock);

    evpl_free(pq);
} /* evpl_pread_close_queue */

static struct evpl_block_queue *
evpl_pread_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev)
{
    struct evpl_pread_queue *pq;

    pq = evpl_zalloc(sizeof(*pq));

    pq->device = bdev->private_data;

    pthread_mutex_init(&pq->lock, NULL);

    evpl_add_doorbell(evpl, &pq->doorbell, evpl_pread_doorbell);

    pq->base.private_data = pq;
    pq->base.close_queue  = evpl_pread_close_queue;
    pq->base.read         = evpl_pread_read;
    pq->base.write        = evpl_pread_write;
    pq->base.flush        = evpl_pread_flush;

    return &pq->base;
} /* evpl_pread_open_queue */

static void
evpl_pread_close_device(struct evpl_block_device *bdev)
{
    struct evpl_pread_device *dev = bdev->private_data;

    if (dev->thread_started) {
        pthread_mutex_lock(&dev->lock);
        dev->shutdown = 1;
        pthread_cond_signal(&dev->cond);
        pthread_mutex_unlock(&dev->lock);

        pthread_join(dev->thread, NULL);
    }

    pthread_cond_destroy(&dev->cond);
    pthread_mutex_destroy(&dev->lock);

    close(dev->fd);

    evpl_free(dev);
    evpl_free(bdev);
} /* evpl_pread_close_device */

/*
 * Size of the thing behind the fd.  A regular file is its own length; a raw
 * disk has to be asked, and the two platforms ask differently.
 */
static int
evpl_pread_device_size(
    int          fd,
    struct stat *st,
    uint64_t    *sizep)
{
    if (S_ISREG(st->st_mode)) {
        *sizep = st->st_size;
        return 0;
    }

#ifdef __linux__
    if (S_ISBLK(st->st_mode)) {
        uint64_t bytes;

        if (ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
            return -1;
        }

        *sizep = bytes;
        return 0;
    }
#endif /* ifdef __linux__ */

#ifdef __APPLE__
    if (S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) {
        uint64_t blocks;
        uint32_t block_size;

        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blocks) < 0 ||
            ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) < 0) {
            return -1;
        }

        *sizep = blocks * block_size;
        return 0;
    }
#endif /* ifdef __APPLE__ */

    /* A fifo, a socket, a directory: nothing that can be addressed by offset. */
    errno = ENOTSUP;

    return -1;
} /* evpl_pread_device_size */

static struct evpl_block_device *
evpl_pread_open_device(
    const char *uri,
    void       *private_data)
{
    struct evpl_block_device *bdev;
    struct evpl_pread_device *dev;
    struct stat               st;
    int                       rc;

    bdev = evpl_zalloc(sizeof(*bdev));
    dev  = evpl_zalloc(sizeof(*dev));

    dev->fd = open(uri, O_RDWR);

    if (dev->fd < 0) {
        evpl_pread_error("failed to open %s: %s", uri, strerror(errno));
        evpl_free(dev);
        evpl_free(bdev);
        return NULL;
    }

    if (fstat(dev->fd, &st) < 0 ||
        evpl_pread_device_size(dev->fd, &st, &bdev->size) < 0) {
        evpl_pread_error("failed to size %s: %s", uri, strerror(errno));
        close(dev->fd);
        evpl_free(dev);
        evpl_free(bdev);
        return NULL;
    }

    pthread_mutex_init(&dev->lock, NULL);
    pthread_cond_init(&dev->cond, NULL);

    rc = evpl_pthread_create(&dev->thread, NULL, evpl_pread_device_thread, dev);

    if (rc) {
        evpl_pread_error("failed to start device thread for %s: %s",
                         uri, strerror(rc));
        pthread_cond_destroy(&dev->cond);
        pthread_mutex_destroy(&dev->lock);
        close(dev->fd);
        evpl_free(dev);
        evpl_free(bdev);
        return NULL;
    }

    dev->thread_started = 1;

    bdev->private_data     = dev;
    bdev->open_queue       = evpl_pread_open_queue;
    bdev->close_device     = evpl_pread_close_device;
    bdev->max_request_size = EVPL_PREAD_MAX_REQUEST;

    return bdev;
} /* evpl_pread_open_device */

struct evpl_block_protocol evpl_block_protocol_pread = {
    .id          = EVPL_BLOCK_PROTOCOL_PREAD,
    .name        = "pread",
    .framework   = NULL,
    .open_device = evpl_pread_open_device,
};
