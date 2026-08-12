// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Portable cross-thread / self wakeup primitive.
 *
 * The event loop needs a readable file descriptor it can register with the
 * core mechanism (epoll/kqueue) and that another thread can poke to wake it.
 * On Linux this is an eventfd (a single fd that is both read and written).
 * macOS has no eventfd, so a self-pipe is used instead: two fds, the read end
 * registered with kqueue and the write end poked to wake the loop.
 *
 * A single struct models both: on Linux rfd == wfd == the eventfd; on macOS
 * rfd is the pipe read end and wfd the write end.  Each signal writes an
 * 8-byte word (matching eventfd's counter semantics) and readers drain to
 * EAGAIN, which is correct for both an eventfd and a level-triggered self-pipe.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/eventfd.h>
#endif /* ifdef __linux__ */

struct evpl_wakeup {
    int rfd;   /* readable end registered with the core mechanism */
    int wfd;   /* writable end poked to wake the loop             */
};

/* Returns 0 on success, -1 on failure (errno set). */
static inline int
evpl_wakeup_open(struct evpl_wakeup *w)
{
#ifdef __linux__
    int fd = eventfd(0, EFD_NONBLOCK);

    if (fd < 0) {
        return -1;
    }

    w->rfd = fd;
    w->wfd = fd;
    return 0;
#else  /* ifdef __linux__ */
    int fds[2];
    int i, flags;

    if (pipe(fds) < 0) {
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        flags = fcntl(fds[i], F_GETFL, 0);
        if (flags < 0 || fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fds[0]);
            close(fds[1]);
            return -1;
        }
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
    }

    w->rfd = fds[0];
    w->wfd = fds[1];
    return 0;
#endif /* ifdef __linux__ */
} /* evpl_wakeup_open */

static inline void
evpl_wakeup_close(struct evpl_wakeup *w)
{
    if (w->rfd >= 0) {
        close(w->rfd);
    }

    if (w->wfd != w->rfd && w->wfd >= 0) {
        close(w->wfd);
    }

    w->rfd = -1;
    w->wfd = -1;
} /* evpl_wakeup_close */

/* Wake the loop.  Returns the number of bytes written (8) or -1 on error. */
static inline ssize_t
evpl_wakeup_signal(struct evpl_wakeup *w)
{
    uint64_t word = 1;
    ssize_t  len;

    do {
        len = write(w->wfd, &word, sizeof(word));
    } while (len < 0 && errno == EINTR);

    /* A wakeup that cannot be written is a wakeup already delivered: EAGAIN
     * means the buffer holds signals the reader has not drained yet (a
     * self-pipe fills after ~2K undrained words; an eventfd counter would
     * have to reach 2^64-1), so the reader is guaranteed to wake without
     * this write.  Report it delivered rather than surfacing an error the
     * callers treat as fatal. */
    if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return (ssize_t) sizeof(word);
    }

    return len;
} /* evpl_wakeup_signal */

/*
 * Drain all pending wakeups from the read end.  Reads until EAGAIN so a
 * level-triggered self-pipe (or an eventfd) is fully cleared.  Returns 0 if at
 * least one word was consumed, -1 if nothing was available (EAGAIN on the
 * first read) or the fd hit EOF.
 */
static inline int
evpl_wakeup_drain(int fd)
{
    uint64_t word;
    ssize_t  len;
    int      got = 0;

    for ( ; ;) {
        do {
            len = read(fd, &word, sizeof(word));
        } while (len < 0 && errno == EINTR);

        if (len == (ssize_t) sizeof(word)) {
            got = 1;
            continue;
        }

        break;
    }

    return got ? 0 : -1;
} /* evpl_wakeup_drain */
