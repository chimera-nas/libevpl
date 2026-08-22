// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The public fd-event API against a pipe.
 *
 * What matters here is the latched-readiness contract: once the kernel has
 * reported the fd readable, the read callback must be re-invoked every loop
 * pass -- with no further kernel edge -- until it drains to EAGAIN and calls
 * evpl_fd_event_mark_unreadable(); after that the loop must leave it alone
 * until new data arrives.  The callback below therefore reads one byte per
 * invocation, so multi-byte writes prove the re-invocation half, and the
 * post-drain checks prove the quiescence half.
 *
 * Also covered: mark_readable() re-queuing a parked event without a kernel
 * edge, write interest on an always-writable fd, and retiring an event from
 * inside its own callback and freeing its storage (meaningful under the
 * Debug/AddressSanitizer build, like doorbell_remove).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "evpl/evpl.h"
#include "tests/test_common.h"

static int failures;

#define CHECK(cond, ...) \
        do { \
            if (!(cond)) { \
                printf("FAIL: " __VA_ARGS__); printf("\n"); failures++; \
            } else { \
                printf("ok:   " __VA_ARGS__); printf("\n"); \
            } \
        } while (0)

/* --- reader: one byte per invocation, mark unreadable on EAGAIN --- */

static struct evpl_fd_event reader;
static int                  reader_invocations;
static int                  reader_bytes;
static int                  reader_drained;
static int                  reader_paused;

static void
reader_callback(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    char    c;
    ssize_t n;

    reader_invocations++;

    if (reader_paused) {
        /* Park without consuming: the loop must not spin on us, and only an
         * explicit mark_readable() may bring us back. */
        evpl_fd_event_mark_unreadable(evpl, event);
        return;
    }

    n = read(evpl_fd_event_fd(event), &c, 1);

    if (n == 1) {
        reader_bytes++;
        return;
    }

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        evpl_fd_event_mark_unreadable(evpl, event);
        reader_drained = 1;
        return;
    }

    printf("FAIL: unexpected read result %zd errno %d\n", n, errno);
    failures++;
} /* reader_callback */

/* --- writer: always-writable fd, single shot --- */

static struct evpl_fd_event writer;
static int                  writer_fired;

static void
writer_callback(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    writer_fired++;

    evpl_fd_event_write_disinterest(evpl, event);
    evpl_fd_event_mark_unwritable(evpl, event);
} /* writer_callback */

/* --- self-retiring heap-allocated event --- */

static int self_fired;

static void
self_callback(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    char c;

    while (read(evpl_fd_event_fd(event), &c, 1) == 1) {
        /* drain */
    }

    self_fired++;

    evpl_remove_fd_event(evpl, event);
    free(event);
} /* self_callback */

/* --- doorbell used as a neutral wakeup so quiescence is observable --- */

static int tick_fired;

static void
tick_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    tick_fired++;
} /* tick_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl          *evpl;
    struct evpl_fd_event *self;
    struct evpl_doorbell  tick;
    int                   p[2], p2[2], baseline;

    test_evpl_config();

    evpl = evpl_create(NULL);

    memset(&tick, 0, sizeof(tick));
    evpl_add_doorbell(evpl, &tick, tick_callback);

    if (pipe(p) || pipe(p2)) {
        perror("pipe");
        return 1;
    }

    fcntl(p[0], F_SETFL, O_NONBLOCK);
    fcntl(p[1], F_SETFL, O_NONBLOCK);
    fcntl(p2[0], F_SETFL, O_NONBLOCK);

    memset(&reader, 0, sizeof(reader));
    evpl_add_fd_event(evpl, &reader, p[0], reader_callback, NULL, NULL);
    evpl_fd_event_read_interest(evpl, &reader);

    CHECK(evpl_fd_event_fd(&reader) == p[0], "event reports its fd");

    /* --- one kernel edge, three bytes: re-invoked until drained --- */

    if (write(p[1], "abc", 3) != 3) {
        perror("write");
        return 1;
    }

    while (!reader_drained) {
        evpl_continue(evpl);
    }

    CHECK(reader_bytes == 3, "all three bytes read one per invocation");
    CHECK(reader_invocations == 4, "invoked per pass until EAGAIN (got %d)",
          reader_invocations);

    /* --- quiescent after the drain --- */

    baseline = reader_invocations;

    evpl_ring_doorbell(&tick);

    while (!tick_fired) {
        evpl_continue(evpl);
    }

    CHECK(reader_invocations == baseline, "no callbacks while drained");

    /* --- a new write wakes it again --- */

    reader_drained = 0;

    if (write(p[1], "d", 1) != 1) {
        perror("write");
        return 1;
    }

    while (!reader_drained) {
        evpl_continue(evpl);
    }

    CHECK(reader_bytes == 4, "delivery resumes on new data");

    /* --- mark_readable requeues a parked event without a kernel edge --- */

    reader_paused = 1;

    if (write(p[1], "e", 1) != 1) {
        perror("write");
        return 1;
    }

    baseline = reader_invocations;

    while (reader_invocations == baseline) {
        evpl_continue(evpl);
    }

    /* The callback parked itself without consuming the byte.  How long it
     * stays parked is backend-specific -- a level-triggered mechanism
     * (select) re-reports the pending byte on its own, an edge-triggered one
     * (epoll, kqueue) never will -- so the only portable claim is that
     * mark_readable() brings it back everywhere.  Quiescence is asserted
     * only in the drained-to-EAGAIN case above, which is uniform. */
    reader_paused  = 0;
    reader_drained = 0;

    evpl_fd_event_mark_readable(evpl, &reader);

    while (!reader_drained) {
        evpl_continue(evpl);
    }

    CHECK(reader_bytes == 5, "mark_readable revives the event without an edge");

    /* --- write interest on an always-writable fd --- */

    memset(&writer, 0, sizeof(writer));
    evpl_add_fd_event(evpl, &writer, p[1], NULL, writer_callback, NULL);
    evpl_fd_event_write_interest(evpl, &writer);

    while (!writer_fired) {
        evpl_continue(evpl);
    }

    CHECK(writer_fired == 1, "write callback fired for writable fd");

    /* --- prove it stays quiet after disinterest --- */

    tick_fired = 0;

    evpl_ring_doorbell(&tick);

    while (!tick_fired) {
        evpl_continue(evpl);
    }

    CHECK(writer_fired == 1, "write callback quiet after disinterest");

    /* --- retire from inside the callback, storage freed there --- */

    self = calloc(1, sizeof(*self));

    evpl_add_fd_event(evpl, self, p2[0], self_callback, NULL, NULL);
    evpl_fd_event_read_interest(evpl, self);

    if (write(p2[1], "x", 1) != 1) {
        perror("write");
        return 1;
    }

    while (!self_fired) {
        evpl_continue(evpl);
    }

    CHECK(self_fired == 1, "event retired and freed from its own callback");

    /* --- delivery in general still works after the removal --- */

    tick_fired = 0;

    evpl_ring_doorbell(&tick);

    while (!tick_fired) {
        evpl_continue(evpl);
    }

    CHECK(tick_fired == 1, "delivery continues after the removal");

    evpl_remove_fd_event(evpl, &reader);
    evpl_remove_fd_event(evpl, &writer);
    evpl_remove_doorbell(evpl, &tick);

    close(p[0]);
    close(p[1]);
    close(p2[0]);
    close(p2[1]);

    evpl_destroy(evpl);

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);

    return failures != 0;
} /* main */
