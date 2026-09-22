// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "evpl/evpl.h"
#include "tests/test_common.h"
#include "fd_cases.h"

static struct evpl_fd_event *event;
static int                   pair[2] = { -1, -1 };
static int                   reads, writes, bytes, retire;

static void
remove_event(struct evpl *evpl)
{
    if (event) {
        evpl_remove_fd_event(evpl, event);
        free(event);
        event = NULL;
        close(pair[0]);
        close(pair[1]);
    }
} /* remove_event */

static void
read_ready(
    struct evpl          *evpl,
    struct evpl_fd_event *fd)
{
    unsigned char c;
    ssize_t       n;

    reads++;
    while ((n = read(evpl_fd_event_fd(fd), &c, 1)) == 1) {
        evpl_test_abort_if(c != 0x67, "fd model: corrupt byte");
        bytes++;
    }
    evpl_test_abort_if(n != -1 || errno != EAGAIN, "fd model: unexpected read");
    if (retire) {
        remove_event(evpl);
    } else {
        evpl_fd_event_mark_unreadable(evpl, fd);
    }
} /* read_ready */

static void
write_ready(
    struct evpl          *evpl,
    struct evpl_fd_event *fd)
{
    char    fill[4096] = { 0 };
    ssize_t n;

    writes++;
    while ((n = write(evpl_fd_event_fd(fd), fill, sizeof(fill))) > 0) {
    }
    evpl_test_abort_if(n != -1 || errno != EAGAIN, "fd model: fill write buffer");
    evpl_fd_event_write_disinterest(evpl, fd);
    evpl_fd_event_mark_unwritable(evpl, fd);
} /* write_ready */

static void tick(
    struct evpl          *evpl,
    struct evpl_doorbell *bell) { (void) evpl; (void) bell; }

int
main(void)
{
    struct evpl_doorbell bell = { 0 };

    test_evpl_config();
    struct evpl         *evpl = evpl_create(NULL);
    evpl_add_doorbell(evpl, &bell, tick);
    for (size_t i = 0; i < sizeof(fd_steps) / sizeof(fd_steps[0]); i++) {
        const struct fd_step *s = &fd_steps[i];
        switch (s->op) {
            case fd_Reset: remove_event(evpl); reads = writes = bytes = 0; break;
            case fd_Attach:
                evpl_test_abort_if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), "socketpair");
                evpl_test_abort_if(fcntl(pair[0], F_SETFL, O_NONBLOCK) || fcntl(pair[1], F_SETFL, O_NONBLOCK), "fcntl");
                event  = calloc(1, sizeof(*event));
                retire = 0;
                evpl_add_fd_event(evpl, event, pair[0], read_ready, write_ready, NULL);
                break;
            case fd_Remove: remove_event(evpl); break;
            case fd_Interest: evpl_fd_event_read_interest(evpl, event); break;
            case fd_Pause: evpl_fd_event_read_disinterest(evpl, event); break;
            case fd_WriteInterest: {
                char drain[4096];
                while (read(pair[1], drain, sizeof(drain)) > 0) {
                }
                evpl_fd_event_write_interest(evpl, event); break;
            }
            case fd_WritePause: evpl_fd_event_write_disinterest(evpl, event); break;
            case fd_Put: {
                unsigned char c = 0x67;
                evpl_test_abort_if(write(pair[1], &c, 1) != 1, "fd model: write");
                break;
            }
            case fd_Force: evpl_fd_event_mark_readable(evpl, event); break;
            case fd_Retire: retire = 1; break;
            case fd_Quiesce:
                /* The entire window is required: absence of late callbacks is
                 * part of the oracle, even after all expected bytes arrived. */
                for (int j = 0; j < 32; j++) {
                    evpl_ring_doorbell(&bell);
                    evpl_continue(evpl);
                }
                evpl_test_abort_if(reads != s->reads || writes != s->writes || bytes != s->bytes ||
                                   !!event != s->attached,
                                   "fd step %zu: got reads/writes/bytes/attached %d/%d/%d/%d expected %d/%d/%d/%d",
                                   i, reads, writes, bytes, !!event, s->reads, s->writes, s->bytes, s->attached);
                break;
            default: abort();
        } /* switch */
    }
    remove_event(evpl);
    evpl_remove_doorbell(evpl, &bell);
    evpl_destroy(evpl);
    printf("fd model: %zu transitions passed\n", sizeof(fd_steps) / sizeof(fd_steps[0]));
    return 0;
} /* main */
