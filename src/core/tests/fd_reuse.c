// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

static int received;

static void
readable(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    char byte;

    evpl_test_abort_if(read(evpl_fd_event_fd(event), &byte, 1) != 1,
                       "replacement descriptor was not readable");
    received++;
    evpl_fd_event_mark_unreadable(evpl, event);
} /* readable */

int
main(void)
{
    struct evpl         *evpl;
    struct evpl_fd_event old_event, replacement;
    int                  first[2], second[2], fd;

    test_evpl_config();
    evpl = evpl_create(NULL);

    evpl_test_abort_if(pipe(first), "pipe failed");
    fd = first[0];
    evpl_add_fd_event(evpl, &old_event, fd, readable, NULL, NULL);
    evpl_fd_event_read_interest(evpl, &old_event);
    close(fd);
    evpl_test_abort_if(pipe(second), "replacement pipe failed");
    if (second[0] != fd) {
        evpl_test_abort_if(dup2(second[0], fd) != fd, "dup2 failed");
        close(second[0]);
    }
    evpl_add_fd_event(evpl, &replacement, fd, readable, NULL, NULL);
    evpl_fd_event_read_interest(evpl, &replacement);
    // A provider reports the old descriptor's removal only after its number
    // has been reused. Retiring it must preserve the replacement's watcher.
    evpl_remove_fd_event(evpl, &old_event);
    evpl_test_abort_if(write(second[1], "x", 1) != 1, "write failed");
    for (int i = 0; i < 100 && !received; i++) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(received != 1, "stale removal deleted replacement registration");
    evpl_remove_fd_event(evpl, &replacement);
    close(fd);
    close(first[1]);
    close(second[1]);
    evpl_destroy(evpl);
    return 0;
} /* main */
