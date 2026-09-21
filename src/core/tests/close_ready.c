// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* A permanently ready, unrelated descriptor must not starve bind teardown.
 * Keep the pipe readable and clear only the software readiness each pass. */
#include <unistd.h>
#include "core/evpl.h"
#include "core/fd_event.h"
#include "core/test_log.h"
#include "test_common.h"

static unsigned int callbacks, disconnected;

static void
ready(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    callbacks++;
    evpl_fd_event_mark_unreadable(evpl, event);
} /* ready */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notification,
    void               *arg)
{
    if (notification->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        disconnected++;
    }
} /* notify */

int
main(void)
{
    struct evpl_thread_config *config;
    struct evpl               *evpl;
    struct evpl_endpoint      *endpoint;
    struct evpl_bind          *bind;
    struct evpl_fd_event       event;
    unsigned int               i;
    int                        pipefd[2];

    alarm(10);
    test_evpl_config();
    config = evpl_thread_config_init();
    evpl_thread_config_set_poll_mode(config, 0);
    evpl_thread_config_set_wait_ms(config, 0);
    evpl     = evpl_create(config);
    endpoint = evpl_endpoint_create("127.0.0.1", 0);
    bind     = evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, endpoint, notify, NULL);
    evpl_test_abort_if(pipe(pipefd), "pipe failed");
    evpl_add_fd_event(evpl, &event, pipefd[0], ready, NULL, NULL);
    evpl_core_remove(&evpl->core, &event.event);
    event.event.flags |= EVPL_LEVEL_TRIGGERED;
    /* The public wrapper always supplies both trampolines.  Only a read
     * filter is useful for this read end of the pipe. */
    event.event.write_callback = NULL;
    evpl_core_add(&evpl->core, &event.event);
    evpl_fd_event_read_interest(evpl, &event);
    evpl_test_abort_if(write(pipefd[1], "x", 1) != 1, "write failed");
    evpl_close(evpl, bind);
    for (i = 0; i < 16; i++) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(callbacks < 2, "level-triggered readiness was lost");
    evpl_test_abort_if(disconnected != 1, "ready descriptor starved close");
    evpl_remove_fd_event(evpl, &event);
    close(pipefd[0]);
    close(pipefd[1]);
    evpl_endpoint_close(endpoint);
    evpl_destroy(evpl);
    return 0;
} /* main */
