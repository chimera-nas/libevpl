// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * A TCP connect that connect() itself rejects -- a multicast destination
 * gives ENETUNREACH on Linux before any packet is sent -- must not abort the
 * process, and the bind's owner hears exactly one DISCONNECTED and never a
 * CONNECTED.  A send queued right after the connect, the normal
 * connect-then-send pattern, must not keep the loop awake once the bind is
 * gone: after the DISCONNECTED the loop has to report idle passes and
 * actually block in them.
 *
 * This is the synchronous failure path; connect_refused covers the one that
 * arrives later through SO_ERROR.
 */

#include "core/os.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evpl/evpl_platform.h"

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

const char  hello[]  = "Hello World!";
const int   hellolen = sizeof(hello);

const char  multicast[] = "224.0.0.1";
const char *address     = multicast;
int         port        = 9;

static int  connected, disconnected;

/* Passes given to the bind's own teardown before the loop must be idle. */
#define SETTLE_PASSES 5
/* Passes that must all be idle, and how long each is asked to block. */
#define IDLE_PASSES   20
#define IDLE_WAIT_MS  20

static long
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
} /* now_ms */

static void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    int *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            connected++;
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            disconnected++;
            *run = 0;
            break;
    } /* switch */
} /* client_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread_config *config;
    struct evpl               *evpl;
    struct evpl_endpoint      *ep;
    struct evpl_bind          *bind;
    enum evpl_protocol_id      proto = EVPL_STREAM_SOCKET_TCP;
    int                        run   = 1, opt, rc, i, work = 0;
    long                       start;

    test_evpl_config();

    while ((opt = getopt(argc, argv, "a:p:r:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [-r protocol] [-a address] [-p port]\n",
                        argv[0]);
                return 1;
        } /* switch */
    }

    config = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(config, IDLE_WAIT_MS);

    evpl = evpl_create(config);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, &run);

    evpl_test_abort_if(!bind, "evpl_connect returned NULL");

    /* Queue bytes before the failure lands, as a caller that dials and sends
     * in the same breath does. */
    evpl_send(evpl, bind, hello, hellolen);

    start = now_ms();

    while (run && now_ms() - start < 10000) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(connected != 0, "unreachable connect reported CONNECTED");
    evpl_test_abort_if(disconnected != 1,
                       "expected exactly one DISCONNECTED, got %d", disconnected);

    evpl_test_info("unreachable connect reported DISCONNECTED after %ld ms",
                   now_ms() - start);

    for (i = 0; i < SETTLE_PASSES; i++) {
        evpl_continue(evpl);
    }

    start = now_ms();

    for (i = 0; i < IDLE_PASSES; i++) {
        work += evpl_continue(evpl);
    }

    evpl_test_abort_if(work != 0,
                       "loop reported %d work units over %d passes after the bind was gone",
                       work, IDLE_PASSES);

    /* An idle pass blocks for wait_ms; a loop that spins returns at once. */
    evpl_test_abort_if(now_ms() - start < (IDLE_PASSES * IDLE_WAIT_MS) / 2,
                       "%d idle passes took only %ld ms: the loop is spinning",
                       IDLE_PASSES, now_ms() - start);

    evpl_test_info("%d idle passes took %ld ms", IDLE_PASSES, now_ms() - start);

    evpl_destroy(evpl);

    return 0;
} /* main */
