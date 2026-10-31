// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * A TCP connect to a port nobody listens on must not abort the process and
 * must not block the loop: the bind's owner hears exactly one DISCONNECTED,
 * never a CONNECTED, and bytes queued before the failure are discarded with
 * it.  The refusal arrives after connect() has returned EINPROGRESS, through
 * SO_ERROR on the first event; connect_unreachable covers a failure that
 * connect() reports on the spot.
 */

#include "core/os.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "evpl/evpl_platform.h"

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

const char  hello[]  = "Hello World!";
const int   hellolen = sizeof(hello);

const char  localhost[] = "127.0.0.1";
const char *address     = localhost;

static int  connected, disconnected;

static long
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
} /* now_ms */

/* Bind a listener on an ephemeral loopback port, then close it: the port is
 * now known to refuse. */
static int
closed_loopback_port(void)
{
    struct sockaddr_in sin;
    socklen_t          len = sizeof(sin);
    int                fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    evpl_test_abort_if(fd < 0, "socket: %s", strerror(errno));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    evpl_test_abort_if(bind(fd, (struct sockaddr *) &sin, sizeof(sin)) < 0,
                       "bind: %s", strerror(errno));
    evpl_test_abort_if(listen(fd, 8) < 0, "listen: %s", strerror(errno));
    evpl_test_abort_if(getsockname(fd, (struct sockaddr *) &sin, &len) < 0,
                       "getsockname: %s", strerror(errno));
    close(fd);

    return ntohs(sin.sin_port);
} /* closed_loopback_port */

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
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct evpl_bind     *bind;
    enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
    int                   run   = 1, opt, rc, port;
    long                  start;

    test_evpl_config();

    while ((opt = getopt(argc, argv, "a:p:r:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                /* The shared test port is not used: the refusing port is
                 * chosen by the kernel below. */
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

    port = closed_loopback_port();

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, &run);

    evpl_test_abort_if(!bind, "evpl_connect returned NULL");

    /* Queue bytes before the failure lands so the write path sees them. */
    evpl_send(evpl, bind, hello, hellolen);

    start = now_ms();

    while (run && now_ms() - start < 10000) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(connected != 0, "refused connect reported CONNECTED");
    evpl_test_abort_if(disconnected != 1,
                       "expected exactly one DISCONNECTED, got %d", disconnected);
    evpl_test_abort_if(now_ms() - start >= 5000,
                       "refused connect took %ld ms", now_ms() - start);

    evpl_test_info("refused connect reported DISCONNECTED after %ld ms",
                   now_ms() - start);

    evpl_destroy(evpl);

    return 0;
} /* main */
