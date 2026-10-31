// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The tcp_connect_timeout_ms knob must bound how long a SYN that is never
 * answered keeps a connect pending.  Linux only: a listener whose accept
 * queue is full drops incoming SYNs, which is the one way to make the
 * kernel's retransmit schedule run against loopback without root or a
 * firewall.  Windows resets such a SYN instead and macOS is unverified, so
 * the CMake registration keeps this test off those platforms.
 *
 * The first half checks the timeout-to-TCP_SYNCNT mapping against the
 * kernel's 1, 2, 4, ... s backoff, under which TCP_SYNCNT n gives up after
 * 2^(n+1) - 1 seconds.
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
#include "core/socket/tcp.h"
#include "test_common.h"

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

static void
check_syn_retries(void)
{
    static const struct {
        unsigned int ms;
        unsigned int retries;
    } table[] = {
        /* *INDENT-OFF* */
        { 0, 1 },
        { 1, 1 },
        { 2999, 1 },
        { 3000, 1 },
        { 6999, 1 },
        { 7000, 2 },
        { 14999, 2 },
        { 15000, 3 },
        { 31000, 4 },
        { 63000, 5 },
        { 127000, 6 },
        { 4294967295u, 21 },
        /* *INDENT-ON* */
    };
    unsigned int i, got;

    for (i = 0; i < sizeof(table) / sizeof(table[0]); ++i) {
        got = evpl_socket_tcp_syn_retries(table[i].ms);
        evpl_test_abort_if(got != table[i].retries,
                           "%u ms mapped to %u retries, expected %u",
                           table[i].ms, got, table[i].retries);
    }
} /* check_syn_retries */

static int
loopback_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    evpl_test_abort_if(fd < 0, "socket: %s", strerror(errno));

    return fd;
} /* loopback_socket */

/* A listener that drops every further SYN: backlog 1, accept queue already
 * holding the backlog + 1 connections Linux admits, nothing ever accepting. */
static int
syn_dropping_port(
    int *fds,
    int  nfds)
{
    struct sockaddr_in sin;
    socklen_t          len = sizeof(sin);
    int                i;

    evpl_test_abort_if(nfds < 3, "need a listener and two fillers");

    fds[0] = loopback_socket();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    evpl_test_abort_if(bind(fds[0], (struct sockaddr *) &sin, sizeof(sin)) < 0,
                       "bind: %s", strerror(errno));
    evpl_test_abort_if(listen(fds[0], 1) < 0, "listen: %s", strerror(errno));
    evpl_test_abort_if(getsockname(fds[0], (struct sockaddr *) &sin, &len) < 0,
                       "getsockname: %s", strerror(errno));

    for (i = 1; i < 3; ++i) {
        fds[i] = loopback_socket();
        evpl_test_abort_if(connect(fds[i], (struct sockaddr *) &sin, sizeof(sin)) < 0,
                           "filler connect %d: %s", i, strerror(errno));
    }

    return ntohs(sin.sin_port);
} /* syn_dropping_port */

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
    struct evpl_global_config *config;
    struct evpl               *evpl;
    struct evpl_endpoint      *ep;
    struct evpl_bind          *bind;
    enum evpl_protocol_id      proto = EVPL_STREAM_SOCKET_TCP;
    int                        run   = 1, opt, rc, port, i;
    int                        fds[3];
    long                       start, elapsed;

    check_syn_retries();

    config = evpl_global_config_init();

    /* TCP_SYNCNT 1: one retransmit, give up after about 3 s. */
    evpl_global_config_set_tcp_connect_timeout_ms(config, 3000);

    test_evpl_set_core_mech(config);

    evpl_init(config);

    while ((opt = getopt(argc, argv, "a:p:r:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                /* The shared test port is not used: the dropping listener
                 * takes whatever ephemeral port the kernel hands out. */
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

    port = syn_dropping_port(fds, 3);

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, &run);

    evpl_test_abort_if(!bind, "evpl_connect returned NULL");

    start = now_ms();

    while (run && now_ms() - start < 30000) {
        evpl_continue(evpl);
    }

    elapsed = now_ms() - start;

    evpl_test_abort_if(connected != 0, "SYN-dropped connect reported CONNECTED");
    evpl_test_abort_if(disconnected != 1,
                       "expected one DISCONNECTED, got %d", disconnected);
    evpl_test_abort_if(elapsed < 2000,
                       "gave up after %ld ms: the SYN retry never ran", elapsed);
    evpl_test_abort_if(elapsed >= 20000,
                       "gave up only after %ld ms: TCP_SYNCNT not applied", elapsed);

    evpl_test_info("SYN-dropped connect reported DISCONNECTED after %ld ms", elapsed);

    evpl_destroy(evpl);

    for (i = 0; i < 3; ++i) {
        close(fds[i]);
    }

    return 0;
} /* main */
