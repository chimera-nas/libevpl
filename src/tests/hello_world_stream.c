// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

const char            hello[]  = "Hello World!";
const int             hellolen = strlen(hello) + 1;

enum evpl_protocol_id proto       = EVPL_STREAM_SOCKET_TCP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    char buffer[hellolen];
    int  length, *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_DATA:

            length = evpl_recv(evpl, bind, buffer, hellolen);

            if (length == hellolen) {
                evpl_test_info("client received '%s'", buffer);
            }

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("client disconnected");
            *run = 0;
            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct evpl_bind     *bind;
    int                   run = 1;

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, &run);


    evpl_send(evpl, bind, hello, hellolen);

    while (run) {
        evpl_continue(evpl);
    }

    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    char buffer[hellolen];
    int  length, *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("server disconnected");
            *run = 0;
            break;
        case EVPL_NOTIFY_RECV_DATA:

            length = evpl_recv(evpl, bind, buffer, hellolen);

            if (length == hellolen) {

                evpl_test_info("server received '%s'", buffer);

                evpl_send(evpl, bind, hello, hellolen);

                evpl_finish(evpl, bind);
            }
            break;
    } /* switch */

} /* server_callback */

void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *conn_private_data = private_data;
} /* accept_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t             thr;
    struct evpl          *evpl;
    struct evpl_listener *listener;
    int                   run = 1, opt, rc;
    struct evpl_endpoint *ep;

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

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    listener = evpl_listener_create();

    evpl_listener_attach(evpl, listener, accept_callback, &run);

    evpl_listen(listener, proto, ep);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_continue(evpl);
    }

    pthread_join(thr, NULL);


    evpl_listener_detach(evpl, listener);

    evpl_listener_destroy(listener);

    evpl_destroy(evpl);

    return 0;
} /* main */
