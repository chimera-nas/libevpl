/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "core/evpl.h"

const char            hello[]  = "Hello World!";
const int             hellolen = strlen(hello) + 1;

enum evpl_protocol_id proto       = EVPL_DATAGRAM_SOCKET_UDP;
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
    int *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            evpl_test_info("client received '%s' len %d",
                           notify->recv_msg.bvec[0].data,
                           notify->recv_msg.bvec[0].length);

            *run = 0;

            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *me, *server;
    struct evpl_bind     *bind;
    int                   run = 1;

    evpl = evpl_create();

    me     = evpl_endpoint_create(evpl, address, port + 1);
    server = evpl_endpoint_create(evpl, address, port);

    bind = evpl_bind(evpl, proto, me, client_callback, &run);

    evpl_sendtoep(evpl, bind,  server, hello, hellolen);

    while (run) {

        evpl_wait(evpl, -1);
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
    struct evpl_endpoint *client;
    int                  *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            evpl_test_info("server received '%s'",
                           notify->recv_msg.bvec[0].data);

            client = evpl_endpoint_create(evpl, address, port + 1);

            evpl_sendtoep(evpl, bind, client, hello, hellolen);

            evpl_finish(evpl, bind);

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            *run = 0;

            break;
    } /* switch */

} /* server_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t             thr;
    struct evpl          *evpl;
    int                   opt, rc, run = 1;
    struct evpl_endpoint *ep;

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


    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, address, port);

    evpl_bind(evpl, proto, ep, server_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
} /* main */
