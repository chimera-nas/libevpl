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

enum evpl_protocol_id proto       = EVPL_DATAGRAM_SOCKET_UDP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;


struct client_state {
    int          sent;
    int          recv;
    int          niters;
    uint32_t     value;
    struct evpl *server_evpl;
};

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            state->recv++;

            evpl_test_info("client received %u sent %u recv %u",
                           *(uint32_t *) notify->recv_msg.iovec[0].data,
                           state->sent, state->recv);

            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *me, *server;
    struct evpl_bind     *bind;
    struct client_state  *state = arg;

    evpl = evpl_create(NULL);

    me = evpl_endpoint_create(address, port + 1);

    server = evpl_endpoint_create(address, port);

    bind = evpl_bind(evpl, proto, me, client_callback, state);

    while (state->sent < state->niters) {

        if (state->sent == state->recv) {

            evpl_sendtoep(evpl, bind, server, &state->value,
                          sizeof(state->value));

            state->value++;
            state->sent++;

            evpl_test_debug("client sent sent %u recv %u",
                            state->sent, state->recv);

        }

        evpl_continue(evpl);
    }

    evpl_test_debug("client completed iterations");

    evpl_stop(state->server_evpl);

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
    struct evpl_endpoint *client = private_data;
    uint32_t              value;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            value = *(uint32_t *) notify->recv_msg.iovec[0].data;
            evpl_sendtoep(evpl, bind, client, &value, sizeof(value));

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
    struct evpl_endpoint *me, *client;
    int                   rc, opt;
    struct client_state   state = {
        .sent   = 0,
        .recv   = 0,
        .niters = 100,
        .value  = 1
    };

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

    state.server_evpl = evpl;

    me     = evpl_endpoint_create(address, port);
    client = evpl_endpoint_create(address, port + 1);

    evpl_bind(evpl, proto, me, server_callback, client);

    pthread_create(&thr, NULL, client_thread, &state);

    evpl_run(evpl);

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
} /* main */
