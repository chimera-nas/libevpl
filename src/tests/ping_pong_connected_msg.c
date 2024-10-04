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

#include "core/evpl.h"
#include "core/test_log.h"

enum evpl_protocol_id proto       = EVPL_DATAGRAM_SOCKET_UDP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;


struct client_state {
    int      run;
    int      sent;
    int      recv;
    int      niters;
    uint32_t value;
};

int
test_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    return sizeof(uint32_t);
} /* test_segment_callback */


int
client_callback(
    struct evpl              *evpl,
    struct evpl_bind         *bind,
    const struct evpl_notify *notify,
    void                     *private_data)
{
    struct client_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            state->recv++;

            evpl_test_info("client received %u sent %u recv %u",
                           *(uint32_t *) notify->recv_msg.bvec[0].data,
                           state->sent, state->recv);

            break;
    } /* switch */

    return 0;
} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *server;
    struct evpl_bind     *bind;
    struct client_state  *state = arg;

    evpl = evpl_create();

    server = evpl_endpoint_create(evpl, address, port);

    bind = evpl_connect(evpl, proto, server, client_callback,
                        test_segment_callback, state);

    while (state->recv != state->niters) {

        if (state->sent == state->recv) {

            evpl_send(evpl, bind, &state->value, sizeof(state->value));

            state->value++;
            state->sent++;

            evpl_test_debug("client sent sent %u recv %u",
                            state->sent, state->recv);

        }

        evpl_wait(evpl, -1);
    }

    evpl_test_debug("client completed iterations");

    state->run = 0;

    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

int
server_callback(
    struct evpl              *evpl,
    struct evpl_bind         *bind,
    const struct evpl_notify *notify,
    void                     *private_data)
{
    uint32_t value;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            value = *(uint32_t *) notify->recv_msg.bvec[0].data;
            evpl_send(evpl, bind, &value, sizeof(value));

            break;
    } /* switch */

    return 0;
} /* server_callback */

void
accept_callback(
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *segment_callback  = test_segment_callback;
    *conn_private_data = private_data;
} /* accept_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t             thr;
    struct evpl          *evpl;
    struct evpl_endpoint *me;
    int                   rc, opt;
    struct client_state   state = {
        .run    = 1,
        .sent   = 0,
        .recv   = 0,
        .niters = 100,
        .value  = 1
    };

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

    me = evpl_endpoint_create(evpl, "0.0.0.0", port);

    evpl_listen(evpl, proto, me, accept_callback, NULL);

    pthread_create(&thr, NULL, client_thread, &state);

    while (state.run) {
        evpl_wait(evpl, 1);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
} /* main */
