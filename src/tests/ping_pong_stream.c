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

enum evpl_protocol_id proto       = EVPL_STREAM_SOCKET_TCP;
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


void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client_state *state = private_data;
    uint32_t             value;
    int                  length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("client connected");
            break;
        case EVPL_NOTIFY_RECV_DATA:

            do {
                length = evpl_recv(evpl, bind, &value, sizeof(value));

                if (length == sizeof(value)) {

                    state->recv++;

                    evpl_test_info("client received %u sent %u recv %u", value,
                                   state->sent, state->recv);

                    if (state->recv < state->niters) {

                        evpl_send(evpl, bind, &state->value, sizeof(state->value));

                        state->value++;
                        state->sent++;

                        evpl_test_debug("client sent sent %u recv %u",
                                        state->sent, state->recv);
                    }

                }
            } while (length > 0);

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("client disconnected");
            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct evpl_bind     *bind;
    struct client_state  *state = arg;

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, state);

    evpl_send(evpl, bind, &state->value, sizeof(state->value));

    state->value++;
    state->sent++;

    evpl_test_debug("client sent sent %u recv %u",
                    state->sent, state->recv);

    while (state->recv != state->niters) {
        evpl_continue(evpl);
    }

    evpl_test_debug("client completed iterations");

    state->run = 0;

    evpl_endpoint_close(ep);

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
    uint32_t value;
    int      length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("server connected");
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("server disconnected");
            break;
        case EVPL_NOTIFY_RECV_DATA:

            length = evpl_recv(evpl, bind, &value, sizeof(value));

            if (length == sizeof(value)) {
                evpl_test_info("server received %u, responding", value);
                evpl_send(evpl, bind, &value, sizeof(value));
            }

            break;
    } /* switch */

} /* server_callback */

void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *accepted_bind,
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
    struct evpl_endpoint *ep;
    int                   rc, opt;
    struct client_state   state = {
        .run    = 1,
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

    ep = evpl_endpoint_create("0.0.0.0", port);

    listener = evpl_listener_create();

    evpl_listener_attach(evpl, listener, accept_callback, &state);

    evpl_listen(listener, proto, ep);

    pthread_create(&thr, NULL, client_thread, &state);

    while (state.run) {
        evpl_continue(evpl);
    }

    pthread_join(thr, NULL);

    evpl_listener_detach(evpl, listener);

    evpl_listener_destroy(listener);

    evpl_destroy(evpl);

    return 0;
} /* main */
