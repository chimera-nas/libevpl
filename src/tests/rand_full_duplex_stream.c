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

enum evpl_protocol_id proto       = EVPL_STREAM_SOCKET_TCP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;
uint64_t              max_delta   = 4 * 1024 * 1024;
uint64_t              max_xfer    = 64 * 1024;
uint64_t              total_bytes = 128 * 1024 * 1024;


struct thread_state {
    int               run;
    int               index;
    int64_t           sent;
    int64_t           recv;
    pthread_t         thread;
    pthread_mutex_t   lock;
    pthread_cond_t    cond;
    struct evpl_bind *bind;
    void             *buffer;
};


void
dispatch(
    struct evpl         *evpl,
    struct thread_state *state)
{
    int length;

    if (!state->bind) {
        return;
    }

    if (state->sent == total_bytes &&
        state->recv == total_bytes) {
        evpl_finish(evpl, state->bind);
        state->bind = NULL;
    }

    if (state->sent == total_bytes) {
        return;
    }

    while ((state->sent <= state->recv ||
            state->sent - state->recv < max_delta ||
            state->recv == total_bytes) &&
           state->sent < total_bytes) {

        length = (rand() | 1) % max_xfer;

        if (length > total_bytes - state->sent) {
            length = total_bytes - state->sent;
        }

        evpl_send(evpl, state->bind, state->buffer, length);

        state->sent += length;

    }

} /* dispatch */

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct thread_state *state = private_data;
    int                  length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("connected");
            state->bind = bind;
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("disconnected");
            state->bind = NULL;
            state->run  = 0;
            break;
        case EVPL_NOTIFY_RECV_DATA:

            do {
                length = evpl_read(evpl, bind, state->buffer, max_xfer);

                state->recv += length;

            } while (length > 0);

            break;
    } /* switch */

} /* client_callback */


void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *listen_bind,
    struct evpl_bind        *accepted_bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    evpl_test_info("accepted connection");
    *notify_callback   = client_callback;
    *conn_private_data = private_data;
} /* accept_callback */


void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct thread_state  *state = arg;

    state->buffer = malloc(max_xfer);

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(evpl, address, port);

    if (state->index == 0) {
        evpl_listen(evpl, proto, ep, accept_callback, state);
    } else {
        evpl_connect(evpl, proto, NULL, ep, client_callback, NULL, state);
    }

    pthread_cond_signal(&state->cond);

    while (state->run) {
        dispatch(evpl, state);
        evpl_continue(evpl);
    }

    evpl_test_info("calling evpl destroy");
    evpl_destroy(evpl);

    free(state->buffer);

    return NULL;
} /* client_thread */

int
main(
    int   argc,
    char *argv[])
{
    struct thread_state state[2];
    int                 i, opt, rc;


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

    srand(time(NULL));

    for (i = 0; i < 2; ++i) {
        memset(&state[i], 0, sizeof(state[i]));
        state[i].run   = 1;
        state[i].index = i;

        pthread_mutex_init(&state[i].lock, NULL);
        pthread_cond_init(&state[i].cond, NULL);

        pthread_create(&state[i].thread, NULL, client_thread, &state[i]);

        pthread_cond_wait(&state[i].cond, &state[i].lock);

    }

    for (i = 0; i < 2; ++i) {
        pthread_join(state[i].thread, NULL);
    }

    return 0;
} /* main */
