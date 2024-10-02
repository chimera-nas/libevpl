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

enum evpl_protocol_id proto       = EVPL_STREAM_SOCKET_TCP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;
uint64_t              max_delta   = 65536;
uint64_t              max_xfer    = 65536;
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
    struct evpl *evpl,
    void        *private_data)
{
    struct thread_state *state = private_data;
    int                  length;

    evpl_test_info("dispatch entry");

    if (!state->bind) {
        return;
    }

    evpl_test_info("dispatch sent_bytes %lu recv_bytes %lu total_bytes %lu",
                   state->sent, state->recv, total_bytes);

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

        length = rand() % max_xfer;

        if (length > total_bytes - state->sent) {
            length = total_bytes - state->sent;
        }

        evpl_send(evpl, state->bind, state->buffer, length);

        state->sent += length;

        evpl_test_info("client sent_length %u sent %lu recv %lu",
                       length, state->sent, state->recv);
    }

} /* dispatch */

int
client_callback(
    struct evpl              *evpl,
    struct evpl_bind         *bind,
    const struct evpl_notify *notify,
    void                     *private_data)
{
    struct thread_state *state = private_data;
    int                  length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("connected");
            state->bind = bind;
            evpl_add_poll(evpl, dispatch, state);
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("disconnected");
            state->bind = NULL;
            state->run  = 0;
            break;
        case EVPL_NOTIFY_RECV_DATA:
            length = evpl_read(evpl, bind, state->buffer, max_xfer);

            state->recv += length;
            evpl_test_info("client recv_length %u sent %lu recv %lu",
                           notify->recv_msg.length,
                           state->sent, state->recv);

            break;
    } /* switch */

    return 0;
} /* client_callback */


void
accept_callback(
    struct evpl_bind       *bind,
    evpl_notify_callback_t *callback,
    void                  **conn_private_data,
    void                   *private_data)
{
    evpl_test_info("accepted connection");
    *callback          = client_callback;
    *conn_private_data = private_data;
} /* accept_callback */


void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct thread_state  *state = arg;

    state->buffer = malloc(max_xfer);

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, address, port);

    if (state->index == 0) {
        evpl_listen(evpl, proto, ep, accept_callback, state);
    } else {
        evpl_connect(evpl, proto, ep, client_callback, state);
    }

    pthread_cond_signal(&state->cond);

    evpl_test_info("entering loop state->run %d", state->run);
    while (state->run) {
        evpl_wait(evpl, -1);
    }

    evpl_test_info("exit loop state->run %d", state->run);

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