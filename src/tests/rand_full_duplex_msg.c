// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

enum evpl_protocol_id proto        = EVPL_DATAGRAM_SOCKET_UDP;
const char            localhost[]  = "127.0.0.1";
const char           *address      = localhost;
int                   port         = 8000;
uint64_t              max_delta    = 16;
uint64_t              max_datagram = 4000;
uint64_t              total_bytes  = 128 * 1024 * 1024;


struct thread_state {
    int       run;
    int       index;
    int64_t   sent;
    int64_t   recv;
    int64_t   recv_msg;
    int64_t   sent_msg;
    pthread_t thread;
};


void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct thread_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("disconnected");
            state->run = 0;
            break;
        case EVPL_NOTIFY_RECV_MSG:
            state->recv += notify->recv_msg.length;
            state->recv_msg++;

            for (int i = 0; i < notify->recv_msg.niov; i++) {
                evpl_iovec_release(&notify->recv_msg.iovec[i]);
            }

            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *me, *them;
    struct evpl_bind     *bind;
    struct thread_state  *state = arg;
    void                 *buffer;
    int                   length;

    evpl = evpl_create(NULL);

    buffer = malloc(max_datagram);

    me   = evpl_endpoint_create(address, port + state->index);
    them = evpl_endpoint_create(address, port + !state->index);

    bind = evpl_bind(evpl, proto, me, client_callback, state);

    while (state->sent < total_bytes) {

        length = (rand() % max_datagram) | 1;

        if (length > total_bytes - state->sent) {
            length = total_bytes - state->sent;
        }

        evpl_sendtoep(evpl, bind, them, buffer, length);

        state->sent += length;
        state->sent_msg++;

        evpl_continue(evpl);
    }

    evpl_destroy(evpl);

    free(buffer);

    return NULL;
} /* client_thread */

int
main(
    int   argc,
    char *argv[])
{
    struct thread_state state[2];
    int                 i, opt, rc;

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

    srand(time(NULL));

    for (i = 0; i < 2; ++i) {
        memset(&state[i], 0, sizeof(state[i]));
        state[i].run   = 1;
        state[i].index = i;
        pthread_create(&state[i].thread, NULL, client_thread, &state[i]);

    }

    for (i = 0; i < 2; ++i) {
        pthread_join(state[i].thread, NULL);
    }

    return 0;
} /* main */
