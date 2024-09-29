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

#include "core/evpl.h"
#include "core/test_log.h"

struct client_state {
    int run;
    int sent;
    int recv;
    int niters;
    uint32_t value;
};


int
client_callback(
    struct evpl *evpl,
    struct evpl_bind *bind,
    const struct evpl_notify *notify,
    void *private_data)
{
    struct client_state *state = private_data;
    uint32_t value;
    int length;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_CONNECTED:
        evpl_test_info("client connected");
        break;
    case EVPL_NOTIFY_RECV_DATA:

        length = evpl_recv(evpl, bind, &value, sizeof(value));

        if (length == sizeof(value)) {
        
            state->recv++;

            evpl_test_info("client received %u sent %u recv %u", value, state->sent, state->recv);

        }

        break;

    case EVPL_NOTIFY_DISCONNECTED:
        evpl_test_info("client disconnected");
        break;
    }

    return 0;
}

void *
client_thread(void *arg)
{
    struct evpl *evpl;
    struct evpl_endpoint *ep;
    struct evpl_bind *bind;
    struct client_state *state = arg;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "127.0.0.1", 8000);

    bind = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, ep, client_callback, state);

    while (state->recv != state->niters) {

        evpl_test_debug("client loop entry sent %u recv %u", 
            state->sent, state->recv);
   
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

    evpl_endpoint_close(evpl, ep);

    evpl_destroy(evpl);

    return NULL;
}

int server_callback(
    struct evpl *evpl,
    struct evpl_bind *bind,
    const struct evpl_notify *notify,
    void *private_data)
{
    uint32_t value;
    int length;

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
            evpl_test_debug("server received %u", value);
            evpl_send(evpl, bind, &value, sizeof(value));
        }

        break;
    }

    return 0;
}

void accept_callback(
    struct evpl_bind *bind,
    evpl_notify_callback_t *callback,
    void **conn_private_data,
    void       *private_data)
{
    const struct evpl_endpoint *ep = evpl_bind_endpoint(bind);

    evpl_test_info("Received connection from %s:%d",
        evpl_endpoint_address(ep),
        evpl_endpoint_port(ep));

    *callback = server_callback;
    *conn_private_data = private_data;
}
int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct evpl *evpl;
    struct evpl_endpoint *ep;
    struct client_state state = {
        .run = 1,
        .sent = 0,
        .recv = 0,
        .niters = 100,
        .value = 1
    };

    evpl_init(NULL);

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "0.0.0.0", 8000);

    evpl_listen(evpl, EVPL_STREAM_SOCKET_TCP, ep, accept_callback, NULL);

    pthread_create(&thr, NULL, client_thread, &state);

    while (state.run) {
        evpl_wait(evpl, 1);
    }

    pthread_join(thr, NULL);

    evpl_endpoint_close(evpl, ep);

    evpl_destroy(evpl);

    evpl_cleanup();

    return 0;
}
