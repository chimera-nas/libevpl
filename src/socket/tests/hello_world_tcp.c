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

const char hello[] = "Hello World!";
const int  hellolen = strlen(hello) + 1;


int
client_callback(
    struct evpl *evpl,
    struct evpl_bind *bind,
    const struct evpl_notify *notify,
    void *private_data)
{
    char buffer[hellolen];
    int length, *run = private_data;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_RECV_DATA:

        length = evpl_recv(evpl, bind, buffer, hellolen);

        if (length == hellolen) {
            evpl_test_info("client received '%s'", buffer);
        }

        break;

    case EVPL_NOTIFY_DISCONNECTED:
        *run = 0;
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
    int run = 1;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "127.0.0.1", 8000);

    bind = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, ep, client_callback, &run);


    evpl_send(evpl, bind, hello, hellolen);

    while (run) {
    
        evpl_wait(evpl, -1);
    }

    evpl_destroy(evpl);

    return NULL;
}

int server_callback(
    struct evpl *evpl,
    struct evpl_bind *bind,
    const struct evpl_notify *notify,
    void *private_data)
{
    char buffer[hellolen];
    int length, *run = private_data;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_DISCONNECTED:
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
    }

    return 0;
}

void accept_callback(
    struct evpl_bind *bind,
    evpl_notify_callback_t *callback,
    void **conn_private_data,
    void       *private_data)
{
    *callback = server_callback;
    *conn_private_data = private_data;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct evpl *evpl;
    int run = 1;
    struct evpl_endpoint *ep;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "0.0.0.0", 8000);

    evpl_listen(evpl, EVPL_STREAM_SOCKET_TCP, ep, accept_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
}
