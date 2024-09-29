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
    int *run = private_data;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_RECV_DATAGRAM:

        evpl_test_info("client received '%s'", notify->recv_msg.bvec[0].data);

        *run = 0;

        break;
    }

    return 0;
}

void *
client_thread(void *arg)
{
    struct evpl *evpl;
    struct evpl_endpoint *me, *server;
    struct evpl_bind *bind;
    int run = 1;

    evpl = evpl_create();

    me = evpl_endpoint_create(evpl, "127.0.0.1", 8001);
    server = evpl_endpoint_create(evpl, "127.0.0.1", 8000);

    bind = evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, me, client_callback, &run);

    evpl_sendto(evpl, bind,  server, hello, hellolen);

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
    struct evpl_endpoint *client;
    int *run = private_data;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_RECV_DATAGRAM:
   
        evpl_test_info("server received '%s'", notify->recv_msg.bvec[0].data); 

        client = evpl_endpoint_create(evpl, "127.0.0.1", 8001);

        evpl_sendto(evpl, bind, client, hello, hellolen);

        evpl_finish(evpl, bind);

        break;

    case EVPL_NOTIFY_DISCONNECTED:
        *run = 0;

        break;
    }

    return 0;
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

    evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, ep, server_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
}
