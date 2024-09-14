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

#include "core/eventpoll.h"
#include "core/internal.h"

int
client_callback(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    int *run = private_data;

    eventpoll_info("client callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVENTPOLL_EVENT_DISCONNECTED:
        *run = 0;
        break;
    }

    return 0;
}

void *
client_thread(void *arg)
{
    struct eventpoll *eventpoll;
    struct eventpoll_conn *conn;
    struct eventpoll_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int run = 1;

    eventpoll = eventpoll_init(NULL);

    conn = eventpoll_connect(eventpoll, EVENTPOLL_PROTO_TCP, "127.0.0.1", 8000,
                      client_callback, &run);

    eventpoll_bvec_alloc(eventpoll, slen, 0, &bvec);

    memcpy(eventpoll_bvec_data(&bvec), hello, slen);

    bvecp = &bvec;

    eventpoll_send(eventpoll, conn, &bvecp, 1);

    while (run) {
    
        eventpoll_wait(eventpoll, -1);
    }

    eventpoll_debug("client loop out");

    eventpoll_destroy(eventpoll);

    return NULL;
}

int server_callback(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    struct eventpoll_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int *run = private_data;

    eventpoll_info("server callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVENTPOLL_EVENT_DISCONNECTED:
        *run = 0;
        break;
    case EVENTPOLL_EVENT_RECEIVED:

        eventpoll_bvec_alloc(eventpoll, slen, 0, &bvec);

        memcpy(eventpoll_bvec_data(&bvec), hello, slen);

        bvecp = &bvec;

        eventpoll_send(eventpoll, conn, &bvecp, 1);

        eventpoll_finish(eventpoll, conn);
        break;
    }

    return 0;
}

void accept_callback(
    struct eventpoll_conn *conn,
    eventpoll_event_callback_t *callback,
    void **conn_private_data,
    void       *private_data)
{
    eventpoll_info("Received connection from %s:%d",
        eventpoll_conn_address(conn),
        eventpoll_conn_port(conn));

    *callback = server_callback;
    *conn_private_data = private_data;
}
int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct eventpoll *eventpoll;
    int run = 1;

    eventpoll = eventpoll_init(NULL);


    eventpoll_listen(eventpoll, EVENTPOLL_PROTO_TCP,
                     "0.0.0.0", 8000, accept_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        eventpoll_wait(eventpoll, -1);
    }

    pthread_join(thr, NULL);

    eventpoll_destroy(eventpoll);

    return 0;
}
