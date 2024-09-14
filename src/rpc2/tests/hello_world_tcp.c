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
#include "core/internal.h"

int
client_callback(
    struct evpl *evpl,
    struct evpl_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    int *run = private_data;

    evpl_info("client callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVPL_EVENT_DISCONNECTED:
        *run = 0;
        break;
    }

    return 0;
}

void *
client_thread(void *arg)
{
    struct evpl *evpl;
    struct evpl_conn *conn;
    struct evpl_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int run = 1;

    evpl = evpl_init(NULL);

    conn = evpl_connect(evpl, EVPL_PROTO_TCP, "127.0.0.1", 8000,
                      client_callback, &run);

    evpl_bvec_alloc(evpl, slen, 0, &bvec);

    memcpy(evpl_bvec_data(&bvec), hello, slen);

    bvecp = &bvec;

    evpl_send(evpl, conn, &bvecp, 1);

    while (run) {
    
        evpl_wait(evpl, -1);
    }

    evpl_debug("client loop out");

    evpl_destroy(evpl);

    return NULL;
}

int server_callback(
    struct evpl *evpl,
    struct evpl_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    struct evpl_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int *run = private_data;

    evpl_info("server callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVPL_EVENT_DISCONNECTED:
        *run = 0;
        break;
    case EVPL_EVENT_RECEIVED:

        evpl_bvec_alloc(evpl, slen, 0, &bvec);

        memcpy(evpl_bvec_data(&bvec), hello, slen);

        bvecp = &bvec;

        evpl_send(evpl, conn, &bvecp, 1);

        evpl_finish(evpl, conn);
        break;
    }

    return 0;
}

void accept_callback(
    struct evpl_conn *conn,
    evpl_event_callback_t *callback,
    void **conn_private_data,
    void       *private_data)
{
    evpl_info("Received connection from %s:%d",
        evpl_conn_address(conn),
        evpl_conn_port(conn));

    *callback = server_callback;
    *conn_private_data = private_data;
}
int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct evpl *evpl;
    int run = 1;

    evpl = evpl_init(NULL);


    evpl_listen(evpl, EVPL_PROTO_TCP,
                     "0.0.0.0", 8000, accept_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
}
