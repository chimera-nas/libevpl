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

int
client_callback(
    struct evpl *evpl,
    struct evpl_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    int *run = private_data;

    evpl_test_info("client callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVPL_EVENT_DISCONNECTED:
        evpl_test_debug("setting run 0");
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
    struct evpl_conn *conn;
    struct evpl_bvec bvec;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int run = 1;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "10.67.15.105", 8000);

    conn = evpl_connect(evpl, EVPL_CONN_RDMACM_RC, ep, client_callback, &run);

    evpl_bvec_alloc(evpl, slen, 0, 1, &bvec);

    memcpy(evpl_bvec_data(&bvec), hello, slen);

    evpl_send(evpl, conn, &bvec, 1);

    while (run) {
        evpl_wait(evpl, -1);
    }

    evpl_test_debug("client loop out");

    evpl_close(evpl, conn);

    evpl_endpoint_close(evpl, ep);

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
    struct evpl_bvec bvec;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int *run = private_data;

    evpl_test_info("server callback event %u code %u", event_type, event_code);

    switch (event_type) {
    case EVPL_EVENT_DISCONNECTED:
        *run = 0;
        break;
    case EVPL_EVENT_RECEIVED:

        evpl_bvec_alloc(evpl, slen, 0, 1, &bvec);

        memcpy(evpl_bvec_data(&bvec), hello, slen);

        evpl_send(evpl, conn, &bvec, 1);

        evpl_test_debug("finishing conn");
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
    const struct evpl_endpoint *ep = evpl_conn_endpoint(conn);

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
    struct evpl_listener *listener;
    int run = 1;
    struct evpl_endpoint *ep;

    evpl_init(NULL);

    evpl = evpl_create();


    ep = evpl_endpoint_create(evpl, "10.67.15.105", 8000);

    listener = evpl_listen(evpl, EVPL_CONN_RDMACM_RC, ep, accept_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_listener_destroy(evpl, listener);

    evpl_endpoint_close(evpl, ep);

    evpl_destroy(evpl);

    evpl_cleanup();

    return 0;
}
