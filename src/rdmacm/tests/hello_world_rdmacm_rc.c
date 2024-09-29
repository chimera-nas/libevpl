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
    struct evpl_bind *bind,
    const struct evpl_notify *notify,
    void *private_data)
{
    int *run = private_data;

    switch (notify->notify_type) {
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
    struct evpl_bvec bvec;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int run = 1;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "10.67.15.105", 8000);

    bind = evpl_connect(evpl, EVPL_RDMACM_RC, ep, client_callback, &run);

    evpl_bvec_alloc(evpl, slen, 0, 1, &bvec);

    memcpy(evpl_bvec_data(&bvec), hello, slen);

    evpl_sendv(evpl, bind, &bvec, 1, slen);

    while (run) {
        evpl_wait(evpl, -1);
    }

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
    struct evpl_bvec bvec;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);
    int *run = private_data;

    switch (notify->notify_type) {
    case EVPL_NOTIFY_DISCONNECTED:
        *run = 0;
        break;
    case EVPL_NOTIFY_RECEIVED_DATA:

        evpl_bvec_alloc(evpl, slen, 0, 1, &bvec);

        memcpy(evpl_bvec_data(&bvec), hello, slen);

        evpl_sendv(evpl, bind, &bvec, 1, slen);

        evpl_finish(evpl, bind);
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
    int run = 1;
    struct evpl_endpoint *ep;

    evpl = evpl_create();

    ep = evpl_endpoint_create(evpl, "10.67.15.105", 8000);

    evpl_listen(evpl, EVPL_RDMACM_RC, ep, accept_callback, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_endpoint_close(evpl, ep);

    evpl_destroy(evpl);

    return 0;
}
