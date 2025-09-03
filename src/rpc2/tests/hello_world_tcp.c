// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>

#include "core/evpl.h"
#include "rpc2/rpc2.h"

#include "core/internal.h"

#include "hello_world_tcp_xdr.h"

typedef void (*GreetingCallback)(
    struct Hello *msg,
    void         *private_data);


void
hello_greeting_call(
    struct evpl_rpc2_agent *agent,
    struct evpl_conn       *conn,
    struct Hello           *hello,
    GreetingCallback        callback,
    void                   *private_data)
{

} /* hello_greeting_call */

int
client_callback(
    struct evpl      *evpl,
    struct evpl_conn *conn,
    unsigned int      event_type,
    unsigned int      event_code,
    void             *private_data)
{
    int *run = private_data;

    evpl_info("client callback event %u code %u", event_type, event_code);

    switch (event_type) {
        case EVPL_EVENT_DISCONNECTED:
            *run = 0;
            break;
    } /* switch */

    return 0;
} /* client_callback */

void
client_dispatch(
    struct evpl_rpc2_agent   *agent,
    struct evpl_rpc2_request *msg,
    void                     *private_data)
{
    evpl_info("Received rpc2 request");
} /* client_dispatch */

void *
client_thread(void *arg)
{
    struct evpl            *evpl;
    struct evpl_rpc2_agent *agent;
    struct evpl_conn       *conn;
    struct Hello            hello;
    static const char       hello_string[] = "Hello World!";
    int                     run            = 1;

    evpl = evpl_init(NULL);

    agent = evpl_rpc2_init(evpl);

    conn = evpl_rpc2_connect(agent, EVPL_PROTO_TCP, "127.0.0.1", 8000,
                             client_dispatch, &run);

    hello.id = 42;

    xdr_set_str_static(&hello, greeting, hello_string, strlen(hello_string));

    evpl_rpc2_call(agent, conn, 1, 1, 1);

    while (run) {

        evpl_wait(evpl, -1);
    }

    evpl_debug("client loop out");

    evpl_close(evpl, conn);
    evpl_rpc2_destroy(agent);
    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

int
server_callback(
    struct evpl      *evpl,
    struct evpl_conn *conn,
    unsigned int      event_type,
    unsigned int      event_code,
    void             *private_data)
{
    //struct evpl_iovec iovec, *iovecp;
    //const char hello[] = "Hello World!";
    //int slen = strlen(hello);
    int *run = private_data;

    evpl_info("server callback event %u code %u", event_type, event_code);

    switch (event_type) {
        case EVPL_EVENT_DISCONNECTED:
            *run = 0;
            break;
        case EVPL_EVENT_RECEIVED:

/*
 *      evpl_iovec_alloc(evpl, slen, 0, &iovec);
 *
 *      memcpy(evpl_iovec_data(&iovec), hello, slen);
 *
 *      iovecp = &iovec;
 *
 *      evpl_send(evpl, conn, &iovecp, 1);
 *
 *      evpl_finish(evpl, conn);
 */
            break;
    } /* switch */

    return 0;
} /* server_callback */

void
server_dispatch(
    struct evpl_rpc2_agent   *agent,
    struct evpl_rpc2_request *msg,
    void                     *private_data)
{
    evpl_info("Received rpc2 request");
} /* server_dispatch */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t               thr;
    struct evpl            *evpl;
    struct evpl_rpc2_agent *agent;
    int                     run = 1;

    evpl = evpl_init(NULL);

    agent = evpl_rpc2_init(evpl);

    evpl_rpc2_listen(agent, EVPL_PROTO_TCP,
                     "0.0.0.0", 8000, server_dispatch, &run);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_wait(evpl, -1);
    }

    pthread_join(thr, NULL);

    evpl_rpc2_destroy(agent);
    evpl_destroy(evpl);

    return 0;
} /* main */
