#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>

#include "eventpoll.h"
#include "eventpoll_internal.h"

int client_recv_callback(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn,
    struct iovec *iov,
    int niov,
    void *private_data)
{
    eventpoll_info("client recv callback");
    return 0;
}

void 
test_error_callback(
    int error_code,
    void *private_data)
{
    eventpoll_fatal("error_callback with error_code %d", error_code);
}

void *
client_thread(void *arg)
{
    struct eventpoll *eventpoll;
    struct eventpoll_conn *conn;
    struct eventpoll_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);

    eventpoll = eventpoll_init(NULL);

    conn = eventpoll_connect(eventpoll, EVENTPOLL_PROTO_TCP, "127.0.0.1", 8000,
                      client_recv_callback, test_error_callback, NULL);

    eventpoll_bvec_alloc(eventpoll, slen, 0, &bvec);

    memcpy(eventpoll_bvec_data(&bvec), hello, slen);

    bvecp = &bvec;

    eventpoll_send(eventpoll, conn, &bvecp, 1);

    while (1) {
    
        eventpoll_wait(eventpoll, -1);
    }

    eventpoll_destroy(eventpoll);

    return NULL;
}

int server_recv_callback(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn,
    struct iovec *iov,
    int niov,
    void *private_data)
{
    struct eventpoll_bvec bvec, *bvecp;
    const char hello[] = "Hello World!";
    int slen = strlen(hello);

    eventpoll_info("Received server recv callback niov %d", niov);

    eventpoll_bvec_alloc(eventpoll, slen, 0, &bvec);

    memcpy(eventpoll_bvec_data(&bvec), hello, slen);

    bvecp = &bvec;

    eventpoll_send(eventpoll, conn, &bvecp, 1);
    return 0;
}

void accept_callback(
    struct eventpoll_conn *conn,
    eventpoll_recv_callback_t  *recv_callback,
    eventpoll_error_callback_t  *error_callback,
    void **conn_private_data,
    void       *private_data)
{
    eventpoll_info("Received connection from %s:%d",
        eventpoll_conn_address(conn),
        eventpoll_conn_port(conn));

    *recv_callback = server_recv_callback;
    *error_callback = test_error_callback;
    *conn_private_data = NULL;
}
int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct eventpoll *eventpoll;

    eventpoll = eventpoll_init(NULL);


    eventpoll_listen(eventpoll, EVENTPOLL_PROTO_TCP,
                     "0.0.0.0", 8000, accept_callback, NULL);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (1) {
        eventpoll_wait(eventpoll, -1);
    }

    pthread_join(thr, NULL);

    eventpoll_destroy(eventpoll);

    return 0;
}
