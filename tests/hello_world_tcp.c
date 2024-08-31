#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/uio.h>

#include "eventpoll.h"
#include "eventpoll_internal.h"

int client_recv_callback(
    struct iovec *iov,
    int niov,
    void *private_data)
{
    eventpoll_info("client recv callback\n");
    return 0;
}

int error_callback(
    int error_code,
    void *private_data)
{
    eventpoll_fatal("error_callback with error_code %d", error_code);
    return 0;
}

int client_connect_callback(
    struct eventpoll_conn *conn,
    void       *private_data)
{
    eventpoll_info("Connected to %s:%d", 
        eventpoll_conn_address(conn),
        eventpoll_conn_port(conn));

    return 0;
}

void *
client_thread(void *arg)
{
    struct eventpoll *eventpoll;

    eventpoll = eventpoll_init(NULL);

    eventpoll_info("Client connecting");
    eventpoll_connect(eventpoll, EVENTPOLL_PROTO_TCP, "127.0.0.1", 8000,
                      client_connect_callback, client_recv_callback, error_callback, NULL);

    eventpoll_info("Client waiting");

    while (1) {
    
        eventpoll_wait(eventpoll, -1);
    }

    eventpoll_destroy(eventpoll);

    return NULL;
}

int server_connect_callback(
    struct eventpoll_conn *conn,
    void       *private_data)
{
    eventpoll_info("Received connection from %s:%d",
        eventpoll_conn_address(conn),
        eventpoll_conn_port(conn));

    return 0;
}

int server_recv_callback(
    struct iovec *iov,
    int niov,
    void *private_data)
{
    eventpoll_info("server recv callback\n");
    return 0;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct eventpoll *eventpoll;

    eventpoll = eventpoll_init(NULL);


    eventpoll_listen(eventpoll, EVENTPOLL_PROTO_TCP,
                     "0.0.0.0", 8000, server_connect_callback, server_recv_callback, error_callback, NULL);

    pthread_create(&thr, NULL, client_thread, NULL);

    while (1) {
        eventpoll_wait(eventpoll, -1);
    }

    pthread_join(thr, NULL);

    eventpoll_destroy(eventpoll);

    return 0;
}
