#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/uio.h>

#include "eventpoll.h"
#include "eventpoll_internal.h"

void *
client_thread(void *arg)
{
    struct eventpoll *eventpoll;

    eventpoll = eventpoll_init(NULL);

    eventpoll_destroy(eventpoll);

    return NULL;
}

int accept_callback(
    const char *client_address,
    const char *server_address,
    void       *private_data)
{
    eventpoll_info("Accepting connection from %s to %s", client_address, server_address);

    return 0;
}

int server_recv_callback(
    struct iovec *iov,
    int niov,
    void *private_data)
{
    return 0;
}

int error_callback(
    int error_code,
    void *private_data)
{
    eventpoll_fatal("error_callback with error_code %d", error_code);
    return 0;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;
    struct eventpoll *eventpoll;

    eventpoll = eventpoll_init(NULL);


    eventpoll_listen(eventpoll, EVENTPOLL_PROTO_TCP,
                     "0.0.0.0", 8000, accept_callback, server_recv_callback, error_callback, NULL);

    pthread_create(&thr, NULL, client_thread, NULL);

    pthread_join(thr, NULL);

    eventpoll_destroy(eventpoll);

    return 0;
}
