// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <evpl/evpl.h>

/* This example implements a echo server that uses datagram semantics.
 * The wire protocol is a four byte little endian msg length followed by the payload.
 * of that length.   For usage over TCP, we provide a segmentation callback to teach
 * libevpl how to break up the stream into messages.  For pure datagram protocols,
 * like RDMA RC, the segmentation callback is not used, but is not harmful to provide
 * regardless for protocol agnosticism.
 */

#define TRANSFER_SIZE (1024 * 1024)  /* 1MB */

struct client_state {
    int done;
};

struct server_state {
    int             ready;
    int             run;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
};

int
echo_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    uint32_t hdr;
    int      length;

    /* Try to peek at the next four byte header */
    length = evpl_peek(evpl, bind, &hdr, sizeof(hdr));

    if (length < sizeof(hdr)) {
        /* We need more data to segment next message */
        return 0;
    }

    /* Next message is the length specified by the header plus the header itself */
    return hdr + sizeof(hdr);
} /* segment_callback */

/* Server callback - echoes received data back to client */
void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct server_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            /* We know we received exactly one whole message */

            printf("[Server] Echoing %d bytes\n", notify->recv_msg.length);

            /* sendv takes ownership of the iovecs, so no release needed */
            evpl_sendv(evpl, bind, notify->recv_msg.iovec, notify->recv_msg.niov, notify->recv_msg.length);

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            state->run = 0;     /* Stop the server */
            break;
    } /* switch */
} /* server_callback */


/* Accept callback - sets up the server callback for new connections */
void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *segment_callback  = echo_segment_callback;
    *conn_private_data = private_data;     /* Pass server state */
} /* accept_callback */


/* Server thread - runs event loop and accepts connections */
void *
server_thread(void *arg)
{
    struct server_state          *state = arg;
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;

    /* Create evpl context for the server thread */
    evpl = evpl_create(NULL);

    /* Create endpoint (localhost, port 8000) */
    endpoint = evpl_endpoint_create("127.0.0.1", 8000);

    /* Create and configure listener */
    listener = evpl_listener_create();

    /* Attach listener to the evpl context */
    binding = evpl_listener_attach(evpl, listener, accept_callback, state);

    /* Start listening for incoming connections */
    evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint);

    printf("[Server] Listening on port 8000\n");

    /* Notify main thread we are ready so client thread can be started */
    pthread_mutex_lock(&state->mutex);
    state->ready = 1;
    pthread_cond_signal(&state->cond);
    pthread_mutex_unlock(&state->mutex);

    /* Run event loop until stopped by the main thread */
    while (state->run) {
        evpl_continue(evpl);
    }

    printf("[Server] Shutting down\n");

    /* Cleanup */
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    evpl_destroy(evpl);

    return NULL;
} /* server_thread */


/* Client callback - sends 1MB and receives echo in chunks */
void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client_state *state = private_data;
    struct evpl_iovec    iov[8];
    uint32_t            *hdr;
    int                  niov;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            printf("[Client] Connected! Sending %d bytes\n", TRANSFER_SIZE + (int) sizeof(uint32_t));

            /* Get a four byte io vector for the header, force it to be contiguous */
            niov = evpl_iovec_alloc(evpl, sizeof(uint32_t), 0, 1, &iov[0]);
            /* Followed by TRANSFER_SIZE worth of buffer for the payload, not necessarily contiguous */
            niov += evpl_iovec_alloc(evpl, TRANSFER_SIZE, 0,  7, &iov[1]);

            /* Set the header to the transfer size */
            hdr  = evpl_iovec_data(&iov[0]);
            *hdr = TRANSFER_SIZE;

            /* Fill the payload iovec(s) with 0xbe */
            for (int i = 1; i < niov; i++) {
                memset(evpl_iovec_data(&iov[i]), 0xbf, evpl_iovec_length(&iov[i]));
            }

            /* evpl owns iovecs after send */
            evpl_sendv(evpl, bind, iov, niov, TRANSFER_SIZE + sizeof(uint32_t));

            break;

        case EVPL_NOTIFY_RECV_MSG:

            /* We know we received exactly one whole message */

            printf("[Client] Received %d bytes\n", notify->recv_msg.length);

            /* Release buffers - we're done with them */
            for (int i = 0; i < notify->recv_msg.niov; i++) {
                evpl_iovec_release(&notify->recv_msg.iovec[i]);
            }

            state->done = 1;

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            /* Client is done */
            break;
    } /* switch */
} /* client_callback */


/* Client thread - connects and transfers data */
void *
client_thread(void *arg)
{
    struct client_state  *state = arg;
    struct evpl          *evpl;
    struct evpl_endpoint *endpoint;
    struct evpl_bind     *bind;

    /* Create evpl context for the client thread */
    evpl = evpl_create(NULL);

    /* Connect to server */
    endpoint = evpl_endpoint_create("127.0.0.1", 8000);
    bind     = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP,
                            NULL, endpoint, client_callback, echo_segment_callback, state);

    if (!bind) {
        fprintf(stderr, "[Client] Failed to connect\n");
        evpl_destroy(evpl);
        return NULL;
    }

    /* Run event loop until transfer completes */
    while (!state->done) {
        evpl_continue(evpl);
    }

    printf("[Client] Transfer complete\n");

    /* Explicitly closing endpoints is optional, otherwise they are cleaned up on process exit */
    evpl_endpoint_close(endpoint);

    /* Destroy the evpl context before the thread exits */
    evpl_destroy(evpl);

    return NULL;
} /* client_thread */


int
main(
    int   argc,
    char *argv[])
{
    struct server_state server_state = { .run = 1, .ready = 0 };
    struct client_state client_state = { 0 };
    pthread_t           server_tid;
    pthread_t           client_tid;

    pthread_mutex_init(&server_state.mutex, NULL);
    pthread_cond_init(&server_state.cond, NULL);

    /* Initialize libevpl */
    evpl_init(NULL);

    /* Start server thread */
    printf("Starting server thread\n");
    pthread_create(&server_tid, NULL, server_thread, &server_state);


    pthread_mutex_lock(&server_state.mutex);
    while (!server_state.ready) {
        pthread_cond_wait(&server_state.cond, &server_state.mutex);
    }
    pthread_mutex_unlock(&server_state.mutex);

    /* Start client thread */
    printf("Starting client thread\n");
    pthread_create(&client_tid, NULL, client_thread, &client_state);

    /* Wait for client to finish */
    pthread_join(client_tid, NULL);

    /* Stop server */
    server_state.run = 0;

    pthread_join(server_tid, NULL);

    return 0;
} /* main */
