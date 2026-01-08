// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

enum evpl_protocol_id proto       = EVPL_DATAGRAM_TCP_RDMA;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8100;

#define BUFFER_SIZE     4096
#define PATTERN_SERVER  0xAB
#define PATTERN_CLIENT  0xCD

/* Message types for our simple protocol */
#define MSG_TYPE_RDMA_INFO    1
#define MSG_TYPE_READ_DONE    2
#define MSG_TYPE_WRITE_DONE   3
#define MSG_TYPE_VERIFY_OK    4
#define MSG_TYPE_COMPLETE     5

struct rdma_info_msg {
    uint32_t msg_type;
    uint32_t rkey;
    uint64_t raddr;
    uint32_t length;
};

struct simple_msg {
    uint32_t msg_type;
    uint32_t status;
};

struct server_state {
    struct evpl       *evpl;
    struct evpl_bind  *bind;
    struct evpl_iovec  rdma_buffer;
    int                rdma_buffer_valid;
    int                phase;
    int                complete;
};

struct client_state {
    struct evpl       *server_evpl;
    struct evpl       *evpl;
    struct evpl_bind  *bind;
    struct evpl_iovec  local_buffer;
    int                local_buffer_valid;
    uint32_t           remote_rkey;
    uint64_t           remote_raddr;
    uint32_t           remote_length;
    int                phase;
    int                read_complete;
    int                write_complete;
    int                complete;
    int                passed;
};

int
test_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    return sizeof(struct rdma_info_msg);
} /* test_segment_callback */

/* Forward declaration */
static void rdma_write_callback(int status, void *private_data);

static void
rdma_read_callback(
    int   status,
    void *private_data)
{
    struct client_state *state = private_data;
    unsigned char       *buf;
    int                  i, match;

    evpl_test_info("RDMA READ completed with status %d", status);

    if (status != 0) {
        evpl_test_info("RDMA READ failed!");
        state->complete = 1;
        return;
    }

    state->read_complete = 1;

    /* Verify READ data */
    buf   = (unsigned char *) state->local_buffer.data;
    match = 1;
    for (i = 0; i < BUFFER_SIZE; i++) {
        if (buf[i] != PATTERN_SERVER) {
            evpl_test_info("RDMA READ data mismatch at offset %d: got 0x%02x, expected 0x%02x",
                           i, buf[i], PATTERN_SERVER);
            match = 0;
            break;
        }
    }

    if (match) {
        evpl_test_info("RDMA READ data verified successfully");
    } else {
        evpl_test_info("RDMA READ data verification failed");
        state->complete = 1;
        return;
    }

    /* Phase 2: RDMA WRITE to server with different pattern */
    /* Release the READ buffer (we're done with the data) and allocate new for WRITE */
    state->phase = 1;
    evpl_iovec_release(state->evpl, &state->local_buffer);
    evpl_iovec_alloc(state->evpl, BUFFER_SIZE, 1, 1, 0, &state->local_buffer);
    memset(state->local_buffer.data, PATTERN_CLIENT, BUFFER_SIZE);

    evpl_test_info("Initiating RDMA WRITE");
    evpl_rdma_write(state->evpl, state->bind,
                    state->remote_rkey,
                    state->remote_raddr,
                    &state->local_buffer, 1,
                    0,
                    rdma_write_callback, state);
} /* rdma_read_callback */

static void
rdma_write_callback(
    int   status,
    void *private_data)
{
    struct client_state *state = private_data;
    struct simple_msg    reply;

    evpl_test_info("RDMA WRITE completed with status %d", status);

    if (status != 0) {
        evpl_test_info("RDMA WRITE failed!");
        state->complete = 1;
        return;
    }

    state->write_complete = 1;
    state->phase          = 2;

    /* Send message to server to verify the write */
    evpl_test_info("RDMA WRITE complete, asking server to verify");

    reply.msg_type = MSG_TYPE_WRITE_DONE;
    reply.status   = 0;
    evpl_send(state->evpl, state->bind, &reply, sizeof(reply));
} /* rdma_write_callback */

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client_state   *state = private_data;
    struct rdma_info_msg  *rdma_info;
    struct simple_msg     *msg;
    struct simple_msg      reply;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("Client connected");
            break;

        case EVPL_NOTIFY_RECV_MSG:
            if (notify->recv_msg.length >= sizeof(struct rdma_info_msg)) {
                rdma_info = (struct rdma_info_msg *) notify->recv_msg.iovec[0].data;

                if (rdma_info->msg_type == MSG_TYPE_RDMA_INFO) {
                    evpl_test_info("Client received RDMA info: rkey=%u raddr=0x%lx len=%u",
                                   rdma_info->rkey, rdma_info->raddr, rdma_info->length);

                    state->remote_rkey   = rdma_info->rkey;
                    state->remote_raddr  = rdma_info->raddr;
                    state->remote_length = rdma_info->length;

                    /* Allocate local buffer for RDMA operations */
                    evpl_iovec_alloc(evpl, BUFFER_SIZE, 1, 1, 0, &state->local_buffer);
                    state->local_buffer_valid = 1;

                    /* Clear local buffer */
                    memset(state->local_buffer.data, 0, BUFFER_SIZE);

                    /* Phase 1: RDMA READ from server */
                    evpl_test_info("Initiating RDMA READ");
                    evpl_rdma_read(evpl, bind,
                                   state->remote_rkey,
                                   state->remote_raddr,
                                   &state->local_buffer, 1,
                                   rdma_read_callback, state);
                }
            } else if (notify->recv_msg.length >= sizeof(struct simple_msg)) {
                msg = (struct simple_msg *) notify->recv_msg.iovec[0].data;

                if (msg->msg_type == MSG_TYPE_VERIFY_OK) {
                    evpl_test_info("Server verified RDMA WRITE data - TEST PASSED!");
                    state->passed   = 1;
                    state->complete = 1;

                    /* Send completion message to server */
                    reply.msg_type = MSG_TYPE_COMPLETE;
                    reply.status   = 0;
                    evpl_send(evpl, bind, &reply, sizeof(reply));
                }
            }

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
            break;
    } /* switch */
} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *server;
    struct evpl_bind     *bind;
    struct client_state  *state = arg;

    evpl = evpl_create(NULL);
    state->evpl = evpl;

    server = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, server, client_callback,
                        test_segment_callback, state);

    state->bind = bind;

    while (!state->complete) {
        evpl_continue(evpl);
    }

    evpl_test_info("Client completed");

    evpl_stop(state->server_evpl);

    if (state->local_buffer_valid) {
        evpl_iovec_release(state->evpl, &state->local_buffer);
    }

    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct server_state  *state = private_data;
    struct simple_msg    *msg;
    struct simple_msg     reply;
    unsigned char        *buf;
    int                   i, match;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:
            msg = (struct simple_msg *) notify->recv_msg.iovec[0].data;

            if (msg->msg_type == MSG_TYPE_WRITE_DONE) {
                evpl_test_info("Server received WRITE_DONE, verifying data");

                /* Verify the data written by client */
                buf   = (unsigned char *) state->rdma_buffer.data;
                match = 1;
                for (i = 0; i < BUFFER_SIZE; i++) {
                    if (buf[i] != PATTERN_CLIENT) {
                        evpl_test_info("RDMA WRITE data mismatch at offset %d: got 0x%02x, expected 0x%02x",
                                       i, buf[i], PATTERN_CLIENT);
                        match = 0;
                        break;
                    }
                }

                if (match) {
                    evpl_test_info("Server verified RDMA WRITE data successfully");
                    reply.msg_type = MSG_TYPE_VERIFY_OK;
                    reply.status   = 0;
                } else {
                    evpl_test_info("Server RDMA WRITE verification failed");
                    reply.msg_type = MSG_TYPE_VERIFY_OK;
                    reply.status   = 1;
                }

                evpl_send(evpl, bind, &reply, sizeof(reply));

            } else if (msg->msg_type == MSG_TYPE_COMPLETE) {
                evpl_test_info("Server received COMPLETE message");
                state->complete = 1;
            }

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
            break;
    } /* switch */
} /* server_callback */

void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    struct server_state  *state = private_data;
    struct rdma_info_msg  rdma_info;
    uint32_t              rkey;
    uint64_t              raddr;

    evpl_test_info("Server accepted connection");

    state->bind = bind;

    /* Allocate RDMA buffer and fill with pattern */
    evpl_iovec_alloc(evpl, BUFFER_SIZE, 1, 1, 0, &state->rdma_buffer);
    state->rdma_buffer_valid = 1;
    memset(state->rdma_buffer.data, PATTERN_SERVER, BUFFER_SIZE);

    /* Get RDMA address for the buffer */
    evpl_rdma_get_address(evpl, bind, &state->rdma_buffer, &rkey, &raddr);

    evpl_test_info("Server RDMA buffer: rkey=%u raddr=0x%lx", rkey, raddr);

    /* Send RDMA info to client */
    rdma_info.msg_type = MSG_TYPE_RDMA_INFO;
    rdma_info.rkey     = rkey;
    rdma_info.raddr    = raddr;
    rdma_info.length   = BUFFER_SIZE;

    evpl_send(evpl, bind, &rdma_info, sizeof(rdma_info));

    *notify_callback   = server_callback;
    *segment_callback  = test_segment_callback;
    *conn_private_data = private_data;
} /* accept_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t                     thr;
    struct evpl                  *evpl;
    struct evpl_endpoint         *me;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    int                           rc, opt;
    struct server_state           server_state = { 0 };
    struct client_state           client_state = { 0 };

    test_evpl_config();

    while ((opt = getopt(argc, argv, "a:p:r:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [-r protocol] [-a address] [-p port]\n",
                        argv[0]);
                return 1;
        } /* switch */
    }

    evpl = evpl_create(NULL);

    server_state.evpl       = evpl;
    client_state.server_evpl = evpl;

    me = evpl_endpoint_create("0.0.0.0", port);

    listener = evpl_listener_create();

    binding = evpl_listener_attach(evpl, listener, accept_callback, &server_state);

    evpl_listen(listener, proto, me);

    pthread_create(&thr, NULL, client_thread, &client_state);

    evpl_run(evpl);

    pthread_join(thr, NULL);

    evpl_listener_detach(evpl, binding);

    evpl_listener_destroy(listener);

    if (server_state.rdma_buffer_valid) {
        evpl_iovec_release(evpl, &server_state.rdma_buffer);
    }

    evpl_destroy(evpl);

    return client_state.passed ? 0 : 1;
} /* main */
