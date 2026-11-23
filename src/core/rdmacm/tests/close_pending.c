// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * Closing an RDMA CM connection while RDMA operations are in flight and
 * queued.  Every operation completes exactly once, and before the client's
 * DISCONNECTED notification (each callback records whether it had already
 * been delivered; it never may have been): one the queue pair ran
 * with the status the hardware gave it (0 if it finished, EIO if the close
 * flushed it), one still queued with ECONNRESET.  The bind is kept until the
 * hardware has returned every posted operation, so at least one flushed
 * operation reports EIO; and a closing bind posts nothing more, so at
 * least one reports ECONNRESET.  The library drops every reference it took
 * to the buffers.
 *
 * Which operations were posted is read from the bind's outstanding count (the
 * gate's own counter) plus those already completed.  The error-count check
 * (done + eio >= posted) therefore reads the gate's own counter, not an
 * independent one.  The outcome of the peer-close case depends on timing.
 *
 * Every posted operation must complete from its queue pair (0 or EIO) and never with ECONNRESET:
 * without the gate the bind can be destroyed while posted operations are in
 * flight, they are then completed with ECONNRESET, and their late completions
 * are dropped.  A closing connection posts nothing more, so in the local
 * close case exactly the operations posted before evpl_close complete from
 * the queue pair, and writes queued after evpl_close complete with
 * ECONNRESET.
 *
 * Two cases, after rdma_conformance's Close and PeerClose: this side closes,
 * and the peer closes.  Each queues more reads than a queue pair may have in
 * flight (at most 16), and each read moves 1 MiB, so the posted ones are
 * still running when the close lands.
 *
 * Optional argument: the first of the two ports to use (default 8019).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The core headers first: they define what the public ones leave opaque. */
#include "core/bind.h"
#include "evpl/evpl.h"
#include "core/test_log.h"

#define REGION_SIZE     (1024 * 1024)
#define NUM_READS       48
#define NUM_WRITES      8
#define NUM_LATE_WRITES 8
#define NUM_OPS         (NUM_READS + NUM_WRITES + NUM_LATE_WRITES)

struct operation {
    int called;
    int status;
    int after_disconnect;
};

static struct evpl      *client, *server;
static struct evpl_bind *client_bind, *server_bind;
static struct operation  operations[NUM_OPS];
static int               connected, disconnected, client_disconnected;
static int               num_ops, posted;
static const char       *case_name;

static void
completed(
    int   status,
    void *arg)
{
    struct operation *operation = arg;

    evpl_test_abort_if(operation->called++, "%s: operation %d completed twice",
                       case_name, (int) (operation - operations));
    operation->status           = status;
    operation->after_disconnect = client_disconnected;
} /* completed */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *arg)
{
    (void) bind;
    (void) arg;

    if (event->notify_type == EVPL_NOTIFY_CONNECTED) {
        connected++;
    } else if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        disconnected++;
        if (evpl == client) {
            client_disconnected = 1;
            client_bind         = NULL;
        } else {
            server_bind = NULL;
        }
    }
} /* notify */

static void
accepted(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **private_data,
    void                    *arg)
{
    (void) evpl;
    (void) arg;

    server_bind   = bind;
    *callback     = notify;
    *segment      = NULL;
    *private_data = NULL;
} /* accepted */

/* How many of the client's operations have been posted so far: those still
 * held by the gate plus those already completed.  Read only while the client
 * bind exists; the count never falls, so the last reading is a lower bound on
 * what was posted. */
static void
sample_posted(void)
{
    int i, n;

    if (!client_bind) {
        return;
    }

    n = (int) client_bind->outstanding;
    for (i = 0; i < num_ops; i++) {
        n += operations[i].called;
    }

    if (n > posted) {
        posted = n;
    }
} /* sample_posted */

static void
pump(void)
{
    evpl_continue(client);
    evpl_continue(server);
    sample_posted();
} /* pump */

static struct evpl *
loop(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 0);
    return evpl_create(config);
} /* loop */

static void
run(
    const char *name,
    const char *address,
    int         port,
    int         peer_close)
{
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;
    struct evpl_iovec             local, remote, iov, spare;
    uint32_t                      key;
    uint64_t                      raddr;
    int                           i, n, eio = 0, reset = 0, done = 0;
    int                           posted_at_close = -1;

    case_name           = name;
    num_ops             = peer_close ? NUM_READS + NUM_WRITES : NUM_OPS;
    posted              = 0;
    connected           = 0;
    disconnected        = 0;
    client_disconnected = 0;
    memset(operations, 0, sizeof(operations));

    client   = loop();
    server   = loop();
    listener = evpl_listener_create();
    endpoint = evpl_endpoint_create(address, port);
    binding  = evpl_listener_attach(server, listener, accepted, NULL);
    evpl_test_abort_if(evpl_listen(listener, EVPL_DATAGRAM_RDMACM_RC, endpoint),
                       "%s: listen failed", name);

    client_bind = evpl_connect(client, EVPL_DATAGRAM_RDMACM_RC, NULL, endpoint,
                               notify, NULL, NULL);
    evpl_test_abort_if(!client_bind, "%s: connect failed", name);
    for (n = 0; n < 10000 && connected != 2; n++) {
        pump();
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(connected != 2, "%s: handshake timed out", name);

    evpl_test_abort_if(evpl_iovec_alloc(client, REGION_SIZE, 1, 1, 0, &local) != 1 ||
                       evpl_iovec_alloc(server, REGION_SIZE, 1, 1, 0, &remote) != 1,
                       "%s: allocation failed", name);
    /* The allocator keeps a reference on its current buffer, which local
     * fills.  A further allocation makes it retire that buffer, so only the
     * test's own reference remains on local's. */
    evpl_test_abort_if(evpl_iovec_alloc(client, 1, 1, 1, 0, &spare) != 1,
                       "%s: allocation failed", name);
    evpl_iovec_release(client, &spare);
    evpl_test_abort_if(evpl_iovec_get_ref(&local)->refcnt != 1,
                       "%s: local buffer has %u references before the run", name,
                       evpl_iovec_get_ref(&local)->refcnt);
    memset(remote.data, 0xa5, REGION_SIZE);
    evpl_rdma_get_address(server, server_bind, &remote, &key, &raddr);
    evpl_test_abort_if(!key || !raddr, "%s: buffer has no RDMA registration", name);

    for (i = 0; i < NUM_READS + NUM_WRITES; i++) {
        evpl_iovec_clone(&iov, &local);
        if (i < NUM_READS) {
            evpl_rdma_read(client, client_bind, key, raddr, &iov, 1,
                           completed, &operations[i]);
        } else {
            evpl_rdma_write(client, client_bind, key, raddr, &iov, 1, 0,
                            completed, &operations[i]);
        }
        evpl_iovec_release(client, &iov);
    }

    /* The client's first pass posts as many reads as the queue pair may have
     * in flight; the rest stay queued. */
    evpl_continue(client);
    evpl_continue(client);
    sample_posted();

    if (peer_close) {
        evpl_close(server, server_bind);
    } else {
        posted_at_close = posted;
        evpl_close(client, client_bind);

        /* Queued on a closing bind: never posted, so ECONNRESET. */
        for (i = NUM_READS + NUM_WRITES; i < NUM_OPS; i++) {
            evpl_iovec_clone(&iov, &local);
            evpl_rdma_write(client, client_bind, key, raddr, &iov, 1, 0,
                            completed, &operations[i]);
            evpl_iovec_release(client, &iov);
        }
    }

    for (n = 0; n < 10000 && disconnected != 2; n++) {
        pump();
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(disconnected != 2, "%s: close did not disconnect both ends", name);
    for (n = 0; n < 32; n++) {
        pump();
    }

    for (i = 0; i < num_ops; i++) {
        evpl_test_abort_if(operations[i].called != 1,
                           "%s: operation %d completed %d times, expected once",
                           name, i, operations[i].called);
        /* A flushed completion polled after the bind was destroyed would
         * show here: the gate keeps the bind, and so DISCONNECTED, back until
         * every one is in. */
        evpl_test_abort_if(operations[i].after_disconnect,
                           "%s: operation %d completed after DISCONNECTED", name, i);
        evpl_test_abort_if(operations[i].status != 0 &&
                           operations[i].status != EIO &&
                           operations[i].status != ECONNRESET,
                           "%s: operation %d completed with %d", name, i,
                           operations[i].status);
        if (i >= NUM_READS + NUM_WRITES) {
            evpl_test_abort_if(operations[i].status != ECONNRESET,
                               "%s: write %d queued after the close completed with %d, "
                               "expected ECONNRESET", name, i, operations[i].status);
            continue;
        }
        eio   += operations[i].status == EIO;
        reset += operations[i].status == ECONNRESET;
        done  += operations[i].status == 0;
    }

    evpl_test_info("%s: %d posted (at least), %d completed, %d flushed (EIO), "
                   "%d never posted (ECONNRESET), %d queued after the close",
                   name, posted, done, eio, reset,
                   num_ops - NUM_READS - NUM_WRITES);

    /* Each posted operation completed from its queue pair while the bind
     * still existed (the DISCONNECTED check above), not with ECONNRESET. */
    evpl_test_abort_if(done + eio < posted,
                       "%s: %d operations were posted but only %d completed from "
                       "the queue pair", name, posted, done + eio);
    evpl_test_abort_if(posted_at_close >= 0 && done + eio != posted_at_close,
                       "%s: %d operations were posted before the close but %d "
                       "completed from the queue pair", name, posted_at_close,
                       done + eio);

    evpl_test_abort_if(reset == 0, "%s: no operation was still queued at close", name);
    evpl_test_abort_if(eio == 0, "%s: no posted operation was flushed by the close", name);
    evpl_test_abort_if(evpl_iovec_get_ref(&local)->refcnt != 1,
                       "%s: the library kept references to the operations' buffers", name);

    evpl_listener_detach(server, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    evpl_iovec_release(client, &local);
    evpl_iovec_release(server, &remote);
    evpl_destroy(client);
    evpl_destroy(server);
    client = server = NULL;
} /* run */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_global_config *config  = evpl_global_config_init();
    const char                *address = getenv("EVPL_TEST_RDMA_IP");
    int                        port    = argc > 1 ? atoi(argv[1]) : 8019;

    evpl_test_abort_if(!address, "RDMA test address is required");
    evpl_global_config_set_buffer_size(config, REGION_SIZE);
    /* Registration pins the whole slab; keep it within the Soft-RoCE guest. */
    evpl_global_config_set_slab_size(config, 64 * 1024 * 1024);
    evpl_global_config_set_rdmacm_srq_size(config, 256);
    evpl_init(config);

    run("close", address, port, 0);
    run("peer close", address, port + 1, 1);

    printf("Test PASSED\n");
    return 0;
} /* main */
