// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * RDMA operations left on a bind when it is torn down complete exactly once,
 * every one of them before the bind's DISCONNECTED notification, and the
 * library drops every reference it took to their buffers before that
 * notification too.
 *
 * Each callback is a probe: it records whether DISCONNECTED had already been
 * delivered on the client bind when it ran.  It never may have been: an
 * application frees its per-connection state at DISCONNECTED.
 *
 * Four cases.  "INPROC unconnected" connects to an in-process name nobody
 * listens on: the bind closes itself at once and has no channel, so the
 * transport never starts the operations queued on it and only the teardown
 * can complete them, with ECONNRESET.  "INPROC unconnected, chained" is the
 * same, except that the first write's callback queues one more read and one
 * more write on the bind while the teardown is completing the others; those
 * too complete once, with ECONNRESET, before DISCONNECTED.  "TCP_RDMA close"
 * and "INPROC close"
 * queue on a connected bind and close it in the same pass, so each
 * transport's own close path ends the operations; they may complete with 0 or
 * ECONNRESET, but never after DISCONNECTED.
 *
 * The connected TCP_RDMA and INPROC cases do not exercise
 * evpl_bind_complete_rdma: they check ordering and exactly-once only.  The
 * INPROC-unconnected case is the regression test for it.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "evpl/evpl.h"
#include "core/test_log.h"
#include "tests/test_common.h"

#define OP_SIZE     4096
#define NUM_READS   8
#define NUM_WRITES  8
#define NUM_OPS     (NUM_READS + NUM_WRITES)
#define NUM_CHAINED 2 /* one read and one write, queued from a callback */
#define REGION_SIZE (NUM_OPS * OP_SIZE)

struct operation {
    int called;
    int status;
    int after_disconnect;
};

static struct evpl      *client, *server;
static struct evpl_bind *client_bind, *server_bind;
static struct evpl_iovec local, remote;
static struct operation  operations[NUM_OPS + NUM_CHAINED];
static int               num_operations, chain, chained;
static unsigned int      refcnt_at_disconnect;
static uint32_t          remote_key;
static uint64_t          remote_address;
static int               connected, disconnected, client_disconnected;
static const char       *case_name;

static void completed(
    int   status,
    void *arg);

/* Operation i reads into or writes from slot i % NUM_OPS of local. */
static void
queue_operation(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               i,
    int               read)
{
    struct evpl_iovec iov;
    uint64_t          offset = (uint64_t) (i % NUM_OPS) * OP_SIZE;

    evpl_iovec_clone(&iov, &local);
    iov.data   = (char *) local.data + offset;
    iov.length = OP_SIZE;
    if (read) {
        evpl_rdma_read(evpl, bind, remote_key, remote_address + offset,
                       &iov, 1, completed, &operations[i]);
    } else {
        evpl_rdma_write(evpl, bind, remote_key, remote_address + offset,
                        &iov, 1, 0, completed, &operations[i]);
    }
    evpl_iovec_release(evpl, &iov);
} /* queue_operation */

static void
completed(
    int   status,
    void *arg)
{
    struct operation *operation = arg;
    int               index     = (int) (operation - operations);

    evpl_test_abort_if(operation->called++, "%s: operation %d completed twice",
                       case_name, index);
    operation->status           = status;
    operation->after_disconnect = client_disconnected;

    /* The first write to complete queues one more read and one more write. */
    if (chain && !chained && index >= NUM_READS && index < NUM_OPS) {
        chained = 1;
        queue_operation(client, client_bind, NUM_OPS, 1);
        queue_operation(client, client_bind, NUM_OPS + 1, 0);
    }
} /* completed */

static void
queue_operations(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    int i;

    for (i = 0; i < NUM_OPS; i++) {
        queue_operation(evpl, bind, i, i < NUM_READS);
    }
} /* queue_operations */

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
            client_disconnected  = 1;
            client_bind          = NULL;
            refcnt_at_disconnect = evpl_iovec_get_ref(&local)->refcnt;
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

/* Allocate local as one whole buffer, then make the allocator retire that
 * buffer: it is full, so the next allocation takes a fresh one and drops the
 * allocator's reference.  From here on only the test holds local's buffer,
 * so any further reference is one the library took and kept. */
static int
alloc_local(void)
{
    struct evpl_iovec spare;

    if (evpl_iovec_alloc(client, REGION_SIZE, 1, 1, 0, &local) != 1 ||
        evpl_iovec_alloc(client, 1, 1, 1, 0, &spare) != 1) {
        return -1;
    }
    evpl_iovec_release(client, &spare);
    return evpl_iovec_get_ref(&local)->refcnt == 1 ? 0 : -1;
} /* alloc_local */

static void
pump(void)
{
    evpl_continue(client);
    if (server) {
        evpl_continue(server);
    }
} /* pump */

static struct evpl *
loop(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 0);
    return evpl_create(config);
} /* loop */

static void
start_case(const char *name)
{
    case_name           = name;
    connected           = 0;
    disconnected        = 0;
    client_disconnected = 0;
    num_operations      = NUM_OPS;
    chain               = 0;
    chained             = 0;
    memset(operations, 0, sizeof(operations));
} /* start_case */

static void
check_operations(int leftovers_only)
{
    int i;

    evpl_test_abort_if(chain && !chained, "%s: no write callback queued more",
                       case_name);

    for (i = 0; i < num_operations; i++) {
        evpl_test_abort_if(operations[i].called != 1,
                           "%s: operation %d completed %d times, expected once",
                           case_name, i, operations[i].called);
        evpl_test_abort_if(operations[i].after_disconnect,
                           "%s: operation %d completed after DISCONNECTED",
                           case_name, i);
        evpl_test_abort_if(leftovers_only && operations[i].status != ECONNRESET,
                           "%s: operation %d completed with %d, expected ECONNRESET",
                           case_name, i, operations[i].status);
        evpl_test_abort_if(operations[i].status != 0 &&
                           operations[i].status != ECONNRESET,
                           "%s: operation %d completed with %d", case_name, i,
                           operations[i].status);
    }

    /* Only the test's own reference may remain (see alloc_local), already
     * when DISCONNECTED is delivered. */
    evpl_test_abort_if(refcnt_at_disconnect != 1,
                       "%s: the library still held the operations' buffers at DISCONNECTED",
                       case_name);

    evpl_test_abort_if(evpl_iovec_get_ref(&local)->refcnt != 1,
                       "%s: the library kept references to the operations' buffers",
                       case_name);
} /* check_operations */

static void
run_unconnected(
    const char *name,
    int         chain_from_write)
{
    struct evpl_endpoint *endpoint;
    int                   n;

    start_case(name);
    if (chain_from_write) {
        chain          = 1;
        num_operations = NUM_OPS + NUM_CHAINED;
    }

    client         = loop();
    server         = NULL;
    remote_key     = 1;
    remote_address = 4096;
    evpl_test_abort_if(alloc_local(), "%s: allocation failed", case_name);

    endpoint    = evpl_endpoint_create("inproc://rdma-close-queued-nobody", 0);
    client_bind = evpl_connect(client, EVPL_DATAGRAM_INPROC, NULL, endpoint,
                               notify, NULL, NULL);
    evpl_test_abort_if(!client_bind, "%s: connect failed", case_name);

    /* Queued in the same pass as the connect: the bind is already closing and
     * has no channel, so no transport path will start these. */
    queue_operations(client, client_bind);

    for (n = 0; n < 5000 && !client_disconnected; n++) {
        evpl_continue(client);
    }
    evpl_test_abort_if(!client_disconnected, "%s: no DISCONNECTED", case_name);

    check_operations(1);

    evpl_endpoint_close(endpoint);
    evpl_iovec_release(client, &local);
    evpl_destroy(client);
    client = NULL;
} /* run_unconnected */

static void
run_connected(
    const char           *name,
    enum evpl_protocol_id protocol,
    const char           *address,
    int                   port)
{
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;
    int                           n;

    start_case(name);

    client   = loop();
    server   = loop();
    listener = evpl_listener_create();
    endpoint = evpl_endpoint_create(address, port);
    binding  = evpl_listener_attach(server, listener, accepted, NULL);
    evpl_test_abort_if(evpl_listen(listener, protocol, endpoint), "%s: listen failed", name);

    client_bind = evpl_connect(client, protocol, NULL, endpoint, notify, NULL, NULL);
    evpl_test_abort_if(!client_bind, "%s: connect failed", name);
    for (n = 0; n < 5000 && connected != 2; n++) {
        pump();
        evpl_sleep_us(100);
    }
    evpl_test_abort_if(connected != 2, "%s: handshake timed out", name);

    evpl_test_abort_if(alloc_local() ||
                       evpl_iovec_alloc(server, REGION_SIZE, 1, 1, 0, &remote) != 1,
                       "%s: allocation failed", name);
    evpl_rdma_get_address(server, server_bind, &remote, &remote_key, &remote_address);

    queue_operations(client, client_bind);
    evpl_close(client, client_bind);

    for (n = 0; n < 5000 && disconnected != 2; n++) {
        pump();
        evpl_sleep_us(100);
    }
    evpl_test_abort_if(disconnected != 2, "%s: close did not disconnect both ends", name);
    for (n = 0; n < 32; n++) {
        pump();
    }

    check_operations(0);

    evpl_listener_detach(server, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    evpl_iovec_release(client, &local);
    evpl_iovec_release(server, &remote);
    evpl_destroy(client);
    evpl_destroy(server);
    client = server = NULL;
} /* run_connected */

int
main(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_buffer_size(config, REGION_SIZE);
    test_evpl_set_core_mech(config);
    evpl_init(config);

    run_unconnected("INPROC unconnected", 0);
    run_unconnected("INPROC unconnected, chained", 1);
    run_connected("TCP_RDMA close", EVPL_DATAGRAM_TCP_RDMA, "127.0.0.1", 8371);
    run_connected("INPROC close", EVPL_DATAGRAM_INPROC, "inproc://rdma-close-queued", 0);

    printf("Test PASSED\n");
    return 0;
} /* main */
