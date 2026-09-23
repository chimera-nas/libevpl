// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <errno.h>
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "rdma_cases.h"

#define REGION_SIZE 32768
#define DATA_OFFSET 128
#define DATA_SIZE   64
#define MAX_PENDING 33

struct operation {
    int called;
    int status;
};
static struct evpl                  *client, *server;
static struct evpl_bind             *client_bind, *server_bind;
static struct evpl_listener         *listener;
static struct evpl_listener_binding *binding;
static struct evpl_endpoint         *endpoint;
static struct evpl_iovec             local, remote;
static struct operation              operations[MAX_PENDING];
static int                           connected, disconnected, completions, errors;
static int                           expected_status, batch_count;
static int                           cancel_at;
static uint32_t                      remote_key;
static uint64_t                      remote_address;
static size_t                        step_index;

static unsigned char
pattern(
    int value,
    int offset)
{
    return (unsigned char) (value * 91 + offset * 7 + 3);
} /* pattern */

static void
completed(
    int   status,
    void *arg)
{
    struct operation *operation = arg;

    evpl_test_abort_if(operation->called++, "step %zu: duplicate RDMA callback", step_index);
    evpl_test_abort_if(status != expected_status, "step %zu: RDMA status %d expected %d",
                       step_index, status, expected_status);
    operation->status = status;
    completions++;
    errors += status != 0;
    if (cancel_at && completions == cancel_at) {
        /* The model chooses this boundary, independently of how many replies
         * the kernel coalesces into one read. Close must stop dispatch of the
         * remaining replies and must not complete this operation twice when
         * its callback returns to the pending-ring code. */
        cancel_at       = 0;
        expected_status = ECONNRESET;
        evpl_close(client, client_bind);
    }
} /* completed */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *arg)
{
    if (event->notify_type == EVPL_NOTIFY_CONNECTED) {
        connected++;
    } else if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        disconnected++;
        if (evpl == client) {
            client_bind = NULL;
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
    server_bind   = bind;
    *callback     = notify;
    *segment      = NULL;
    *private_data = NULL;
} /* accepted */

static void
pump(void)
{
    evpl_continue(client);
    evpl_continue(server);
} /* pump */

static void
check_memory(int memory)
{
    for (int i = 0; i < REGION_SIZE; i++) {
        unsigned char expected = i >= DATA_OFFSET && i < DATA_OFFSET + DATA_SIZE ?
            pattern(memory, i - DATA_OFFSET) : 0xcc;
        evpl_test_abort_if(((unsigned char *) remote.data)[i] != expected,
                           "step %zu: remote byte %d differs from model", step_index, i);
    }
} /* check_memory */

static void
check_batch(
    const struct rdma_step *before,
    int                     prefix)
{
    for (int i = 0; i < batch_count; i++) {
        int status = i < prefix ? (before->access ? EINVAL : 0) : ECONNRESET;
        evpl_test_abort_if(operations[i].called != 1, "step %zu: missing RDMA callback %d", step_index, i);
        evpl_test_abort_if(operations[i].status != status,
                           "step %zu: operation %d status %d expected %d",
                           step_index, i, operations[i].status, status);
    }
    for (int i = 0; i < REGION_SIZE; i++) {
        int           slot = i / 80, offset = i % 80 - 8;
        unsigned char expected = 0x5a;
        if (slot < batch_count && offset >= 0 && offset < DATA_SIZE) {
            if (before->kind == 1) {
                expected = pattern(before->value, offset);
            } else if (slot < prefix && before->access == 0) {
                expected = pattern(before->memory, offset);
            }
        }
        evpl_test_abort_if(((unsigned char *) local.data)[i] != expected,
                           "step %zu: local byte %d differs from model", step_index, i);
    }
    /* Whole-buffer allocations have no allocator-held remainder. Check the
     * application's reference survives and every library clone is gone. */
    evpl_test_abort_if(evpl_iovec_get_ref(&local)->refcnt != 1,
                       "step %zu: RDMA buffer references leaked", step_index);
    batch_count = 0;
} /* check_batch */

static void
cleanup(void)
{
    if (!client) {
        return;
    }
    cancel_at       = 0;
    expected_status = ECONNRESET;
    if (client_bind) {
        evpl_close(client, client_bind);
    }
    if (server_bind) {
        evpl_close(server, server_bind);
    }
    for (int n = 0; n < 5000 && disconnected != 2; n++) {
        pump(); evpl_sleep_us(100);
    }
    evpl_test_abort_if(disconnected != 2, "RDMA cleanup did not disconnect both ends");
    evpl_listener_detach(server, binding);
    test_mbt_listener_destroy(server, listener);
    evpl_endpoint_close(endpoint);
    evpl_iovec_release(client, &local);
    evpl_iovec_release(server, &remote);
    evpl_destroy(client);
    evpl_destroy(server);
    client      = server = NULL;
    batch_count = 0;
} /* cleanup */

static struct evpl *
loop(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 0);
    return evpl_create(config);
} /* loop */

static void
connect_pair(int memory)
{
    static int port = 26000;

    cleanup();
    connected = disconnected = 0;
    client    = loop(); server = loop();
    listener  = evpl_listener_create();
    endpoint  = evpl_endpoint_create("127.0.0.1", port++);
    evpl_test_abort_if(test_mbt_listen(server, listener, EVPL_DATAGRAM_TCP_RDMA, endpoint), "RDMA listen failed");
    binding     = evpl_listener_attach(server, listener, accepted, NULL);
    client_bind = evpl_connect(client, EVPL_DATAGRAM_TCP_RDMA, NULL, endpoint, notify, NULL, NULL);
    evpl_test_abort_if(!client_bind, "RDMA connect failed");
    for (int n = 0; n < 5000 && connected != 2; n++) {
        pump(); evpl_sleep_us(100);
    }
    evpl_test_abort_if(connected != 2, "RDMA handshake timed out");
    evpl_test_abort_if(evpl_iovec_alloc(client, REGION_SIZE, 1, 1, 0, &local) != 1 ||
                       evpl_iovec_alloc(server, REGION_SIZE, 1, 1, 0, &remote) != 1, "RDMA allocation failed");
    memset(remote.data, 0xcc, REGION_SIZE);
    for (int i = 0; i < DATA_SIZE; i++) {
        ((unsigned char *) remote.data)[DATA_OFFSET + i] = pattern(memory, i);
    }
    evpl_rdma_get_address(server, server_bind, &remote, &remote_key, &remote_address);
    evpl_test_abort_if(!remote_key || !remote_address, "connected buffer has no RDMA registration");
} /* connect_pair */

static void
queue_batch(const struct rdma_step *s)
{
    uint32_t key     = s->access == 1 ? 0 : s->access == 2 ? UINT32_MAX : remote_key;
    uint64_t address = s->access == 3 ? 0 : s->access == 4 ? UINT64_MAX - 31 : remote_address + DATA_OFFSET;

    memset(operations, 0, sizeof(operations));
    memset(local.data, 0x5a, REGION_SIZE);
    batch_count     = s->count;
    expected_status = s->access ? EINVAL : 0;
    for (int i = 0; i < batch_count; i++) {
        struct evpl_iovec iov[2];
        if (s->kind) {
            for (int j = 0; j < DATA_SIZE; j++) {
                ((unsigned char *) local.data)[i * 80 + 8 + j] = pattern(s->value, j);
            }
        }
        evpl_iovec_clone(&iov[0], &local);
        evpl_iovec_clone(&iov[1], &local);
        iov[0].data   = (char *) local.data + i * 80 + 8;
        iov[0].length = 19;
        iov[1].data   = (char *) iov[0].data + 19;
        iov[1].length = DATA_SIZE - 19;
        if (s->kind == 0) {
            evpl_rdma_read(client, client_bind, key, address, iov, 2, completed, &operations[i]);
        } else {
            evpl_rdma_write(client, client_bind, key, address, iov, 2,
                            s->take ? EVPL_RDMA_FLAG_TAKE_REF : 0, completed, &operations[i]);
        }
        if (s->kind == 0 || !s->take) {
            evpl_iovecs_release(client, iov, 2);
        }
    }
    /* Only the initiator progresses: all requests enter the pending ring
    * before the peer can execute any of them or produce a completion. */
    for (int n = 0; n < 32; n++) {
        evpl_continue(client);
    }
} /* queue_batch */

int
main(void)
{
    struct evpl_global_config *config   = evpl_global_config_init();
    const struct rdma_step    *previous = NULL;

    evpl_global_config_set_buffer_size(config, REGION_SIZE);
    test_evpl_set_core_mech(config);
    evpl_init(config);
    for (step_index = 0; step_index < sizeof(rdma_steps) / sizeof(rdma_steps[0]); step_index++) {
        const struct rdma_step *s = &rdma_steps[step_index];
        switch (s->op) {
            case rdma_Reset: cleanup(); completions = errors = 0; break;
            case rdma_Connect: connect_pair(s->memory); break;
            case rdma_Queue: queue_batch(s); break;
            case rdma_Drain:
            case rdma_Close:
            case rdma_PeerClose:
            case rdma_PartialClose: {
                int cancelled = s->op != rdma_Drain;
                if (s->op == rdma_PartialClose) {
                    cancel_at = completions + s->prefix;
                } else if (cancelled) {
                    expected_status = ECONNRESET;
                    if (s->op == rdma_Close) {
                        evpl_close(client, client_bind);
                        /* Local close must finish without dispatching the
                         * peer. Closing both at once could hide a broken
                         * local close behind the peer's disconnect. */
                        for (int n = 0; n < 5000 && (client_bind || completions < s->completions); n++) {
                            evpl_continue(client); evpl_sleep_us(100);
                        }
                        evpl_test_abort_if(client_bind || completions != s->completions,
                                           "step %zu: local close did not cancel pending work", step_index);
                        evpl_close(server, server_bind);
                    } else {
                        evpl_close(server, server_bind);
                    }
                }
                for (int n = 0; n < 5000 && (completions < s->completions || (cancelled && disconnected != 2)); n++) {
                    pump(); evpl_sleep_us(100);
                }
                for (int n = 0; n < 32; n++) {
                    pump();
                }
                if (previous->pending) {
                    check_batch(previous, s->op == rdma_PartialClose ? s->prefix : cancelled ? 0 : previous->count);
                }
                evpl_test_abort_if(cancel_at, "step %zu: partial cancellation callback boundary never reached",
                                   step_index);
                check_memory(s->memory);
                if (cancelled) {
                    evpl_test_abort_if(disconnected != 2, "step %zu: missing disconnect", step_index);
                }
                break;
            }
            case rdma_Inspect: break;
            default: abort();
        } /* switch */
        evpl_test_abort_if(completions != s->completions || errors != s->errors,
                           "step %zu: completions/errors %d/%d expected %d/%d",
                           step_index, completions, errors, s->completions, s->errors);
        previous = s;
    }
    cleanup();
    return 0;
} /* main */
