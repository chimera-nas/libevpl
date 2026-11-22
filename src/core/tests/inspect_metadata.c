// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include "evpl/evpl.h"
#include "evpl/evpl_config.h"

static struct evpl_bind_info accepted, connected;
static int                   accepts, connects, disconnects;
static struct evpl_bind     *server_bind;

static void
check(int condition)
{
    if (!condition) {
        abort();
    }
} /* check */
static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *data)
{
    if (event->notify_type == EVPL_NOTIFY_CONNECTED) {
        if (data) {
            evpl_bind_get_info(bind, &accepted); accepts++; server_bind = bind;
        } else {
            evpl_bind_get_info(bind, &connected); connects++;
        }
    } else if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        disconnects++;
    }
} /* notify */
static void
attach(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **connection_data,
    void                    *data)
{
    *callback        = notify;
    *connection_data = (void *) 1;
} /* attach */
static void
test_family(
    struct evpl *evpl,
    const char  *wildcard,
    const char  *address,
    const char  *family,
    int          port)
{
    struct evpl_listener         *listener = evpl_listener_create();
    struct evpl_endpoint         *local    = evpl_endpoint_create(wildcard, port);
    struct evpl_endpoint         *remote   = evpl_endpoint_create(address, port);
    struct evpl_listener_binding *binding  = evpl_listener_attach(evpl, listener, attach, NULL);

    check(evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, local) == 0);
    uint64_t                      serial = 0;
    for (int cycle = 0; cycle < 2; cycle++) {
        accepts = connects = disconnects = 0;
        struct evpl_bind *client = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, NULL, remote, notify, NULL, NULL);
        check(client != NULL);
        while (!accepts || !connects) {
            evpl_continue(evpl);
        }
        check(accepted.serial > serial && accepted.created_monotonic_ns && !accepted.closing);
        check(!strcmp(accepted.local.family, family) && !strcmp(accepted.remote.family, family));
        check(!strcmp(accepted.local.address, address) && !strcmp(accepted.remote.address, address));
        check(accepted.local.port == port && accepted.remote.port == connected.local.port);
        check(accepted.remote.port > 0 && connected.remote.port == port);
        serial = accepted.serial;
        evpl_close(evpl, server_bind);
        struct evpl_bind_info closing;
        evpl_bind_get_info(server_bind, &closing);
        check(closing.closing);
        evpl_close(evpl, client);
        while (disconnects < 2) {
            evpl_continue(evpl);
        }
    }
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(local);
    evpl_endpoint_close(remote);
} /* test_family */
static atomic_uint           owner_mask;
static struct evpl_listener *pool_listener;
struct pool_worker { struct evpl_listener_binding *binding; int index; };
static void
pool_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *data)
{
    struct pool_worker *worker = data;

    if (event->notify_type == EVPL_NOTIFY_CONNECTED) {
        struct evpl_bind_info info;
        evpl_bind_get_info(bind, &info);
        check(!strcmp(info.local.address, "127.0.0.1") && info.local.port == 18303);
        check(info.remote.port > 0);
        atomic_fetch_or(&owner_mask, 1U << worker->index);
    }
} /* pool_notify */
static void
pool_attach(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **connection_data,
    void                    *data)
{
    *callback        = pool_notify;
    *connection_data = data;
} /* pool_attach */
static void *
pool_init(
    struct evpl *evpl,
    void        *data)
{
    struct pool_worker         *worker = calloc(1, sizeof(*worker));
    struct evpl_thread_identity identity;

    evpl_thread_get_identity(evpl, &identity);
    check(identity.pool_index >= 0 && identity.pool_index < 8);
    char                        expected[32];
    snprintf(expected, sizeof(expected), "inspect_%d", identity.pool_index);
    check(!strcmp(identity.name, expected));
    worker->index   = identity.pool_index;
    worker->binding = evpl_listener_attach(evpl, pool_listener, pool_attach, worker);
    return worker;
} /* pool_init */
static void
pool_shutdown(
    struct evpl *evpl,
    void        *data)
{
    struct pool_worker *worker = data;

    evpl_listener_detach(evpl, worker->binding);
    free(worker);
} /* pool_shutdown */
static void
test_eight_owners(struct evpl *evpl)
{
    pool_listener = evpl_listener_create();
    struct evpl_thread_config *config = evpl_thread_config_init();
    evpl_thread_config_set_name(config, "inspect");
    struct evpl_threadpool    *pool     = evpl_threadpool_create(config, 8, pool_init, pool_shutdown, NULL);
    struct evpl_endpoint      *endpoint = evpl_endpoint_create("127.0.0.1", 18303);
    check(evpl_listen(pool_listener, EVPL_STREAM_SOCKET_TCP, endpoint) == 0);
    struct evpl_bind          *clients[8];
    connects = disconnects = 0;
    for (int i = 0; i < 8; i++) {
        clients[i] = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, NULL, endpoint, notify, NULL, NULL);
        check(clients[i] != NULL);
    }
    while (connects < 8 || atomic_load(&owner_mask) != 255) {
        evpl_continue(evpl);
    }
    for (int i = 0; i < 8; i++) {
        evpl_close(evpl, clients[i]);
    }
    while (disconnects < 8) {
        evpl_continue(evpl);
    }
    evpl_threadpool_destroy(pool);
    evpl_listener_destroy(pool_listener);
    evpl_endpoint_close(endpoint);
} /* test_eight_owners */

int
main(void)
{
    struct evpl_thread_config  *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 1);
    struct evpl                *evpl = evpl_create(config);
    struct evpl_thread_identity identity;
    evpl_thread_get_identity(evpl, &identity);
    check(identity.pool_index == -1 && !strcmp(identity.executor, "native"));
    test_family(evpl, "0.0.0.0", "127.0.0.1", "ipv4", 18301);
    test_family(evpl, "::", "::1", "ipv6", 18302);
    test_eight_owners(evpl);
    evpl_destroy(evpl);
    return 0;
} /* main */
