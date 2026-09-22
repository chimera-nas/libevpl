// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "core/evpl.h"
#include "tests/test_mbt.h"
#include "listener_cases.h"

static struct evpl                  *client, *worker;
static struct evpl_listener         *listener;
static struct evpl_listener_binding *binding;
static struct evpl_endpoint         *endpoint;
static int                           accepts, disconnects;

static void
client_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *arg)
{
    if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        disconnects++;
    }
} /* client_notify */
static void
server_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *arg)
{
    if (notify->notify_type == EVPL_NOTIFY_CONNECTED) {
        evpl_close(evpl, bind);
    }
} /* server_notify */
static void
accepted(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify,
    evpl_segment_callback_t *segment,
    void                   **private_data,
    void                    *arg)
{
    accepts++;
    *notify       = server_notify;
    *segment      = NULL;
    *private_data = NULL;
} /* accepted */
static void pump(void) { evpl_continue(worker); evpl_continue(client); }
static void
cleanup(void)
{
    if (binding) {
        evpl_listener_detach(worker, binding);
    }
    binding = NULL;
    if (listener) {
        test_mbt_listener_destroy(worker, listener);
    }
    listener = NULL;
    if (endpoint) {
        evpl_endpoint_close(endpoint);
    }
    endpoint = NULL;
    if (worker) {
        evpl_destroy(worker);
    }
    if (client) {
        evpl_destroy(client);
    }
    worker = client = NULL;
} /* cleanup */
static struct evpl *
loop(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 0);
    return evpl_create(config);
} /* loop */
int
main(void)
{
    int                        port = 25000;

    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_buffer_size(config, 32768);
    evpl_global_config_set_io_uring_entries(config, 256);
    test_mbt_tls_config(config);
    test_evpl_set_core_mech(config);
    evpl_init(config);
#ifdef _WIN32
    atexit(evpl_cleanup);
#endif /* ifdef _WIN32 */
    for (size_t i = 0; i < sizeof(listener_steps) / sizeof(listener_steps[0]); i++) {
        const struct listener_step *s = &listener_steps[i];
        switch (s->op) {
            case listener_Reset:
                cleanup(); accepts = disconnects = 0;
                worker             = loop(); client = loop(); break;
            case listener_Start:
                listener = evpl_listener_create();
                endpoint = evpl_endpoint_create(test_address(test_mbt_stream_protocol(),
                                                             "127.0.0.1", "listener-mbt"), port++);
                evpl_test_abort_if(test_mbt_listen(worker, listener, test_mbt_stream_protocol(), endpoint),
                                   "listen failed");
                break;
            case listener_Attach: binding = evpl_listener_attach(worker, listener
                                                                 , accepted, NULL); break;
            case listener_Detach: evpl_listener_detach(worker, binding); binding = NULL; break;
            case listener_Connect: {
                int queued = 0;
                evpl_test_abort_if(!evpl_connect(client, test_mbt_stream_protocol(), NULL, endpoint,
                                                 client_notify, NULL, NULL), "connect failed");
                /* Freeze worker dispatch at a real handoff barrier, then let the
                 * model choose whether detach or acceptance wins ownership. */
                for (int n = 0; n < 5000 && !queued; n++) {
                    evpl_continue(client);
                    evpl_mutex_lock(&worker->lock);
                    queued = worker->connect_requests != NULL;
                    evpl_mutex_unlock(&worker->lock);
                    if (!queued) {
                        evpl_sleep_us(1000);
                    }
                }
                evpl_test_abort_if(!queued, "listener did not queue accepted connection");
                break;
            }
            case listener_Stop:
                test_mbt_listener_destroy(worker, listener); listener = NULL;
                evpl_endpoint_close(endpoint); endpoint               = NULL; break;
            case listener_Quiesce:
                for (int n = 0; n < 5000 && disconnects < s->disconnects; n++) {
                    pump(); evpl_sleep_us(1000);
                }
                for (int n = 0; n < 32; n++) {
                    pump();
                }
                evpl_test_abort_if(accepts != s->accepts || disconnects != s->disconnects,
                                   "listener step %zu: accepted/disconnected %d/%d expected %d/%d",
                                   i, accepts, disconnects, s->accepts, s->disconnects);
                break;
            default: abort();
        } /* switch */
    }
    cleanup();
    return 0;
} /* main */
