// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "core/evpl.h"
#include "tests/test_common.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed: %s\n", #c); abort(); } } while (0)

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *private_data)
{
    (void) evpl; (void) bind;
    if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        (*(int *) private_data)++;
    }
} /* notify */

static void
attach(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **private_data,
    void                    *arg)
{
    (void) evpl; (void) bind; (void) callback; (void) segment;
    (void) private_data; (void) arg;
    /* No callback is allowed after detach or while destroying the worker. */
    abort();
} /* attach */

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
    struct evpl_listener *listener;
    struct evpl_endpoint *endpoint;

    test_evpl_config();
    listener = evpl_listener_create();
    endpoint = evpl_endpoint_create_inproc("listener-lifetime");
    CHECK(evpl_listen(listener, EVPL_STREAM_INPROC, endpoint) == 0);
    for (int mode = 0; mode < 3; mode++) {
        struct evpl                  *client = loop(), *worker = loop();
        struct evpl_listener_binding *binding = NULL;
        int                           disconnected = 0, queued = 0;
        if (mode) {
            binding = evpl_listener_attach(worker, listener, attach, NULL);
        }
        CHECK(evpl_connect(client, EVPL_STREAM_INPROC, NULL, endpoint, notify,
                           NULL, &disconnected) != NULL);
        if (mode) {
            /* Freeze dispatch on the worker until the listener hands it an
             * accepted connection. This exercises the queue ownership race. */
            for (int i = 0; i < 5000 && !queued; i++) {
                evpl_mutex_lock(&worker->lock);
                queued = worker->connect_requests != NULL;
                evpl_mutex_unlock(&worker->lock);
                evpl_sleep_us(1000);
            }
            CHECK(queued);
        }
        if (mode == 1) {
            evpl_listener_detach(worker, binding);
            evpl_continue(worker);
        }
        evpl_destroy(worker);
        for (int i = 0; i < 5000 && !disconnected; i++) {
            evpl_continue(client);
            evpl_sleep_us(1000);
        }
        CHECK(disconnected == 1);
        evpl_destroy(client);
    }
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    return 0;
} /* main */
