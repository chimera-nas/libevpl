// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "evpl/evpl.h"
#include "evpl/evpl_platform.h"
#include "tests/test_common.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "failed: %s\n", #c); return 1; } } while (0)
static atomic_int started;
static atomic_int failures;
static int        callbacks;

static void
callback(
    struct evpl          *evpl,
    struct evpl_doorbell *receiver)
{
    (void) evpl; (void) receiver;
    callbacks++;
} /* callback */

static void *
producer(void *arg)
{
    struct evpl_doorbell_sender *sender = arg;

    atomic_fetch_add(&started, 1);
    for (int i = 0; i < 10000; i++) {
        int rc = evpl_doorbell_signal(sender);
        if (rc != 0 && rc != ECANCELED) {
            atomic_fetch_add(&failures, 1);
        }
    }
    evpl_doorbell_sender_release(sender);
    return NULL;
} /* producer */

int
main(void)
{
    struct evpl_doorbell        *receiver = calloc(1, sizeof(*receiver));
    struct evpl_doorbell_sender *sender;
    evpl_native_thread_t         producers[4];
    struct evpl                 *evpl;
    struct evpl_thread_config   *config;

    test_evpl_config();
    config = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(config, 0);
    evpl = evpl_create(config);
    evpl_add_doorbell(evpl, receiver, callback);
    sender = evpl_doorbell_sender(receiver);
    CHECK(evpl_doorbell_signal(sender) == 0);
    for (int i = 0; i < 100 && !callbacks; i++) {
        evpl_continue(evpl);
    }
    CHECK(callbacks != 0);
    for (int i = 0; i < 4; i++) {
        evpl_doorbell_sender_retain(sender);
        CHECK(evpl_native_thread_create(&producers[i], NULL, producer, sender) == 0);
    }
    while (atomic_load(&started) != 4) {
        evpl_continue(evpl);
    }
    evpl_remove_doorbell(evpl, receiver);
    /* Reuse the exact receiver address: old sending handles must stay revoked. */
    evpl_add_doorbell(evpl, receiver, callback);
    callbacks = 0;
    for (int i = 0; i < 4; i++) {
        CHECK(evpl_native_thread_join(producers[i], NULL) == 0);
    }
    CHECK(evpl_doorbell_signal(sender) == ECANCELED);
    for (int i = 0; i < 10; i++) {
        evpl_continue(evpl);
    }
    CHECK(callbacks == 0 && atomic_load(&failures) == 0);
    evpl_doorbell_sender_release(sender);
    sender = evpl_doorbell_sender(receiver);
    evpl_destroy(evpl);
    free(receiver);
    CHECK(evpl_doorbell_signal(sender) == ECANCELED);
    evpl_doorbell_sender_release(sender);
    return 0;
} /* main */
