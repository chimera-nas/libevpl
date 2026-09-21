// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once

#include <stdatomic.h>
#include "test_common.h"
#include "core/test_log.h"

static const char *
test_mbt_address(void)
{
    const char *address = getenv("EVPL_TEST_RDMA_IP");

    return address ? address : "127.0.0.1";
} // test_mbt_address

static int
test_mbt_spdk(void)
{
    const char *mech = getenv("EVPL_TEST_CORE_MECH");

    return mech && strcmp(mech, "spdk") == 0;
} // test_mbt_spdk

static struct evpl *
test_mbt_create(struct evpl_thread_config *config)
{
#ifdef HAVE_SPDK
    if (test_mbt_spdk()) {
        evpl_test_abort_if(spdk_get_thread(), "replay already owns an SPDK thread");
        evpl_spdk_test_manual = 1;
        struct spdk_thread *thread = spdk_thread_create("model-replay", NULL);
        evpl_spdk_test_manual = 0;
        evpl_test_abort_if(!thread, "cannot create replay SPDK thread");
        spdk_set_thread(thread);
    }
#endif // ifdef HAVE_SPDK
    return evpl_create(config);
} // test_mbt_create

static int
test_mbt_continue(struct evpl *evpl)
{
#ifdef HAVE_SPDK
    if (test_mbt_spdk()) {
        struct spdk_thread *thread = spdk_get_thread();
        evpl_test_abort_if(!thread, "replay lost its SPDK owner");
        int                 work = spdk_thread_poll(thread, 0, 0);
        if (!work) {
            /* Cooperate with the wire peer and listener reactor on shared CI CPUs. */
            sched_yield();
        }
        return work;
    }
#endif // ifdef HAVE_SPDK
    return evpl_continue(evpl);
} // test_mbt_continue

static void
test_mbt_done(void *arg)
{
    atomic_store((atomic_int *) arg, 1);
} // test_mbt_done

static void
test_mbt_destroy(struct evpl *evpl)
{
#ifdef HAVE_SPDK
    if (test_mbt_spdk()) {
        struct spdk_thread *thread = spdk_get_thread();
        atomic_int          done   = 0;
        evpl_destroy_async(evpl, test_mbt_done, &done);
        while (!atomic_load(&done)) {
            spdk_thread_poll(thread, 0, 0);
        }
        spdk_thread_exit(thread);
        while (!spdk_thread_is_exited(thread)) {
            spdk_thread_poll(thread, 0, 0);
        }
        spdk_set_thread(NULL);
        spdk_thread_destroy(thread);
        return;
    }
#endif // ifdef HAVE_SPDK
    evpl_destroy(evpl);
} // test_mbt_destroy

/* The interpreter runs outside spdk_thread_poll callbacks. Synchronous host
 * management must not pump its guest between model steps: that would deliver
 * callbacks before the model's next quiesce. Background reactors service the
 * listener while this OS thread temporarily leaves its logical SPDK thread. */
static int
test_mbt_listen(
    struct evpl          *evpl,
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol,
    struct evpl_endpoint *endpoint)
{
    int                 rc;

#ifdef HAVE_SPDK
    struct spdk_thread *thread = spdk_get_thread();
    spdk_set_thread(NULL);
#endif // ifdef HAVE_SPDK
    rc = evpl_listen(listener, protocol, endpoint);
#ifdef HAVE_SPDK
    spdk_set_thread(thread);
#endif // ifdef HAVE_SPDK
    return rc;
} // test_mbt_listen

static void
test_mbt_listener_destroy(
    struct evpl          *evpl,
    struct evpl_listener *listener)
{
#ifdef HAVE_SPDK
    struct spdk_thread *thread = spdk_get_thread();
    spdk_set_thread(NULL);
#endif // ifdef HAVE_SPDK
    evpl_listener_destroy(listener);
#ifdef HAVE_SPDK
    spdk_set_thread(thread);
#endif // ifdef HAVE_SPDK
} // test_mbt_listener_destroy

static enum evpl_protocol_id
test_mbt_stream_protocol(void)
{
    const char *name = getenv("EVPL_TEST_STREAM_PROTOCOL");
    enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;

    evpl_test_abort_if(name && evpl_protocol_lookup(&proto, name),
                       "unknown replay stream protocol %s", name);
    return proto;
} // test_mbt_stream_protocol
