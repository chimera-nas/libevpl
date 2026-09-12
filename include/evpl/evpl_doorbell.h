// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_doorbell.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_doorbell;

#ifndef EVPL_INTERNAL
struct evpl_doorbell {
    uint64_t opaque[8];
};
#endif /* ifndef EVPL_INTERNAL */

typedef void (*evpl_doorbell_callback_t)(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);

void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback);

/*
 * Retire a doorbell.  Must be called on the thread that added it, and before
 * that thread's evpl is destroyed.
 *
 * Once this returns the library holds no further reference to the doorbell, so
 * the caller may free the storage it lives in -- including from inside the
 * doorbell's own callback.
 */
void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);

int
evpl_doorbell_fd(
    struct evpl_doorbell *doorbell);

void
evpl_ring_doorbell(
    struct evpl_doorbell *doorbell);

/* Obtain an owned sending reference on the receiver's loop thread before
 * sharing it. Signal/retain/release are thread-safe while holding a reference.
 * Signals coalesce; success is not an acknowledgement that work was consumed.
 * Receiver removal (or loop destruction) revokes every sender: signal returns
 * ECANCELED thereafter. A queued notification may be dropped by removal.
 * Sender lifetime does not extend the lifetime of application work queues.
 * Legacy ring(receiver) still requires caller synchronization against removal.
 */
struct evpl_doorbell_sender;
struct evpl_doorbell_sender * evpl_doorbell_sender(
    struct evpl_doorbell *receiver);
void evpl_doorbell_sender_retain(
    struct evpl_doorbell_sender *sender);
void evpl_doorbell_sender_release(
    struct evpl_doorbell_sender *sender);
/* Returns zero, ECANCELED for a closed receiver, or an error code. */
int evpl_doorbell_signal(
    struct evpl_doorbell_sender *sender);
