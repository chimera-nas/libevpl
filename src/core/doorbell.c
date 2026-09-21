// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>
#include <utlist.h>
#include "core/evpl.h"
#include "core/doorbell.h"
#include "core/event_fn.h"
#include "core/macros.h"

_Static_assert(sizeof(struct evpl_doorbell) <= 8 * sizeof(uint64_t),
               "doorbell exceeds public storage");

#ifdef _WIN32
static void
evpl_doorbell_complete(
    struct evpl              *evpl,
    struct evpl_iocp_request *request,
    DWORD                     bytes,
    DWORD                     error)
{
    struct evpl_doorbell_sender *sender = container_of(request, struct evpl_doorbell_sender, notification);
    struct evpl_doorbell        *receiver;
    evpl_doorbell_callback_t     callback;

    (void) bytes; (void) error;
    evpl_mutex_lock(&sender->lock);
    sender->queued = 0;
    receiver       = sender->receiver;
    callback       = sender->callback;
    evpl_mutex_unlock(&sender->lock);
    if (receiver) {
        callback(evpl, receiver);
    }
    evpl_doorbell_sender_release(sender);
} /* evpl_doorbell_complete */
#else  /* ifdef _WIN32 */
static void
evpl_event_user_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_doorbell_sender *sender = container_of(event, struct evpl_doorbell_sender, event);

    if (evpl_wakeup_drain(event->fd) < 0) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }
    /* The callback may remove the receiver and free sender's last reference.
     * The event dispatcher supports self-removal; do not touch either again. */
    sender->callback(evpl, sender->receiver);
} /* evpl_event_user_callback */

#endif /* ifdef _WIN32 */

SYMBOL_EXPORT void
evpl_doorbell_sender_retain(struct evpl_doorbell_sender *sender)
{
    atomic_fetch_add_explicit(&sender->refs, 1, memory_order_relaxed);
} /* evpl_doorbell_sender_retain */

SYMBOL_EXPORT void
evpl_doorbell_sender_release(struct evpl_doorbell_sender *sender)
{
    if (atomic_fetch_sub_explicit(&sender->refs, 1, memory_order_acq_rel) == 1) {
        evpl_mutex_destroy(&sender->lock);
        evpl_free(sender);
    }
} /* evpl_doorbell_sender_release */

SYMBOL_EXPORT struct evpl_doorbell_sender *
evpl_doorbell_sender(struct evpl_doorbell *receiver)
{
    evpl_doorbell_sender_retain(receiver->sender);
    return receiver->sender;
} /* evpl_doorbell_sender */

SYMBOL_EXPORT int
evpl_doorbell_signal(struct evpl_doorbell_sender *sender)
{
    int result;

    /* Closing and native wake submission are serialized. The owner can close
     * its loop immediately after retirement without racing an in-flight write. */
    evpl_mutex_lock(&sender->lock);
    if (!sender->owner) {
        result = ECANCELED;
    } else {
#ifdef _WIN32
        result = 0;
        if (!sender->queued) {
            sender->queued = 1;
            evpl_doorbell_sender_retain(sender);
            result = evpl_iocp_post(sender->owner, &sender->notification);
            if (result) {
                sender->queued = 0;
                evpl_doorbell_sender_release(sender);
            }
        }
#else  /* ifdef _WIN32 */
        result = evpl_wakeup_signal(&sender->wakeup) == sizeof(uint64_t) ? 0 : errno;
#endif /* ifdef _WIN32 */
    }
    evpl_mutex_unlock(&sender->lock);
    return result;
} /* evpl_doorbell_signal */

SYMBOL_EXPORT void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *receiver,
    evpl_doorbell_callback_t callback)
{
    struct evpl_doorbell_sender *sender = evpl_zalloc(sizeof(*sender));

    atomic_init(&sender->refs, 1);
    evpl_mutex_init(&sender->lock, NULL);
    sender->owner    = evpl;
    sender->receiver = receiver;
    sender->callback = callback;
    receiver->sender = sender;
#ifdef _WIN32
    sender->notification.callback = evpl_doorbell_complete;
#else  /* ifdef _WIN32 */
    evpl_core_abort_if(evpl_wakeup_open(&sender->wakeup) < 0,
                       "evpl_add_doorbell: wakeup open failed");
    evpl_add_event(evpl, &sender->event, sender->wakeup.rfd,
                   evpl_event_user_callback, NULL, NULL);
    evpl_event_read_interest(evpl, &sender->event);
#endif /* ifdef _WIN32 */
    DL_APPEND(evpl->doorbells, sender);
} /* evpl_add_doorbell */

SYMBOL_EXPORT void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *receiver)
{
    struct evpl_doorbell_sender *sender = receiver->sender;

    evpl_core_assert(sender && sender->owner == evpl);
    evpl_mutex_lock(&sender->lock);
    sender->owner    = NULL;
    sender->receiver = NULL;
#ifndef _WIN32
    evpl_remove_event(evpl, &sender->event);
    evpl_wakeup_close(&sender->wakeup);
#endif /* ifndef _WIN32 */
    evpl_mutex_unlock(&sender->lock);
    DL_DELETE(evpl->doorbells, sender);
    receiver->sender = NULL;
    evpl_doorbell_sender_release(sender);
} /* evpl_remove_doorbell */

SYMBOL_EXPORT int
evpl_doorbell_fd(struct evpl_doorbell *receiver)
{
#ifdef _WIN32
    (void) receiver;
    errno = ENOTSUP;
    return -1;
#else  /* ifdef _WIN32 */
    return receiver->sender->event.fd;
#endif /* ifdef _WIN32 */
} /* evpl_doorbell_fd */

SYMBOL_EXPORT void
evpl_ring_doorbell(struct evpl_doorbell *receiver)
{
    int result = evpl_doorbell_signal(receiver->sender);

    evpl_core_abort_if(result, "evpl_ring_doorbell: signal failed: %d", result);
} /* evpl_ring_doorbell */

void
evpl_doorbell_destroy_all(struct evpl *evpl)
{
    while (evpl->doorbells) {
        evpl_remove_doorbell(evpl, evpl->doorbells->receiver);
    }
} /* evpl_doorbell_destroy_all */
