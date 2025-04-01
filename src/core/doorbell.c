#include <sys/eventfd.h>
#include <unistd.h>

#include "uthash/utlist.h"

#include "doorbell.h"
#include "evpl/evpl.h"
#include "macros.h"
#include "logging.h"
#include "event_fn.h"

static void
evpl_event_user_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_doorbell *doorbell = container_of(event, struct evpl_doorbell, event);

    uint64_t              word;
    ssize_t               len;

    len = read(event->fd, &word, sizeof(word));

    if (len != sizeof(word)) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    doorbell->callback(evpl, doorbell);
} /* evpl_event_user_callback */


SYMBOL_EXPORT void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback)
{
    struct evpl_event *event = &doorbell->event;

    evpl_add_event(evpl, event, eventfd(0, EFD_NONBLOCK),
                   evpl_event_user_callback, NULL, NULL);

    evpl_event_read_interest(evpl, event);

    doorbell->callback = callback;

} /* evpl_add_event_user */

SYMBOL_EXPORT void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    evpl_remove_event(evpl, &doorbell->event);

    close(doorbell->event.fd);
} /* evpl_remove_doorbell */

SYMBOL_EXPORT void
evpl_ring_doorbell(struct evpl_doorbell *doorbell)
{
    uint64_t word = 1;
    ssize_t  len;

    len = write(doorbell->event.fd, &word, sizeof(word));

    evpl_core_abort_if(len != sizeof(word), "failed to write to doorbell fd");
} /* evpl_ring_doorbell */