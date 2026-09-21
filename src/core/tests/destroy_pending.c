// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "evpl/evpl.h"
#include "tests/test_common.h"

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *private_data)
{
    unsigned int *disconnected = private_data;

    (void) evpl;
    (void) bind;
    if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        (*disconnected)++;
    }
} /* notify */
int
main(void)
{
    unsigned int          disconnected = 0;
    struct evpl          *evpl;
    struct evpl_endpoint *endpoint;

    test_evpl_config();
    evpl     = evpl_create(NULL);
    endpoint = evpl_endpoint_create("127.0.0.1", 0);
    if (!evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, endpoint, notify, &disconnected)) {
        return 1;
    }
    /* IOCP has a receive posted already. Destruction must cancel AND drain it,
     * then deliver disconnect, before freeing loop-owned buffer caches. */
    evpl_destroy(evpl);
    evpl_endpoint_close(endpoint);
    if (disconnected != 1) {
        fprintf(stderr, "destroy returned before disconnect (%u)\n", disconnected);
        return 1;
    }
    return 0;
} /* main */
