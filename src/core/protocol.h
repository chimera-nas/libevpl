#pragma once

#include "core/evpl.h"

struct evpl_event;

struct evpl_protocol {
    /* unique ID number for each protocol */
    unsigned int    id;
    /* human readable name for protocol, no spaces */
    const char     *name;

    /* process global state, can be NULL if not required */
    void * (*init)(void);
    void (*cleanup)(void *private_data);

    /* per-thread state, passed global state, can be NULL if not required  */
    void *  (*create)(void *private_data);
    void (*destroy)(void *private_data);

    /* Create a connection to the given endpoint, fill in event handlers,
     * and return private connection structure.
     * May be NULL for non-connection-oriented protocols
     */
    void (*connect)(
        struct evpl *evpl,
        struct evpl_conn *conn);

    /* Destroy a connection created above 
     * Can be NULL for non-connection-oriented protocols
     */
    void (*close_conn)(
        struct evpl *evpl,
        struct evpl_conn *conn);

    /* Listen for connections on the given endpoint
     * May be NULL for non-connection-oriented protocols
     */

    void (*listen)(
        struct evpl        *evpl,
        struct evpl_listener *listener);

    /* Destroy a listen handler created above
     * May be NULL for non-connection-oriented protocols
     */

    void (*close_listen)(
        struct evpl       *evpl,
        struct evpl_listener *listener);

    /*
     * Called when connection has new data available to be written
     */
    void (*flush)(
        struct evpl       *evpl,
        struct evpl_conn  *conn);
};

void *
evpl_protocol_private(struct evpl *evpl, int protocol);
