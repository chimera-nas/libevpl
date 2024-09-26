#pragma once

#include "core/evpl.h"

struct evpl_event;

/*
 * Some sets of protocols share a common framework that requires
 * things like global state, per thread state, and memory
 * registration. Other protocols require no global state,
 * such as unix sockets, so they are not associated with a framework
 */

struct evpl_framework {
    /* unique ID number for each framework */
    unsigned int    id;
    /* human readable name for framework, no spaces */
    const char     *name;

    /* process global state, can be NULL if not required */
    void * (*init)(void);
    void (*cleanup)(void *private_data);

    /* per-thread state, passed global state, can be NULL if not required  */
    void *  (*create)(struct evpl *evpl, void *private_data);
    void (*destroy)(struct evpl *evpl, void *private_data);

    /* per-memory-buffer state, can be NULL if not required */
    void * (*register_buffer)(void *buffer, int size, void *thread_private);
    void (*unregister_buffer)(void *buffer_private, void *thread_private);
};


/*
 * API for connection oriented protocols
 */
struct evpl_conn_protocol {
    /* unique ID number for each protocol */
    unsigned int    id;
    /* human readable name for protocol, no spaces */
    const char     *name;

    void (*connect)(
        struct evpl *evpl,
        struct evpl_conn *conn);

    void (*close_conn)(
        struct evpl *evpl,
        struct evpl_conn *conn);

    void (*listen)(
        struct evpl        *evpl,
        struct evpl_listener *listener);

    void (*close_listen)(
        struct evpl       *evpl,
        struct evpl_listener *listener);

    /* Called when connection has new data available to be written */

    void (*flush)(
        struct evpl       *evpl,
        struct evpl_conn  *conn);
};

void *
evpl_framework_private(struct evpl *evpl, int id);

