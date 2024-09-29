#pragma once

#include "core/evpl.h"

struct evpl_event;
struct evpl_bind;

/*
 * Some sets of protocols share a common framework that requires
 * things like global state, per thread state, and memory
 * registration. Other protocols require no global state,
 * such as unix sockets, so they are not associated with a framework
 */

struct evpl_framework {
    /* unique ID number for each framework */
    unsigned int id;
    /* human readable name for framework, no spaces */
    const char  *name;

    /* process global state, can be NULL if not required */
    void       * (*init)(
        void);
    void         (*cleanup)(
        void *private_data);

    /* per-thread state, passed global state, can be NULL if not required  */
    void       * (*create)(
        struct evpl *evpl,
        void        *private_data);
    void         (*destroy)(
        struct evpl *evpl,
        void        *private_data);

    /* per-memory-buffer state, can be NULL if not required */
    void       * (*register_buffer)(
        void *buffer,
        int   size,
        void *thread_private);
    void         (*unregister_buffer)(
        void *buffer_private,
        void *thread_private);
};


/*
 * API for connection oriented protocols
 */
struct evpl_protocol {
    /* unique ID number for each protocol */
    unsigned int id;

    /* 1 iff connection oriented protocol */
    unsigned int connected;

    /* 1 iff stream oriented protocol */
    unsigned int stream;

    /* human readable name for protocol, no spaces */
    const char  *name;

    /*
     * Callbacks needed for all protocols
     */

    void         (*close)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    /* Called when new data is available to be written */
    void         (*flush)(
        struct evpl      *evpl,
        struct evpl_bind *bind);


    /*
     * Callbacks for connection-oriented protocols
     */

    void         (*connect)(
        struct evpl          *evpl,
        struct evpl_endpoint *ep,
        struct evpl_bind     *bind);

    void         (*listen)(
        struct evpl          *evpl,
        struct evpl_endpoint *ep,
        struct evpl_bind     *bind);

    /*
     * Callbacks for non-connection-oriented protocols
     */

    void         (*bind)(
        struct evpl          *evpl,
        struct evpl_endpoint *ep,
        struct evpl_bind     *bind);
};

void *
evpl_framework_private(
    struct evpl *evpl,
    int          id);

