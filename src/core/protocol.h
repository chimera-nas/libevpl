// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "evpl/evpl.h"

struct evpl_event;
struct evpl_bind;
struct evpl_shared;

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

    /* create process global state, can be NULL if not required */
    void       * (*init)(
        void);

    /* destroy process global state, passed pointer returned from init */
    void         (*cleanup)(
        void *private_data);

    /* create per-thread state, passed global state, can be NULL if not required  */
    void       * (*create)(
        struct evpl *evpl,
        void        *private_data);

    /* destroy per-thread state, passed pointer returned from create*/
    void         (*destroy)(
        struct evpl *evpl,
        void        *private_data);

    /* create  per-memory-buffer state, can be NULL if not required
     * if device changes occur, may be called repeatedly on the
     * same buffer, in which case buffer_private will provide
     * the previous returned value, otherwise buffer_private will be NULL
     * thread_private is the per-thread state returned from create
     */

    void       * (*register_memory)(
        void *buffer,
        int   size,
        void *buffer_private,
        void *thread_private);

    /* destroy per-memory-buffer state, passed pointer returned from register_memory */
    void         (*unregister_memory)(
        void *buffer_private,
        void *thread_private);


    /* Fetch key and address for registered memory */
    void         (*get_rdma_address)(
        struct evpl_bind  *bind,
        struct evpl_iovec *iov,
        uint32_t          *r_key,
        uint64_t          *r_address);


    /* release per-address state */
    void         (*release_address)(
        void *address_private,
        void *thread_private);
};


/*
 * API for network/fabric protocols
 */
struct evpl_protocol {
    /* unique ID number for each protocol */
    unsigned int           id;

    /* 1 iff connection oriented protocol */
    unsigned int           connected;

    /* 1 iff stream oriented protocol */
    unsigned int           stream;

    /* 1 iff supports RDMA read/write */
    unsigned int           rdma;

    /* human readable name for protocol, no spaces */
    const char            *name;

    /* pointer to associated framework, or NULL if no framework */
    struct evpl_framework *framework;

    /*
     * Callbacks needed for all protocols
     */

    /* Called to put a connection into a pending close state
     * backend should close the connection as soon as practical
     * and emit a notification that it  has been disconnected
     */
    void                   (*pending_close)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    /* Called to close a connection
     *
     * will be called after pending_close and only after
     * a disconnect notification has been emitted
     */

    void                   (*close)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    /* Called when new data is available to be written */
    void                   (*flush)(
        struct evpl      *evpl,
        struct evpl_bind *bind);


    /*
     * Callbacks for connection-oriented protocols
     */

    void                   (*connect)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    void                   (*listen)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    /* Called to attach an accepted connection to an evpl context */
    void                   (*attach)(
        struct evpl      *evpl,
        struct evpl_bind *bind,
        void             *accepted);

    /*
     * Callbacks for non-connection-oriented protocols
     */

    void                   (*bind)(
        struct evpl      *evpl,
        struct evpl_bind *bind);
};

/* API for a block protocol */

struct evpl_block_device {
    /* Private data owned by the protocol */
    void                       *private_data;

    /* Protocol that owns this device */
    struct evpl_block_protocol *protocol;

    /* Size of the device in bytes, set by the protocol */
    uint64_t                    size;

    /* maximum size of a single I/O request in bytes */
    uint64_t                    max_request_size;

    /* Open a device queue */
    struct evpl_block_queue   * (*open_queue)(
        struct evpl              *evpl,
        struct evpl_block_device *blockdev);

    void                        (*close_device)(
        struct evpl_block_device *blockdev);
};

struct evpl_block_queue {
    /* Private data owned by the protocol */
    void                       *private_data;

    /* Protocol that owns this queue */
    struct evpl_block_protocol *protocol;

    /* Close a device queue */
    void                        (*close_queue)(
        struct evpl             *evpl,
        struct evpl_block_queue *queue);

    /* Read from a block queue */
    void                        (*read)(
        struct evpl             *evpl,
        struct evpl_block_queue *queue,
        struct evpl_iovec       *iov,
        int                      niov,
        uint64_t                 offset,
        evpl_block_callback_t    callback,
        void                    *private_data);

    /* Write to a block queue */
    void                        (*write)(
        struct evpl             *evpl,
        struct evpl_block_queue *queue,
        const struct evpl_iovec *iov,
        int                      niov,
        uint64_t                 offset,
        int                      sync,
        evpl_block_callback_t    callback,
        void                    *private_data);

    /* Flush a block device */
    void                        (*flush)(
        struct evpl             *evpl,
        struct evpl_block_queue *queue,
        evpl_block_callback_t    callback,
        void                    *private_data);
};

struct evpl_block_protocol {
    /* unique ID number for each protocol */
    unsigned int               id;

    /* human readable name for protocol, no spaces */
    const char                *name;

    /* pointer to associated framework, or NULL if no framework */
    struct evpl_framework     *framework;

    /* Open a block device */
    struct evpl_block_device * (*open_device)(
        const char *uri,
        void       *private_data);
};

void
evpl_framework_init(
    struct evpl_shared    *evpl_shared,
    unsigned int           id,
    struct evpl_framework *framework);


void
evpl_protocol_init(
    struct evpl_shared   *evpl_shared,
    unsigned int          id,
    struct evpl_protocol *protocol);


void
evpl_block_protocol_init(
    struct evpl_shared         *evpl_shared,
    unsigned int                id,
    struct evpl_block_protocol *protocol);

void *
evpl_framework_private(
    struct evpl *evpl,
    int          id);


void
evpl_attach_framework(
    struct evpl           *evpl,
    enum evpl_framework_id framework_id);
