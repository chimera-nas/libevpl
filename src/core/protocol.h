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

    /* per-memory-buffer state, can be NULL if not required
     * if device changes occur, may be called repeatedly on the
     * same buffer, in which case buffer_private will provide
     * the previous returned value
     */
    void       * (*register_memory)(
        void *buffer,
        int   size,
        void *buffer_private,
        void *thread_private);
    void         (*unregister_memory)(
        void *buffer_private,
        void *thread_private);

    /* per-address state */
    void         (*release_address)(
        void *address_private,
        void *thread_private);
};


/*
 * API for connection oriented protocols
 */
struct evpl_protocol {
    /* unique ID number for each protocol */
    unsigned int           id;

    /* 1 iff connection oriented protocol */
    unsigned int           connected;

    /* 1 iff stream oriented protocol */
    unsigned int           stream;

    /* human readable name for protocol, no spaces */
    const char            *name;

    /* pointer to associated framework, or NULL if no framework */
    struct evpl_framework *framework;

    /*
     * Callbacks needed for all protocols
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

    /*
     * Callbacks for non-connection-oriented protocols
     */

    void                   (*bind)(
        struct evpl      *evpl,
        struct evpl_bind *bind);

    /*
     * Callbacks for RDMA read/write operations
     */

    void                   (*rdma_read)(
        struct evpl *evpl,
        struct evpl_bind *bind,
        uint32_t remote_key,
        uint64_t remote_address,
        struct evpl_iovec *iov,
        int niov,
        void ( *callback )(int status, void *private_data),
        void *private_data);

    void                   (*rdma_write)(
        struct evpl *evpl,
        struct evpl_bind *bind,
        uint32_t remote_key,
        uint64_t remote_address,
        struct evpl_iovec *iov,
        int niov,
        void ( *callback )(int status, void *private_data),
        void *private_data);
};

struct evpl_block_device {
    /* Private data owned by the protocol */
    void                       *private_data;

    /* Protocol that owns this device */
    struct evpl_block_protocol *protocol;

    /* Size of the device in bytes, set by the protocol */
    uint64_t                    size;

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
        struct evpl *evpl,
        struct evpl_block_queue *queue,
        struct evpl_iovec *iov,
        int niov,
        uint64_t offset,
        void ( *callback )(int status, void *private_data),
        void *private_data);

    /* Write to a block queue */
    void                        (*write)(
        struct evpl *evpl,
        struct evpl_block_queue *queue,
        const struct evpl_iovec *iov,
        int niov,
        uint64_t offset,
        int sync,
        void ( *callback )(int status, void *private_data),
        void *private_data);

    /* Flush a block device */
    void                        (*flush)(
        struct evpl *evpl,
        struct evpl_block_queue *queue,
        void ( *callback )(int status, void *private_data),
        void *private_data);
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


void *
evpl_framework_private(
    struct evpl *evpl,
    int          id);


void
evpl_attach_framework(
    struct evpl           *evpl,
    enum evpl_framework_id framework_id);
