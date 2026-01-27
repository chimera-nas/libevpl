// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stddef.h>
#include <uthash.h>

#include "evpl/evpl_rpc2.h"
#define EVPL_RPC2 1

#include <pthread.h>
struct prometheus_histogram_instance;

#ifndef container_of
#define container_of(ptr, type, member) \
        ((type *) ((char *) (ptr) - offsetof(type, member)))
#endif // ifndef container_of

/* Define xdr_dbuf here so it's available for embedded use in evpl_rpc2_msg.
 * This guard allows xdr_builtin.h to skip its own definition if already defined. */
#ifndef XDR_DBUF_DEFINED
#define XDR_DBUF_DEFINED
struct xdr_dbuf {
    void *buffer;
    int   size;
    int   used;
};
typedef struct xdr_dbuf xdr_dbuf;
#endif // ifndef XDR_DBUF_DEFINED

struct evpl;
struct evpl_rpc2_conn;
struct evpl_rpc2_program;
struct evpl_rpc2_cred;
struct rpc_msg;
struct rdma_msg;

struct evpl_rpc2_rdma_chunk {
    uint32_t           xdr_position;
    uint32_t           length;
    uint32_t           max_length;
    struct evpl_iovec *iov;
    int                niov;
};

struct evpl_rpc2_rdma_segment {
    uint32_t handle;
    uint32_t length;
    uint64_t offset;
};

struct evpl_rpc2_rdma_segment_list {
    struct evpl_rpc2_rdma_segment segments[16];
    int                           num_segments;
};

/*
 * evpl_rpc2_encoding is the public interface between libevpl and applications.
 *
 * This structure contains pointers to everything needed for XDR encoding/decoding
 * and is passed to application handlers instead of exposing internal structures.
 * xdrzcc-generated code can access these fields directly.
 */
struct evpl_rpc2_encoding {
    struct evpl_rpc2_program    *program;     /* RPC program (contains reserve size) */
    struct xdr_dbuf             *dbuf;        /* Dynamic buffer for allocations */
    struct evpl_rpc2_rdma_chunk *read_chunk;  /* RDMA read chunk (for writes) */
    struct evpl_rpc2_rdma_chunk *write_chunk; /* RDMA write chunk (for replies) */
};

/*
 * evpl_rpc2_msg represents a single received RPC message (either a CALL or REPLY).
 *
 * Each msg has its own dbuf for dynamic allocations during unmarshalling.
 * The recv_iov holds references to the received data buffers.
 */
struct evpl_rpc2_msg {
    struct xdr_dbuf        dbuf;
    struct evpl_iovec     *recv_iov;
    int                    recv_niov;
    struct evpl_iovec     *req_iov;
    int                    req_niov;
    struct evpl_rpc2_msg  *next;
};

/*
 * evpl_rpc2_request represents an RPC exchange (call + reply).
 *
 * For server: created when a CALL is received, freed after reply is sent.
 * For client: created when making a call, freed after reply is received.
 *
 * The request holds metadata about the exchange (xid, proc, RDMA info)
 * and points to the associated msg containing the received data.
 */
struct evpl_rpc2_request {
    uint32_t                              xid;
    uint32_t                              proc;
    uint32_t                              rdma_credits;
    uint16_t                              pending_reads;
    struct evpl_bind                     *bind;
    struct evpl_rpc2_conn                *conn;
    struct evpl_rpc2_thread              *thread;
    struct evpl_rpc2_program             *program;
    struct timespec                       timestamp;
    struct prometheus_histogram_instance *metric;
    void                                 *callback;
    void                                 *callback_arg;
    struct UT_hash_handle                 hh;
    struct evpl_rpc2_rdma_chunk           read_chunk;
    struct evpl_rpc2_rdma_chunk           write_chunk;
    struct evpl_rpc2_rdma_segment_list    reply_segments;
    struct evpl_rpc2_rdma_segment_list    write_segments;
    struct evpl_iovec                     reply_segment_iov;
    struct evpl_rpc2_msg                 *msg;
    struct evpl_rpc2_request             *next;
    struct evpl_rpc2_encoding             encoding; /* Public interface for apps */
};

/*
 * Get the request from an encoding pointer.
 * Used internally by libevpl to access the full request from the public encoding.
 */
static inline struct evpl_rpc2_request *
evpl_rpc2_request_from_encoding(struct evpl_rpc2_encoding *encoding)
{
    return container_of(encoding, struct evpl_rpc2_request, encoding);
} // evpl_rpc2_request_from_encoding

struct evpl_rpc2_program {
    uint32_t                             program;
    uint32_t                             version;
    uint32_t                             maxproc;
    uint32_t                             reserve;
    struct prometheus_histogram_series **metrics;
    const char                         **procs;
    void                                *program_data;

    int                                  (*recv_call_dispatch)(
        struct evpl               *evpl,
        struct evpl_rpc2_conn     *conn,
        struct evpl_rpc2_encoding *encoding,
        uint32_t                   proc,
        void                      *program_data,
        struct evpl_rpc2_cred     *cred,
        xdr_iovec                 *iov,
        int                        niov,
        int                        length,
        void                      *private_data);

    int                                  (*recv_reply_dispatch)(
        struct evpl                 *evpl,
        struct evpl_rpc2_conn       *conn,
        struct xdr_dbuf             *dbuf,
        uint32_t                     proc,
        struct evpl_rpc2_rdma_chunk *read_chunk,
        const struct evpl_rpc2_verf *verf,
        xdr_iovec                   *iov,
        int                          niov,
        int                          length,
        void                        *callback_fn,
        void                        *callback_private_data);


    int                                  (*send_reply_dispatch)(
        struct evpl                 *evpl,
        struct evpl_rpc2_encoding   *encoding,
        const struct evpl_rpc2_verf *verf,
        xdr_iovec                   *iov,
        int                          niov,
        int                          length);
};

int
evpl_rpc2_call(
    struct evpl                 *evpl,
    struct evpl_rpc2_program    *program,
    struct evpl_rpc2_conn       *conn,
    const struct evpl_rpc2_cred *cred,
    uint32_t                     procedure,
    struct evpl_iovec           *req_iov,
    int                          req_niov,
    int                          req_length,
    struct evpl_rpc2_rdma_chunk *rdma_chunk,
    int                          max_rdma_write_chunk,
    int                          max_rdma_reply_chunk,
    void                        *callback,
    void                        *private_data);

/*
 * Transfer ownership of read_chunk iovecs to the caller.
 *
 * After this call, the caller owns the iovecs and is responsible for releasing
 * them. The read_chunk's niov is set to 0 to prevent double-releasing.
 *
 * This is typically used when a server receives write data via RDMA read_chunk
 * and needs to pass ownership to a lower layer (e.g., VFS) for processing.
 */
static inline void
evpl_rpc2_encoding_take_read_chunk(
    struct evpl_rpc2_encoding *encoding,
    struct evpl_iovec        **iov_out,
    int                       *niov_out)
{
    if (iov_out) {
        *iov_out = encoding->read_chunk->iov;
    }
    if (niov_out) {
        *niov_out = encoding->read_chunk->niov;
    }
    encoding->read_chunk->niov = 0;
} /* evpl_rpc2_encoding_take_read_chunk */

/*
 * Transfer ownership of write_chunk iovecs to the caller.
 *
 * After this call, the caller owns the iovecs and is responsible for releasing
 * them. The write_chunk's niov is set to 0 to prevent double-releasing.
 *
 * This is typically used when a client receives read data via RDMA write_chunk
 * and needs to pass ownership to the application callback.
 */
static inline void
evpl_rpc2_encoding_take_write_chunk(
    struct evpl_rpc2_encoding *encoding,
    struct evpl_iovec        **iov_out,
    int                       *niov_out)
{
    if (iov_out) {
        *iov_out = encoding->write_chunk->iov;
    }
    if (niov_out) {
        *niov_out = encoding->write_chunk->niov;
    }
    encoding->write_chunk->niov = 0;
} /* evpl_rpc2_encoding_take_write_chunk */

static inline int
evpl_rpc2_send_reply_dispatch(
    struct evpl                 *evpl,
    struct evpl_rpc2_encoding   *encoding,
    const struct evpl_rpc2_verf *verf,
    xdr_iovec                   *iov,
    int                          niov,
    int                          length)
{
    return encoding->program->send_reply_dispatch(evpl, encoding, verf, iov, niov, length);
} // evpl_rpc2_send_reply_dispatch
