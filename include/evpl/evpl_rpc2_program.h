// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stddef.h>
#include <uthash.h>

#include "evpl/evpl_rpc2.h"
#define EVPL_RPC2                       1

/*
 * Status passed to a client reply callback when the peer's reply could not be
 * decoded (truncated, malformed, or wrong length).  The reply argument is NULL
 * (or a zero value for a by-value reply), so callbacks -- which must check
 * status before touching the reply -- treat it as a failed call rather than the
 * connection being torn down by an abort.  Negative so it cannot collide with a
 * protocol status code.
 */
#define EVPL_RPC2_REPLY_DECODE_ERROR    (-1)

/*
 * Status passed to a client reply callback when an in-flight call is terminated
 * without a reply because the connection was torn down.  As with
 * EVPL_RPC2_REPLY_DECODE_ERROR, the reply argument is NULL (or a zero value for
 * a by-value reply), so callbacks treat it as a failed call.  A distinct
 * negative value (cannot collide with a protocol status code) so callers can
 * tell a transport reset apart from a malformed reply.
 */
#define EVPL_RPC2_REPLY_TRANSPORT_ERROR (-2)

#include <pthread.h>
struct prometheus_histogram_instance;

#ifndef container_of
#define container_of(ptr, type, member) \
        ((type *) ((char *) (ptr) - offsetof(type, member)))
#endif // ifndef container_of

struct evpl;
struct evpl_iovec;
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
 * Optional pre-dispatch reply-capture callback.
 *
 * If set on an evpl_rpc2_encoding before a send_reply call, libevpl invokes
 * this callback inside send_reply -- after the reply has been marshalled
 * into iovecs but before they are queued onto the wire and the request is
 * freed.  This gives applications a chance to copy out the encoded reply
 * bytes for later replay (NFS4.1 session replay cache).
 *
 * The iov array is the complete RPC reply (header + body).  Pointers are
 * valid only for the duration of the callback; the callback must copy any
 * bytes it wishes to retain.
 */
typedef void (*evpl_rpc2_reply_capture_cb_t)(
    const struct evpl_iovec *iov,
    int                      niov,
    int                      total_length,
    void                    *private_data);

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
    uint32_t                     xid;         /* RPC transaction id for this request */
    /* Optional reply-capture hook -- see evpl_rpc2_reply_capture_cb_t.
     * NULL means "do not capture". */
    evpl_rpc2_reply_capture_cb_t reply_capture_cb;
    void                        *reply_capture_private;
};

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

    int                                  (*recv_reply_error)(
        struct evpl *evpl,
        uint32_t     proc,
        int          status,
        void        *callback_fn,
        void        *callback_private_data);


    int                                  (*send_reply_dispatch)(
        struct evpl                 *evpl,
        struct evpl_rpc2_encoding   *encoding,
        const struct evpl_rpc2_verf *verf,
        xdr_iovec                   *iov,
        int                          niov,
        int                          length);
};

/*
 * Issue an RPC call.
 *
 * write_chunk_iov/write_chunk_niov (optional, NULL/0 to omit) supply a
 * caller-owned buffer for the reply's RDMA write chunk to land in directly
 * (zero-copy read-into) instead of an internally allocated one.  Borrow
 * semantics: the caller keeps ownership, must keep the buffer alive until the
 * reply, and releases it itself; libevpl never releases it.  Only honored over
 * RDMA and only when niov == 1 (a single contiguous, RDMA-registered buffer);
 * otherwise an internal chunk is allocated.  max_rdma_write_chunk still gives
 * the advertised chunk length.
 */
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
    struct evpl_iovec           *write_chunk_iov,
    int                          write_chunk_niov,
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
