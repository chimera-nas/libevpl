// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define EVPL_RPC2 1

#include <pthread.h>
struct prometheus_histogram_instance;

struct evpl;
struct evpl_rpc2_conn;
struct evpl_rpc2_program;
struct rpc_msg;
struct rdma_msg;

struct evpl_rpc2_rdma_chunk {
    uint32_t   xdr_position;
    uint32_t   length;
    uint32_t   max_length;
    xdr_iovec *iov;
    int        niov;
};

struct evpl_rpc2_msg {
    uint32_t                              xid;
    uint32_t                              proc;
    uint32_t                              rdma;
    uint32_t                              rdma_credits;
    uint32_t                              request_length;
    uint32_t                              reply_length;
    uint16_t                              pending_reads;
    uint16_t                              pending_writes;
    struct evpl_iovec                    *req_iov;
    struct evpl_iovec                    *reply_iov;
    int                                   req_niov;
    int                                   reply_niov;
    struct timespec                       timestamp;
    struct rpc_msg                       *rpc_msg;
    struct rdma_msg                      *rdma_msg;
    xdr_dbuf                             *dbuf;
    struct evpl_bind                     *bind;
    struct evpl_rpc2_thread              *thread;
    struct evpl_rpc2_conn                *conn;
    struct prometheus_histogram_instance *metric;
    struct evpl_rpc2_program             *program;
    struct evpl_rpc2_msg                 *next;
    struct evpl_rpc2_rdma_chunk           read_chunk;
    struct evpl_rpc2_rdma_chunk           write_chunk;
};

struct evpl_rpc2_program {
    uint32_t                             program;
    uint32_t                             version;
    uint32_t                             maxproc;
    uint32_t                             reserve;
    struct prometheus_histogram_series **metrics;
    const char                         **procs;
    void                                *program_data;

    int                                  (*call_dispatch)(
        struct evpl           *evpl,
        struct evpl_rpc2_conn *conn,
        struct evpl_rpc2_msg  *msg,
        xdr_iovec             *iov,
        int                    niov,
        int                    length,
        void                  *private_data);

    int                                  (*reply_dispatch)(
        struct evpl          *evpl,
        struct evpl_rpc2_msg *msg,
        xdr_iovec            *iov,
        int                   niov,
        int                   length);
};
