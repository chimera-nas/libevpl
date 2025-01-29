// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#define EVPL_RPC2 1

#include <pthread.h>

struct evpl;
struct evpl_rpc2_conn;
struct evpl_rpc2_program;
struct rpc_msg;
struct rdma_msg;

struct evpl_rpc2_metric {
    uint64_t min_latency;
    uint64_t max_latency;
    uint64_t total_latency;
    uint64_t total_calls;
};

struct evpl_rpc2_rdma_chunk {
    uint32_t   xdr_position;
    uint32_t   length;
    uint32_t   max_length;
    xdr_iovec *iov;
    int        niov;
};

struct evpl_rpc2_msg {
    uint32_t                    xid;
    uint32_t                    proc;
    uint32_t                    rdma;
    uint32_t                    rdma_credits;
    uint32_t                    request_length;
    uint32_t                    reply_length;
    uint16_t                    pending_reads;
    uint16_t                    pending_writes;
    struct evpl_iovec          *req_iov;
    struct evpl_iovec          *reply_iov;
    int                         req_niov;
    int                         reply_niov;
    struct timespec             timestamp;
    struct rpc_msg             *rpc_msg;
    struct rdma_msg            *rdma_msg;
    xdr_dbuf                   *dbuf;
    struct evpl_bind           *bind;
    struct evpl_rpc2_agent     *agent;
    struct evpl_rpc2_conn      *conn;
    struct evpl_rpc2_metric    *metric;
    struct evpl_rpc2_program   *program;
    struct evpl_rpc2_msg       *next;
    struct evpl_rpc2_rdma_chunk read_chunk;
    struct evpl_rpc2_rdma_chunk write_chunk;
};

struct evpl_rpc2_program {
    uint32_t                 program;
    uint32_t                 version;
    uint32_t                 maxproc;
    uint32_t                 reserve;
    const char             **procs;
    struct evpl_rpc2_metric *metrics;
    pthread_mutex_t          metrics_lock;
    void                    *program_data;

    int                      (*call_dispatch)(
        struct evpl           *evpl,
        struct evpl_rpc2_conn *conn,
        struct evpl_rpc2_msg  *msg,
        xdr_iovec             *iov,
        int                    niov,
        int                    length,
        void                  *private_data);

    int                      (*reply_dispatch)(
        struct evpl          *evpl,
        struct evpl_rpc2_msg *msg,
        xdr_iovec            *iov,
        int                   niov,
        int                   length);
};
