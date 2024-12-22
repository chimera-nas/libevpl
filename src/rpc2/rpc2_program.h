#pragma once

#define EVPL_RPC2                    1

#include <pthread.h>

struct evpl;
struct evpl_rpc2_conn;
struct evpl_rpc2_program;

#define EVPL_RPC2_MAX_READ_SEGMENTS  1
#define EVPL_RPC2_MAX_WRITE_SEGMENTS 1
#define EVPL_RPC2_MAX_REPLY_SEGMENTS 16


struct evpl_rpc2_metric {
    uint64_t min_latency;
    uint64_t max_latency;
    uint64_t total_latency;
    uint64_t total_calls;
};

struct evpl_rpc2_rdma_segment {
    uint32_t   xdr_position;
    uint32_t   handle;
    uint32_t   length;
    uint64_t   offset;
    xdr_iovec *iov;
    int        niov;
};

struct evpl_rpc2_msg {
    uint32_t                      xid;
    uint32_t                      proc;
    uint32_t                      rdma;
    uint32_t                      rdma_credits;
    struct timespec               timestamp;
    int                           num_read_segments;
    int                           num_write_segments;
    int                           num_reply_segments;
    xdr_dbuf                     *dbuf;
    struct evpl_bind             *bind;
    struct evpl_rpc2_agent       *agent;
    struct evpl_rpc2_metric      *metric;
    struct evpl_rpc2_program     *program;
    struct evpl_rpc2_msg         *next;
    struct evpl_rpc2_rdma_segment read_segments[EVPL_RPC2_MAX_READ_SEGMENTS];
    struct evpl_rpc2_rdma_segment write_segments[EVPL_RPC2_MAX_WRITE_SEGMENTS];
    struct evpl_rpc2_rdma_segment reply_segments[EVPL_RPC2_MAX_REPLY_SEGMENTS];
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
