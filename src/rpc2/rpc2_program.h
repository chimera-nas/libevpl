#pragma once

#include <pthread.h>

struct evpl;
struct evpl_rpc2_conn;
struct evpl_rpc2_program;


struct evpl_rpc2_metric {
    uint64_t min_latency;
    uint64_t max_latency;
    uint64_t total_latency;
    uint64_t total_calls;
};

struct evpl_rpc2_msg {
    uint32_t                  xid;
    uint32_t                  proc;
    struct timespec           timestamp;
    xdr_dbuf                 *dbuf;
    struct evpl_bind         *bind;
    struct evpl_rpc2_agent   *agent;
    struct evpl_rpc2_metric  *metric;
    struct evpl_rpc2_program *program;
    struct evpl_rpc2_msg     *next;
};

struct evpl_rpc2_program {
    uint32_t                 program;
    uint32_t                 version;
    uint32_t                 maxproc;
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
