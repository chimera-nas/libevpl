// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <stdlib.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>





#include <utlist.h>

#include "core/evpl.h"
#include "core/rdmacm/rdmacm.h"
#include "core/protocol.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/evpl_shared.h"
#include "core/event_fn.h"
#include "core/poll.h"

extern struct evpl_shared *evpl_shared;

#define evpl_rdmacm_debug(...) evpl_debug("rdmacm", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_rdmacm_info(...)  evpl_info("rdmacm", __FILE__, __LINE__, \
                                         __VA_ARGS__)
#define evpl_rdmacm_error(...) evpl_error("rdmacm", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_rdmacm_fatal(...) evpl_fatal("rdmacm", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_rdmacm_abort(...) evpl_abort("rdmacm", __FILE__, __LINE__, \
                                          __VA_ARGS__)

#define evpl_rdmacm_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "rdmacm", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_rdmacm_abort_if(cond, ...) \
        evpl_abort_if(cond, "rdmacm", __FILE__, __LINE__, __VA_ARGS__)

/* Completion IDs must survive datagram-ring growth. The low two bits name
 * the request kind; the remaining bits hold a per-QP sequence or SRQ index. */
#define EVPL_RDMACM_WR_SEND 0U
#define EVPL_RDMACM_WR_READ 1U
#define EVPL_RDMACM_WR_RECV 2U
#define EVPL_RDMACM_WR_MASK (UINT64_MAX >> 2)

struct ibv_context **context = NULL;

struct evpl_rdmacm_ah {
    struct ibv_ah    **ahset;
    struct ibv_ah_attr ah_attr;
    uint32_t           qp_num;
    uint32_t           qkey;
};

struct evpl_rdmacm_request {
    struct evpl_iovec           iovec;
    struct ibv_sge              sge;
    int                         used;
    struct evpl_rdmacm_request *next;
};

struct evpl_rdmacm_sr_ring {
    struct evpl_rdmacm_sr *sr;
    int                    size;
    int                    mask;
    int                    head;
    int                    tail;
};

struct evpl_rdmacm_devices {
    struct ibv_context    **context;
    struct ibv_pd         **pd;
    struct ibv_device_attr *device_attr;
    int                     num_devices;
};

#define QP_LOOKUP_LEVEL2_SIZE  4096
#define QP_LOOKUP_LEVEL1_SIZE  4096
#define QP_LOOKUP_LEVEL1_SHIFT 12
#define QP_LOOKUP_LEVEL2_MASK  0xFFF

struct evpl_rdmacm_device {
    struct evpl_event           event;
    struct evpl_rdmacm         *rdmacm;
    struct ibv_context         *context;
    struct ibv_comp_channel    *comp_channel;
    struct ibv_td              *td;
    struct ibv_pd              *parent_pd;
    struct ibv_pd              *pd;
    struct ibv_cq              *cq;
    struct ibv_srq             *srq;
    struct evpl_rdmacm_request *srq_reqs;
    struct evpl_rdmacm_request *srq_free_reqs;
    int                         srq_max;
    int                         srq_min;
    int                         srq_fill;
    int                         index;
    int                         num_qp;
    uint8_t                     initiator_depth;
    uint8_t                     responder_resources;
    struct evpl_rdmacm_id     **qp_lookup[QP_LOOKUP_LEVEL1_SIZE];
};

struct evpl_rdmacm {
    struct rdma_event_channel   *event_channel;
    struct evpl_event            event;
    struct evpl_poll            *poll;
    struct evpl_rdmacm_listener *listener;
    struct evpl_rdmacm_device   *devices;
    int                          num_devices;
    int                          num_active_devices;
    struct evpl_rdmacm_device  **active_devices;

};

#define evpl_event_rdmacm(eventp) \
        container_of((eventp), struct evpl_rdmacm, event)

#define evpl_event_rdmacm_device(eventp) \
        container_of((eventp), struct evpl_rdmacm_device, event)

struct evpl_rdmacm_accepted_id {
    struct rdma_cm_id     *id;
    struct rdma_conn_param conn_param;
};

struct evpl_rdmacm_id {
    struct evpl_rdmacm           *rdmacm;
    struct evpl_rdmacm_device    *dev;
    struct rdma_cm_id            *id;
    struct rdma_cm_id            *resolve_id;
    struct ibv_qp_ex             *qp;
    int                           stream;
    int                           ud;
    int                           connected;
    int                           max_rdma_reads;
    int                           cur_rdma_reads;
    int                           cur_sends;
    uint64_t                      sends_posted, sends_completed;
    uint64_t                      reads_posted, reads_completed;

    /* RNR diagnostics: message-SEND (reply) work requests in flight on this
     * connection, and the high-water mark.  If a SEND completes with RNR
     * (status 13) this is dumped: a value near/above the client's ~128 recv
     * credit affirms chimera over-sending replies on the connection; a small
     * value points elsewhere (wrong-QP routing or a client recv gap). */
    int                           dbg_send_inflight;
    int                           dbg_send_hwm;
    uint64_t                      dbg_send_rnr;

    /* Per-connection 1:1 invariant: CALLs delivered to this bind vs reply
     * SENDs issued on it.  Replies must follow the bind the CALL arrived on,
     * so dbg_reply_sent must never exceed dbg_req_recv.  If it does, chimera
     * put a reply on a connection that never sent the matching CALL
     * (wrong-QP routing) -- which the client RNRs because it posted no
     * receive there.  Dumped at the RNR. */
    uint64_t                      dbg_req_recv;
    uint64_t                      dbg_reply_sent;

    struct evpl_address          *resolve_addr;

    struct evpl_rdmacm_listen_id *listen_id;

    uint32_t                      qp_num;
    int                           devindex;
    struct evpl_rdmacm_sr_ring    sr_ring;
};

static inline void
evpl_rdmacm_qp_lookup_init(struct evpl_rdmacm_device *dev)
{
    uint32_t i;

    for (i = 0; i < QP_LOOKUP_LEVEL1_SIZE; ++i) {
        dev->qp_lookup[i] = NULL;
    }
} /* evpl_rdmacm_qp_lookup_init */

static inline void
evpl_rdmacm_qp_lookup_cleanup(struct evpl_rdmacm_device *dev)
{
    uint32_t i;

    for (i = 0; i < QP_LOOKUP_LEVEL1_SIZE; ++i) {
        if (dev->qp_lookup[i]) {
            evpl_free(dev->qp_lookup[i]);
            dev->qp_lookup[i] = NULL;
        }
    }
} /* evpl_rdmacm_qp_lookup_cleanup */

static inline void
evpl_rdmacm_qp_lookup_add(
    struct evpl_rdmacm_device *dev,
    uint32_t                   qp_num,
    struct evpl_rdmacm_id     *rdmacm_id)
{
    uint32_t level1_idx = qp_num >> QP_LOOKUP_LEVEL1_SHIFT;
    uint32_t level2_idx = qp_num & QP_LOOKUP_LEVEL2_MASK;

    evpl_rdmacm_abort_if(level1_idx >= QP_LOOKUP_LEVEL1_SIZE,
                         "qp_num %u exceeds maximum 24-bit value", qp_num);

    if (!dev->qp_lookup[level1_idx]) {
        dev->qp_lookup[level1_idx] = evpl_zalloc(
            QP_LOOKUP_LEVEL2_SIZE * sizeof(struct evpl_rdmacm_id *));
    }

    dev->qp_lookup[level1_idx][level2_idx] = rdmacm_id;
} /* evpl_rdmacm_qp_lookup_add */

static inline struct evpl_rdmacm_id *
evpl_rdmacm_qp_lookup_find(
    struct evpl_rdmacm_device *dev,
    uint32_t                   qp_num)
{
    uint32_t level1_idx = qp_num >> QP_LOOKUP_LEVEL1_SHIFT;
    uint32_t level2_idx = qp_num & QP_LOOKUP_LEVEL2_MASK;

    if (level1_idx >= QP_LOOKUP_LEVEL1_SIZE || !dev->qp_lookup[level1_idx]) {
        return NULL;
    }

    return dev->qp_lookup[level1_idx][level2_idx];
} /* evpl_rdmacm_qp_lookup_find */

static inline void
evpl_rdmacm_qp_lookup_del(
    struct evpl_rdmacm_device *dev,
    uint32_t                   qp_num)
{
    uint32_t level1_idx = qp_num >> QP_LOOKUP_LEVEL1_SHIFT;
    uint32_t level2_idx = qp_num & QP_LOOKUP_LEVEL2_MASK;

    if (level1_idx >= QP_LOOKUP_LEVEL1_SIZE || !dev->qp_lookup[level1_idx]) {
        return;
    }

    dev->qp_lookup[level1_idx][level2_idx] = NULL;
} /* evpl_rdmacm_qp_lookup_del */

static struct evpl_rdmacm_device *
evpl_rdmacm_map_device(
    struct evpl_rdmacm *rdmacm,
    struct ibv_context *context)
{
    struct evpl_rdmacm_device *dev;
    int                        i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        if (dev->context == context) {
            return dev;
        }
    }

    evpl_rdmacm_abort("Unable to map RDMA device context for device %s",
                      context->device->name);

    return NULL;
} /* evpl_rdmacm_map_device */

static void
evpl_rdmacm_create_qp(
    struct evpl           *evpl,
    struct evpl_rdmacm    *rdmacm,
    struct evpl_rdmacm_id *rdmacm_id)
{
    struct evpl_rdmacm_device *dev;
    struct ibv_qp_init_attr_ex qp_attr;
    int                        rc;

    dev = evpl_rdmacm_map_device(rdmacm, rdmacm_id->id->verbs);

    if (dev->num_qp == 0) {
        rdmacm->active_devices[rdmacm->num_active_devices++] = dev;
    }

    dev->num_qp++;

    rdmacm_id->dev      = dev;
    rdmacm_id->devindex = dev->index;

    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.pd = dev->pd;

    if (rdmacm_id->ud) {
        qp_attr.qp_type = IBV_QPT_UD;
    } else {
        qp_attr.qp_type = IBV_QPT_RC;
    }

    qp_attr.send_cq             = dev->cq;
    qp_attr.recv_cq             = dev->cq;
    qp_attr.srq                 = dev->srq;
    qp_attr.cap.max_send_wr     = evpl_shared->config->rdmacm_sq_size;
    qp_attr.cap.max_recv_wr     = evpl_shared->config->rdmacm_sq_size;
    qp_attr.cap.max_send_sge    = evpl_shared->config->rdmacm_max_sge;
    qp_attr.cap.max_recv_sge    = evpl_shared->config->rdmacm_max_sge;
    qp_attr.cap.max_inline_data = evpl_shared->config->rdmacm_max_inline;
    qp_attr.sq_sig_all          = 0;

    qp_attr.send_ops_flags = IBV_QP_EX_WITH_SEND;
    if (!rdmacm_id->ud) {
        qp_attr.send_ops_flags |= IBV_QP_EX_WITH_RDMA_READ |
            IBV_QP_EX_WITH_RDMA_WRITE;
    }

    qp_attr.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS |
        IBV_QP_INIT_ATTR_PD |
        IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;

    rc = rdma_create_qp_ex(rdmacm_id->id, &qp_attr);

    evpl_rdmacm_abort_if(rc, "rdma_create_qp error %s", strerror(errno));

    rdmacm_id->qp     = ibv_qp_to_qp_ex(rdmacm_id->id->qp);
    rdmacm_id->qp_num = rdmacm_id->id->qp->qp_num;

    evpl_rdmacm_qp_lookup_add(dev, rdmacm_id->qp_num, rdmacm_id);

} /* evpl_rdmacm_create_qp */

static void
evpl_rdmacm_set_options(struct rdma_cm_id *id)
{
    int rc;

    if (evpl_shared->config->rdmacm_tos) {
        uint8_t tos = evpl_shared->config->rdmacm_tos;
        rc = rdma_set_option(id, RDMA_OPTION_ID, RDMA_OPTION_ID_TOS, &tos, sizeof(tos));

        evpl_rdmacm_abort_if(rc, "rdma_set_option error %s", strerror(errno));
    }
} /* evpl_rdmacm_set_options */


static void
evpl_rdmacm_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm             *rdmacm = evpl_event_rdmacm(event);
    struct evpl_rdmacm_id          *rdmacm_id;
    struct evpl_bind               *bind;
    struct evpl_bind               *listen_bind;
    struct evpl_notify              notify;
    struct evpl_address            *remote_addr;
    struct evpl_rdmacm_accepted_id *accepted_id;
    struct evpl_rdmacm_ah          *ah;
    struct rdma_cm_event           *cm_event;
    struct rdma_cm_id              *request_id;
    struct rdma_conn_param          conn_param;
    struct ibv_qp_attr              qp_attr;
    struct ibv_qp_init_attr         qp_init_attr;
    int                             rc;

 again:

    if (rdma_get_cm_event(rdmacm->event_channel, &cm_event)) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    rdmacm_id = cm_event->id->context;

    switch (cm_event->event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED:

            rc = rdma_resolve_route(cm_event->id,
                                    evpl_shared->config->resolve_timeout_ms);

            evpl_rdmacm_abort_if(rc, "rdma_resolve_route error %s", strerror(
                                     errno));
            break;
        case RDMA_CM_EVENT_ROUTE_RESOLVED:

            if (cm_event->id != rdmacm_id->resolve_id) {
                evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);
            }

            memset(&conn_param, 0, sizeof(conn_param));
            conn_param.private_data    = rdmacm_id;
            conn_param.retry_count     = evpl_shared->config->rdmacm_retry_count;
            conn_param.rnr_retry_count = evpl_shared->config->rdmacm_rnr_retry_count;
            if (rdmacm_id->ud) {
                conn_param.qp_num = rdmacm_id->qp_num;
                conn_param.srq    = 1;
            } else {
                conn_param.initiator_depth     = rdmacm_id->dev->initiator_depth;
                conn_param.responder_resources = rdmacm_id->dev->responder_resources;
            }

            rc = rdma_connect(cm_event->id, &conn_param);

            evpl_rdmacm_abort_if(rc, "rdma_connect error %s", strerror(errno));

            break;
        case RDMA_CM_EVENT_CONNECT_REQUEST:

            evpl_rdmacm_set_options(cm_event->id);

            if (!rdmacm_id->ud) {

                listen_bind = evpl_private2bind(rdmacm_id);

                remote_addr = evpl_address_init(&cm_event->id->route.addr.dst_addr,
                                                sizeof(cm_event->id->route.addr.dst_addr));

                accepted_id             = evpl_zalloc(sizeof(*accepted_id));
                accepted_id->id         = cm_event->id;
                accepted_id->conn_param = cm_event->param.conn;

                rdma_ack_cm_event(cm_event);
                listen_bind->accept_callback(
                    evpl,
                    listen_bind,
                    remote_addr,
                    accepted_id,
                    listen_bind->private_data);
                goto again;

            } else {
                /* SIDR advertises the bound UD QP; this request does not own
                 * that QP and has no subsequent connection lifecycle. */
                request_id = cm_event->id;
                memset(&conn_param, 0, sizeof(conn_param));
                conn_param.qp_num = rdmacm_id->qp_num;
                conn_param.srq    = 1;
                rc                = rdma_accept(request_id, &conn_param);
                evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));
                rdma_ack_cm_event(cm_event);
                rdma_destroy_id(request_id);
                goto again;
            }

            break;
        case RDMA_CM_EVENT_ESTABLISHED:

            bind = evpl_private2bind(rdmacm_id);

            if (cm_event->id == rdmacm_id->resolve_id) {

                ah = evpl_zalloc(sizeof(*ah));

                ah->ahset = evpl_zalloc(sizeof(struct ibv_ah *) *
                                        rdmacm->num_devices);

                ah->ah_attr = cm_event->param.ud.ah_attr;
                ah->qp_num  = cm_event->param.ud.qp_num;
                ah->qkey    = cm_event->param.ud.qkey;

                evpl_address_set_private(rdmacm_id->resolve_addr,
                                         EVPL_FRAMEWORK_RDMACM, ah);

                evpl_address_release(rdmacm_id->resolve_addr);
                rdmacm_id->resolve_addr = NULL;
                evpl_defer(evpl, &bind->flush_deferral);

            } else {
                if (!rdmacm_id->ud) {
                    /* Use the negotiated outbound depth on both peers. A
                     * zero-initialized limit would strand every queued read. */
                    rc = ibv_query_qp(rdmacm_id->id->qp, &qp_attr,
                                      IBV_QP_MAX_QP_RD_ATOMIC, &qp_init_attr);
                    evpl_rdmacm_abort_if(rc, "ibv_query_qp: %s", strerror(rc));
                    rdmacm_id->max_rdma_reads = qp_attr.max_rd_atomic;
                }
                /* On the connecting (client) side bind->local was never
                 * populated; the accept path sets it, but connect() does not.
                 * Now that the connection is established the cm_id's route
                 * holds the resolved local address and port, so record it
                 * (mirrors the server attach path) before notifying the
                 * upper layer, which may query the local address. */
                if (!bind->local) {
                    bind->local = evpl_address_init(
                        &cm_event->id->route.addr.src_addr,
                        sizeof(cm_event->id->route.addr.src_addr));
                }

                notify.notify_type   = EVPL_NOTIFY_CONNECTED;
                notify.notify_status = 0;

                bind->notify_callback(evpl, bind, &notify,
                                      bind->private_data);

                rdmacm_id->connected = 1;
                evpl_defer(evpl, &bind->flush_deferral);
            }
            break;
        case RDMA_CM_EVENT_CONNECT_RESPONSE:
            break;
        case RDMA_CM_EVENT_CONNECT_ERROR:
            evpl_rdmacm_debug("connect error");
            break;
        case RDMA_CM_EVENT_UNREACHABLE:
            evpl_rdmacm_debug("unreachable");
            break;
        case RDMA_CM_EVENT_DISCONNECTED:

            bind = evpl_private2bind(rdmacm_id);

            rdmacm_id->connected = 0;

            /* Reply to a peer's DREQ, including simultaneous disconnects.
             * For a DREP this is harmless: the CM has nothing left to send. */
            rc = rdma_disconnect(cm_event->id);
            evpl_rdmacm_abort_if(rc, "rdma_disconnect reply: %s", strerror(errno));

            if (bind->flags & EVPL_BIND_CLOSE_DEFERRED) {
                /* We initiated this disconnect; the bind has been parked on
                 * pending_close_binds awaiting exactly this event.  Clear the
                 * deferral so the core finalizes (close + destroy) it on the
                 * next iteration, now that this event has been acked. */
                bind->flags &= ~EVPL_BIND_CLOSE_DEFERRED;
            } else {
                evpl_close(evpl, bind);
            }
            break;
        case RDMA_CM_EVENT_REJECTED:

            evpl_rdmacm_info("RDMA connection rejected");

            bind = evpl_private2bind(rdmacm_id);

            evpl_close(evpl, bind);

            break;
        case RDMA_CM_EVENT_ADDR_CHANGE:
            /* No action required */
            break;
        default:
            evpl_rdmacm_debug("unhandled rdmacm event %u", cm_event->event);
    } /* switch */

    rdma_ack_cm_event(cm_event);

    goto again;

} /* evpl_rdmacm_event_callback */

void
evpl_rdmacm_fill_srq(
    struct evpl               *evpl,
    struct evpl_rdmacm        *rdmacm,
    struct evpl_rdmacm_device *dev)
{
    struct evpl_rdmacm_request *req;
    struct ibv_mr             **mrset, *mr;
    struct ibv_recv_wr         *wrs, *wr, *bad_wr;
    int                         rc, i, batch;
    int                         size;

    if (evpl_shared->config->rdmacm_datagram_size_override) {
        size = evpl_shared->config->rdmacm_datagram_size_override;
    } else {
        size = evpl_shared->config->max_datagram_size;
    }

    batch = evpl_shared->config->rdmacm_srq_batch;

    if (dev->srq_max - dev->srq_fill < batch) {
        batch = dev->srq_max - dev->srq_fill;
    }

    wrs = alloca(sizeof(struct ibv_recv_wr) * batch);
    wr  = NULL;

    for (i = 0; i < batch; i++) {

        if (wr) {
            wr->next = &wrs[i];
        }

        wr = &wrs[i];

        req = dev->srq_free_reqs;
        LL_DELETE(dev->srq_free_reqs, req);

        req->used = 1;

        evpl_iovec_alloc_datagram(evpl, &req->iovec, size);

        mrset = evpl_memory_framework_private(&req->iovec, EVPL_FRAMEWORK_RDMACM);

        mr = mrset[dev->index];

        req->sge.addr   = (uint64_t) req->iovec.data;
        req->sge.length = req->iovec.length;
        req->sge.lkey   = mr->lkey;

        wr->wr_id = ((uint64_t) (req - dev->srq_reqs) << 2) | EVPL_RDMACM_WR_RECV;
        wr->next  = NULL;

        wr->sg_list = &req->sge;
        wr->num_sge = 1;
    }

    rc = ibv_post_srq_recv(dev->srq, &wrs[0], &bad_wr);

    evpl_rdmacm_abort_if(rc, "ibv_post_srq_recv error %s", strerror(rc));

    dev->srq_fill += batch;

} /* evpl_rdmacm_fill_srq */

void
evpl_rdmacm_fill_all_srq(
    struct evpl        *evpl,
    struct evpl_rdmacm *rdmacm)
{
    struct evpl_rdmacm_device *dev;
    int                        i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];
        while (dev->srq_fill < dev->srq_max) {
            evpl_rdmacm_fill_srq(evpl, rdmacm, dev);
        }
    }
} /* evpl_rdmacm_fill_all_srq */

static inline void
evpl_rdmacm_process_send_completions(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id,
    uint64_t               completed,
    int                    status)
{
    struct evpl_dgram *dgram;
    struct evpl_bind  *bind = evpl_private2bind(rdmacm_id);
    struct evpl_iovec *iovec;
    struct evpl_notify notify;
    int                i;
    uint64_t           remaining   = (completed - rdmacm_id->sends_completed) & EVPL_RDMACM_WR_MASK;
    uint64_t           total_bytes = 0;
    uint64_t           total_msgs  = 0;

    evpl_rdmacm_abort_if(!remaining || remaining > (uint64_t) rdmacm_id->cur_sends,
                         "invalid send completion sequence");
    while (remaining--) {
        evpl_rdmacm_abort_if(bind->dgram_send.tail == bind->dgram_send.waist,
                             "completion exceeds posted datagrams");

        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

        evpl_dgram_ring_remove(&bind->dgram_send);

        for (i = 0; i < dgram->niov; ++i) {
            iovec = evpl_iovec_ring_tail(&bind->iovec_send);
            evpl_iovec_release_internal(evpl, iovec);
            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        --rdmacm_id->cur_sends;
        rdmacm_id->sends_completed = (rdmacm_id->sends_completed + 1) & EVPL_RDMACM_WR_MASK;

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_SEND) {
            --rdmacm_id->dbg_send_inflight;
        }

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
            if (dgram->callback) {
                dgram->callback(status, dgram->private_data);
            }
        } else {
            total_bytes += dgram->length;
            total_msgs++;
        }
    }

    bind = evpl_private2bind(rdmacm_id);

    if (likely(rdmacm_id->id)) {

        if ((total_bytes || total_msgs) && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
            notify.notify_type   = EVPL_NOTIFY_SENT;
            notify.notify_status = status;
            notify.sent.bytes    = total_bytes;
            notify.sent.msgs     = total_msgs;

            bind->notify_callback(evpl, bind, &notify,
                                  bind->private_data);
        }

        if (unlikely(rdmacm_id->cur_sends == 0 &&
                     evpl_iovec_ring_is_empty(&bind->iovec_send))) {
            if (bind->flags & EVPL_BIND_FINISH) {
                evpl_close(evpl, bind);
            }
        }
    }

    if (!evpl_dgram_ring_is_empty(&bind->dgram_send)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_rdmacm_process_send_completions */


static inline void
evpl_rdmacm_process_rdma_read_completions(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id,
    uint64_t               completed,
    int                    status)
{
    struct evpl_dgram *dgram;
    struct evpl_bind  *bind = evpl_private2bind(rdmacm_id);
    int                i;
    uint64_t           remaining = (completed - rdmacm_id->reads_completed) & EVPL_RDMACM_WR_MASK;

    evpl_rdmacm_abort_if(!remaining || remaining > (uint64_t) rdmacm_id->cur_rdma_reads,
                         "invalid read completion sequence");
    while (remaining--) {
        evpl_rdmacm_abort_if(bind->dgram_read.tail == bind->dgram_read.waist,
                             "completion exceeds posted datagrams");

        dgram = evpl_dgram_ring_tail(&bind->dgram_read);

        evpl_dgram_ring_remove(&bind->dgram_read);

        for (i = 0; i < dgram->niov; ++i) {
            struct evpl_iovec *iovec = evpl_iovec_ring_tail(&bind->iovec_rdma_read);

            evpl_iovec_release_internal(evpl, iovec);
            evpl_iovec_ring_remove(&bind->iovec_rdma_read);
        }

        --rdmacm_id->cur_rdma_reads;
        rdmacm_id->reads_completed = (rdmacm_id->reads_completed + 1) & EVPL_RDMACM_WR_MASK;

        if (dgram->callback) {
            dgram->callback(status, dgram->private_data);
        }

    }

    bind = evpl_private2bind(rdmacm_id);


    if (rdmacm_id->cur_rdma_reads < rdmacm_id->max_rdma_reads && !evpl_dgram_ring_is_empty(&bind->dgram_read)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_rdmacm_process_send_completions */


static void
evpl_rdmacm_recv_stream(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *received)
{
    struct evpl_iovec *iov;
    struct evpl_notify notify;
    int                length, niov;

    evpl_iovec_ring_add(&bind->iovec_recv, received);

    if (!bind->segment_callback) {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
        return;
    }

    iov = alloca(sizeof(*iov) * evpl_shared->config->max_num_iovec);
    while (!(bind->flags & EVPL_BIND_PENDING_CLOSED)) {
        length = bind->segment_callback(evpl, bind, bind->private_data);
        if (length < 0) {
            evpl_close(evpl, bind);
            break;
        }
        if (!length || evpl_iovec_ring_bytes(&bind->iovec_recv) < (uint64_t) length) {
            break;
        }
        niov                   = evpl_iovec_ring_copyv(evpl, iov, &bind->iovec_recv, length);
        notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
        notify.notify_status   = 0;
        notify.recv_msg.iovec  = iov;
        notify.recv_msg.niov   = niov;
        notify.recv_msg.length = length;
        notify.recv_msg.addr   = bind->remote;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_rdmacm_recv_stream */


static FORCE_INLINE void
evpl_rdmacm_poll_cq(
    struct evpl               *evpl,
    struct evpl_rdmacm_device *dev,
    int                        drain)
{
    struct evpl_rdmacm            *rdmacm = dev->rdmacm;
    struct evpl_rdmacm_id         *rdmacm_id;
    struct evpl_rdmacm_request    *req;
    struct evpl_bind              *bind;
    struct evpl_notify             notify;
    struct ibv_cq_ex              *cq      = (struct ibv_cq_ex *) dev->cq;
    static struct ibv_poll_cq_attr cq_attr = { .comp_mask = 0 };
    int                            rc, n;
    uint32_t                       qp_num, kind;
    uint64_t                       id;

 again:

    rc = ibv_start_poll(cq, &cq_attr);

    if (rc) {
        return;
    }

    n = 0;

    evpl_activity(evpl);

    do {

        n++;

        /* qp_num and wr_id remain valid on errors; opcode does not. */
        qp_num    = ibv_wc_read_qp_num(cq);
        kind      = cq->wr_id & 3;
        id        = cq->wr_id >> 2;
        rdmacm_id = evpl_rdmacm_qp_lookup_find(dev, qp_num);

        if (unlikely(cq->status)) {
            evpl_rdmacm_error("completion error wr_id %lu qp %u status %u vendor_err %u",
                              cq->wr_id, qp_num, cq->status, ibv_wc_read_vendor_err(cq));
        }

        if (kind == EVPL_RDMACM_WR_RECV) {
            evpl_rdmacm_abort_if(id >= (uint64_t) dev->srq_max, "invalid receive request ID");
            req = &dev->srq_reqs[id];
            if (unlikely(cq->status)) {
                evpl_iovec_release_internal(evpl, &req->iovec);
            } else {
                req->iovec.length = ibv_wc_read_byte_len(cq);

                if (unlikely(!rdmacm_id)) {
                    evpl_iovec_release_internal(evpl, &req->iovec);
                } else if (rdmacm_id->stream) {

                    bind = evpl_private2bind(rdmacm_id);

                    evpl_rdmacm_recv_stream(evpl, bind, &req->iovec);
                } else {

                    bind = evpl_private2bind(rdmacm_id);

                    /* UD reserves a GRH-sized prefix even without a
                     * valid GRH. RC has no prefix; RXE may still set the
                     * completion flag there, so use the QP type. */
                    if (rdmacm_id->ud) {
                        evpl_rdmacm_abort_if(req->iovec.length < sizeof(struct ibv_grh),
                                             "short UD receive buffer");
                        req->iovec.length -= sizeof(struct ibv_grh);
                        req->iovec.data    = (char *) req->iovec.data + sizeof(struct ibv_grh);
                    }

                    rdmacm_id->dbg_req_recv++;

                    notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
                    notify.notify_status   = 0;
                    notify.recv_msg.iovec  = &req->iovec;
                    notify.recv_msg.niov   = 1;
                    notify.recv_msg.addr   = bind->remote;
                    notify.recv_msg.length = req->iovec.length;

                    bind->notify_callback(evpl, bind, &notify,
                                          bind->private_data);
                }

            }
            --dev->srq_fill;
            req->used = 0;
            LL_PREPEND(dev->srq_free_reqs, req);
        } else if (rdmacm_id) {
            if (kind == EVPL_RDMACM_WR_READ) {
                evpl_rdmacm_process_rdma_read_completions(evpl, rdmacm_id, id, cq->status ? EIO : 0);
            } else {
                evpl_rdmacm_abort_if(kind != EVPL_RDMACM_WR_SEND, "invalid send request ID");
                if (cq->status == IBV_WC_RNR_RETRY_EXC_ERR) {
                    rdmacm_id->dbg_send_rnr++;
                    evpl_rdmacm_error(
                        "RNR-DIAG qp=%u send_inflight=%d send_hwm=%d cur_sends=%d rnr_count=%lu req_recv=%lu reply_sent=%lu excess_replies=%ld",
                        rdmacm_id->qp_num, rdmacm_id->dbg_send_inflight,
                        rdmacm_id->dbg_send_hwm, rdmacm_id->cur_sends,
                        rdmacm_id->dbg_send_rnr,
                        rdmacm_id->dbg_req_recv, rdmacm_id->dbg_reply_sent,
                        (long) (rdmacm_id->dbg_reply_sent - rdmacm_id->dbg_req_recv));
                }
                evpl_rdmacm_process_send_completions(evpl, rdmacm_id, id, cq->status ? EIO : 0);
            }
        }
        if (unlikely(cq->status) && rdmacm_id) {
            evpl_close(evpl, evpl_private2bind(rdmacm_id));
        }


    } while (n < 64 && ibv_next_poll(cq) == 0);

    ibv_end_poll(cq);

    while (dev->srq_fill < dev->srq_max &&
           dev->srq_max - dev->srq_fill >= evpl_shared->config->rdmacm_srq_batch) {
        evpl_rdmacm_fill_srq(evpl, rdmacm, dev);
    }

    if (drain && n) {
        goto again;
    }


} /* evpl_rdmacm_poll_cq */


static void
evpl_rdmacm_comp_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm_device *dev = evpl_event_rdmacm_device(event);
    struct ibv_cq             *ev_cq;
    void                      *ev_ctx;
    int                        rc;

    rc = ibv_get_cq_event(dev->comp_channel, &ev_cq, &ev_ctx);

    if (rc) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    rc = ibv_req_notify_cq(dev->cq, 0);

    evpl_rdmacm_abort_if(rc, "ibv_req_notify_cq error %s", strerror(errno));

    evpl_rdmacm_poll_cq(evpl, dev, 0);

    ibv_ack_cq_events(dev->cq, 1);
} /* evpl_rdmacm_comp_callback */

void *
evpl_rdmacm_init()
{
    struct evpl_rdmacm_devices *devices;
    int                         i;


    devices = evpl_zalloc(sizeof(*devices));

    devices->context = rdma_get_devices(&devices->num_devices);

    devices->pd = evpl_zalloc(sizeof(struct ibv_pd *) * devices->num_devices);

    devices->device_attr = evpl_zalloc(sizeof(struct ibv_device_attr) * devices->num_devices);

    for (i = 0; i < devices->num_devices; ++i) {
        devices->pd[i] = ibv_alloc_pd(devices->context[i]);

        evpl_rdmacm_abort_if(!devices->pd[i],
                             "Failed to create parent protection domain for rdma device");

        ibv_query_device(devices->context[i], &devices->device_attr[i]);
    }

    return devices;
} /* evpl_rdmacm_init */

void
evpl_rdmacm_cleanup(void *private_data)
{
    struct evpl_rdmacm_devices *devices = private_data;
    int                         i;

    for (i = 0; i < devices->num_devices; ++i) {
        ibv_dealloc_pd(devices->pd[i]);
    }

    rdma_free_devices(devices->context);
    evpl_free(devices->device_attr);
    evpl_free(devices->pd);
    evpl_free(devices);

} /* evpl_rdmacm_cleanup */

static void
evpl_rdmacm_poll_enter(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_rdmacm        *rdmacm = arg;
    struct evpl_rdmacm_device *dev;
    int                        i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        evpl_event_read_disinterest(evpl, &dev->event);
    }
} /* evpl_rdmacm_poll_enter */

static void
evpl_rdmacm_poll_exit(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_rdmacm        *rdmacm = arg;
    struct evpl_rdmacm_device *dev;
    int                        i, rc;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        evpl_event_read_interest(evpl, &dev->event);

        rc = ibv_req_notify_cq(dev->cq, 0);

        evpl_rdmacm_abort_if(rc, "ibv_req_notify_cq error %s", strerror(errno));

        evpl_rdmacm_poll_cq(evpl, dev, 1);
    }
} /* evpl_rdmacm_poll_exit */

static void
evpl_rdmacm_poll(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_rdmacm        *rdmacm = arg;
    struct evpl_rdmacm_device *dev;
    int                        i;

    for (i = 0; i < rdmacm->num_active_devices; ++i) {
        dev = rdmacm->active_devices[i];
        evpl_rdmacm_poll_cq(evpl, dev, 0);
    }

} /* evpl_rdmacm_poll */

void *
evpl_rdmacm_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_rdmacm_devices        *rdmacm_devices = private_data;
    struct evpl_rdmacm_device         *dev;
    struct evpl_rdmacm                *rdmacm;
    struct ibv_srq_init_attr           srq_init_attr;
    struct ibv_cq_init_attr_ex         cq_attr;
    struct ibv_td_init_attr            td_attr;
    struct ibv_parent_domain_init_attr pd_attr;
    int                                flags, rc, i, j;

    rdmacm = evpl_zalloc(sizeof(*rdmacm));

    rdmacm->num_devices = rdmacm_devices->num_devices;

    rdmacm->devices = evpl_zalloc(
        sizeof(struct evpl_rdmacm_device) * rdmacm->num_devices);

    rdmacm->active_devices = evpl_zalloc(
        sizeof(struct evpl_rdmacm_device *) * rdmacm->num_devices);

    rdmacm->num_active_devices = 0;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        dev->rdmacm = rdmacm;

        dev->context         = rdmacm_devices->context[i];
        dev->index           = i;
        dev->initiator_depth = rdmacm_devices->device_attr[i].max_qp_init_rd_atom > 16 ?
            16 : rdmacm_devices->device_attr[i].max_qp_init_rd_atom;
        dev->responder_resources = rdmacm_devices->device_attr[i].max_qp_rd_atom > 16 ?
            16 : rdmacm_devices->device_attr[i].max_qp_rd_atom;

        evpl_rdmacm_qp_lookup_init(dev);

        dev->parent_pd = rdmacm_devices->pd[i];

        dev->comp_channel = ibv_create_comp_channel(dev->context);

        evpl_rdmacm_abort_if(!dev->comp_channel,
                             "Failed to create completion chnanel for rdma device");

        flags = fcntl(dev->comp_channel->fd, F_GETFL, 0);

        evpl_rdmacm_abort_if(flags == -1, "fcntl(F_GETFL) failed");

        flags |= O_NONBLOCK;

        rc = fcntl(dev->comp_channel->fd, F_SETFL, flags);

        evpl_rdmacm_abort_if(rc == -1, "fcntl(F_SETFL, O_NONBLOCK) failed");

        evpl_add_event(evpl, &dev->event, dev->comp_channel->fd,
                       evpl_rdmacm_comp_callback, NULL, NULL);

        evpl_event_read_interest(evpl, &dev->event);

        memset(&td_attr, 0, sizeof(td_attr));

        dev->td = ibv_alloc_td(dev->context, &td_attr);

        evpl_rdmacm_abort_if(!dev->td && errno != EOPNOTSUPP && errno != ENOSYS,
                             "Failed to allocate thread domain for rdma device: %s",
                             strerror(errno));

        memset(&pd_attr, 0, sizeof(pd_attr));

        pd_attr.pd        = dev->parent_pd;
        pd_attr.td        = dev->td;
        pd_attr.comp_mask = 0;

        if (dev->td) {
            dev->pd = ibv_alloc_parent_domain(dev->context, &pd_attr);
            evpl_rdmacm_abort_if(!dev->pd && errno != EOPNOTSUPP && errno != ENOSYS,
                                 "Failed to allocate parent domain for rdma device: %s",
                                 strerror(errno));
        }
        /* Thread/parent domains are optional provider optimizations. Keep the
         * shared registration PD when they are unavailable (e.g. Soft-RoCE). */
        if (!dev->pd) {
            dev->pd = dev->parent_pd;
        }

        memset(&cq_attr, 0, sizeof(cq_attr));

        cq_attr.cqe         = evpl_shared->config->rdmacm_cq_size;
        cq_attr.cq_context  = dev;
        cq_attr.channel     = dev->comp_channel;
        cq_attr.comp_vector = 0;
        cq_attr.wc_flags    = IBV_WC_EX_WITH_BYTE_LEN | IBV_WC_EX_WITH_QP_NUM;
        if (dev->pd != dev->parent_pd) {
            cq_attr.parent_domain = dev->pd;
            cq_attr.flags         = IBV_CREATE_CQ_ATTR_SINGLE_THREADED;
            cq_attr.comp_mask     = IBV_CQ_INIT_ATTR_MASK_FLAGS | IBV_CQ_INIT_ATTR_MASK_PD;
        }

        dev->cq = (struct ibv_cq *) ibv_create_cq_ex(dev->context, &cq_attr);

        evpl_rdmacm_abort_if(!dev->cq,
                             "Failed to create completion queue for rdma device");

        rc = ibv_req_notify_cq(dev->cq, 0);

        evpl_rdmacm_abort_if(rc, "ibv_req_notify_cq error %s", strerror(errno));

        memset(&srq_init_attr, 0, sizeof(srq_init_attr));

        srq_init_attr.attr.max_wr  = evpl_shared->config->rdmacm_srq_size;
        srq_init_attr.attr.max_sge = 1;

        dev->srq = ibv_create_srq(dev->pd, &srq_init_attr);

        evpl_rdmacm_abort_if(!dev->srq,
                             "Failed to create shared receive queue for rdma device");

        dev->srq_max = evpl_shared->config->rdmacm_srq_size;
        dev->srq_min = evpl_shared->config->rdmacm_srq_min;

        dev->srq_reqs = evpl_zalloc(sizeof(struct evpl_rdmacm_request) *
                                    dev->srq_max);

        for (j = 0; j < dev->srq_max; ++j) {
            LL_PREPEND(dev->srq_free_reqs, &dev->srq_reqs[j]);
        }
    }

    rdmacm->event_channel = rdma_create_event_channel();

    evpl_rdmacm_abort_if(!rdmacm->event_channel,
                         "Failed to create rdma event channel");

    flags = fcntl(rdmacm->event_channel->fd, F_GETFL, 0);

    evpl_rdmacm_abort_if(flags == -1, "fcntl(F_GETFL) failed");

    flags |= O_NONBLOCK;

    rc = fcntl(rdmacm->event_channel->fd, F_SETFL, flags);

    evpl_rdmacm_abort_if(rc == -1, "fcntl(F_SETFL, O_NONBLOCK) failed");

    evpl_add_event(evpl, &rdmacm->event, rdmacm->event_channel->fd,
                   evpl_rdmacm_event_callback, NULL, NULL);

    evpl_event_read_interest(evpl, &rdmacm->event);

    rdmacm->poll = evpl_add_poll(evpl,
                                 evpl_rdmacm_poll_enter,
                                 evpl_rdmacm_poll_exit,
                                 evpl_rdmacm_poll,
                                 rdmacm);

    if (evpl_shared->config->rdmacm_srq_prefill) {
        evpl_rdmacm_fill_all_srq(evpl, rdmacm);
    }

    return rdmacm;
} /* evpl_rdmacm_create */

void
evpl_rdmacm_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_rdmacm         *rdmacm = private_data;
    struct evpl_rdmacm_device  *dev;
    struct evpl_rdmacm_request *req;
    int                         i, j;

    evpl_remove_poll(evpl, rdmacm->poll);

    rdma_destroy_event_channel(rdmacm->event_channel);

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        evpl_remove_event(evpl, &dev->event);

        evpl_rdmacm_qp_lookup_cleanup(dev);

        ibv_destroy_srq(dev->srq);

        for (j = 0; j < dev->srq_max; ++j) {
            req = &dev->srq_reqs[j];

            if (req->used) {
                evpl_iovec_release_internal(evpl, &req->iovec);
            }
        }

        evpl_free(dev->srq_reqs);

        ibv_destroy_cq(dev->cq);
        if (dev->pd != dev->parent_pd) {
            ibv_dealloc_pd(dev->pd);
        }
        ibv_destroy_comp_channel(dev->comp_channel);
        if (dev->td) {
            ibv_dealloc_td(dev->td);
        }
    }

    evpl_free(rdmacm->devices);
    evpl_free(rdmacm->active_devices);
    evpl_free(rdmacm);
} /* evpl_rdmacm_destroy */

static void
evpl_rdmacm_discard(
    struct evpl *evpl,
    void        *accepted)
{
    struct evpl_rdmacm_accepted_id *a = accepted;

    (void) evpl;
    rdma_reject(a->id, NULL, 0);
    rdma_destroy_id(a->id);
    evpl_free(a);
} /* evpl_rdmacm_discard */

void
evpl_rdmacm_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_rdmacm             *rdmacm;
    struct evpl_rdmacm_id          *rdmacm_id   = evpl_bind_private(bind);
    struct evpl_rdmacm_accepted_id *accepted_id = accepted;
    struct rdma_conn_param          conn_param;
    int                             rc;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_migrate_id(accepted_id->id, rdmacm->event_channel);

    evpl_rdmacm_abort_if(rc, "rdma_migrate_id error %s", strerror(errno));

    /* Set the local address to the actual interface address from the RDMA CM ID.
     * This is important when the server binds to 0.0.0.0/:: because the route.addr.src_addr
     * contains the actual interface IP the client connected to. */
    bind->local = evpl_address_init(&accepted_id->id->route.addr.src_addr,
                                    sizeof(accepted_id->id->route.addr.src_addr));

    rdmacm_id->rdmacm      = rdmacm;
    rdmacm_id->stream      = bind->protocol->stream;
    rdmacm_id->connected   = 0;
    rdmacm_id->id          = accepted_id->id;
    rdmacm_id->id->context = rdmacm_id;

    evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.private_data    = rdmacm;
    conn_param.retry_count     = evpl_shared->config->rdmacm_retry_count;
    conn_param.rnr_retry_count = evpl_shared->config->rdmacm_rnr_retry_count;
    /* CM presents the request limits from the accepting peer's perspective. */
    conn_param.responder_resources = rdmacm_id->dev->responder_resources;
    if (conn_param.responder_resources > accepted_id->conn_param.responder_resources) {
        conn_param.responder_resources = accepted_id->conn_param.responder_resources;
    }
    conn_param.initiator_depth = rdmacm_id->dev->initiator_depth;
    if (conn_param.initiator_depth > accepted_id->conn_param.initiator_depth) {
        conn_param.initiator_depth = accepted_id->conn_param.initiator_depth;
    }

    rdmacm_id->max_rdma_reads = 0;
    rdmacm_id->cur_rdma_reads = 0;

    rc = rdma_accept(accepted_id->id, &conn_param);

    evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));

    evpl_free(accepted_id);
} /* evpl_rdmacm_attach */

int
evpl_rdmacm_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    char                   addr_str[80];
    int                    rc;

    rdmacm_id->stream         = bind->protocol->stream;
    rdmacm_id->ud             = 0;
    rdmacm_id->cur_rdma_reads = 0;

    rdmacm_id->resolve_id = NULL;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    if (rc) {
        evpl_rdmacm_error("rdma_create_id listen error %s", strerror(rc));
        return -1;
    }

    rc = rdma_bind_addr(rdmacm_id->id, bind->local->addr);

    if (rc) {
        evpl_address_get_address(bind->local, addr_str, sizeof(addr_str));
        evpl_rdmacm_error("Failed to bind to address %s: %s",
                          addr_str, strerror(errno));
        goto fail;
    }

    rc = rdma_listen(rdmacm_id->id, 1024);

    if (rc) {
        evpl_rdmacm_error("Failed to listen on cm id: %s", strerror(errno));
        goto fail;
    }

    return 0;

 fail:

    rdma_destroy_id(rdmacm_id->id);

    rdmacm_id->id = NULL;

    return -1;
} /* evpl_rdmacm_listen */

void
evpl_rdmacm_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    int                    rc;

    rdmacm_id->stream     = bind->protocol->stream;
    rdmacm_id->ud         = 0;
    rdmacm_id->connected  = 0;
    rdmacm_id->resolve_id = NULL;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm_id->rdmacm = rdmacm;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id,
                        RDMA_PS_TCP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    evpl_rdmacm_set_options(rdmacm_id->id);

    rc = rdma_resolve_addr(rdmacm_id->id, NULL, bind->remote->addr,
                           evpl_shared->config->resolve_timeout_ms);

    evpl_rdmacm_abort_if(rc, "rdma_resolve_addr error %s", strerror(errno));
} /* evpl_rdmacm_connect */

void *
evpl_rdmacm_register(
    void *buffer,
    int   size,
    void *buffer_private,
    void *private_data)
{
    struct evpl_rdmacm_devices *rdmacm_devices = private_data;
    struct ibv_mr             **mrset;
    int                         i;

    if (buffer_private) {
        mrset = (struct ibv_mr **) buffer_private;
    } else {
        mrset = evpl_zalloc(sizeof(struct ibv_mr *) * rdmacm_devices->
                            num_devices);
    }

    for (i = 0; i < rdmacm_devices->num_devices; ++i) {

        if (mrset[i]) {
            continue;
        }

        mrset[i] = ibv_reg_mr(rdmacm_devices->pd[i], buffer, size,
                              IBV_ACCESS_LOCAL_WRITE |
                              IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE |
                              IBV_ACCESS_RELAXED_ORDERING);

        evpl_rdmacm_abort_if(!mrset[i], "Failed to register %d-byte RDMA memory region on %s: %s",
                             size, ibv_get_device_name(rdmacm_devices->pd[i]->context->device),
                             strerror(errno));
    }

    return mrset;
} /* evpl_rdmacm_register */

void
evpl_rdmacm_unregister(
    void *buffer_private,
    void *private_data)
{
    struct evpl_rdmacm_devices *rdmacm_devices = private_data;
    struct ibv_mr             **mrset          = buffer_private;
    int                         i;

    for (i = 0; i < rdmacm_devices->num_devices; ++i) {
        ibv_dereg_mr(mrset[i]);
    }

    evpl_free(mrset);

} /* evpl_rdmacm_unregister */

static void
evpl_rdmacm_get_rdma_address(
    struct evpl_bind  *bind,
    struct evpl_iovec *iov,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct ibv_mr        **mrset;
    struct ibv_mr         *mr;

    /* The rkey we return is for the MR registered against the device this
     * QP is bound to (mrset[rdmacm_id->devindex]).  devindex is only set
     * once evpl_rdmacm_create_qp runs at RDMA_CM_EVENT_ROUTE_RESOLVED;
     * before then it is still the evpl_zalloc default of 0.  If the cm_id
     * later binds to a different device (multi-HCA / bonded topologies
     * routinely do), the rkey we advertised in any pre-bind call belongs
     * to a PD the responder QP can't see, and the responder rejects the
     * subsequent RDMA_READ with REM_ACCESS_ERR (Mellanox responder
     * vendor 0x95 / requester vendor 0x88).  The bug is silent because
     * the caller already queued the SEND with the wrong rkey; the
     * failure surfaces minutes or millions of ops later at the responder.
     *
     * Refuse the call loudly so callers learn to wait for
     * EVPL_NOTIFY_CONNECTED before issuing operations that advertise a
     * remote key. */
    evpl_rdmacm_abort_if(
        !rdmacm_id->dev,
        "evpl_rdma_get_address called before the QP is bound to a device; "
        "callers must wait for EVPL_NOTIFY_CONNECTED on this bind before "
        "issuing operations that advertise an rkey to the peer");

    mrset = evpl_memory_framework_private(iov, EVPL_FRAMEWORK_RDMACM);

    evpl_rdmacm_abort_if(
        !mrset,
        "evpl_rdma_get_address: iovec is from a slab that was never "
        "registered with the rdmacm framework (framework_private[RDMACM] "
        "is NULL).  Was the iovec allocated before the framework attached "
        "and not picked up by evpl_allocator_reregister?");

    mr = mrset[rdmacm_id->devindex];

    *r_key     = mr->rkey;
    *r_address = (uint64_t) iov->data;
} /* evpl_rdmacm_get_rdma_address */

static void
evpl_rdmacm_ud_resolve(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id,
    struct evpl_address   *address)
{
    int rc;

    /* A completed SIDR lookup cannot resolve another destination on the
     * same CM ID. The bound data QP remains on rdmacm_id->id. */
    if (rdmacm_id->resolve_id) {
        rdma_destroy_id(rdmacm_id->resolve_id);
    }
    rc = rdma_create_id(rdmacm_id->rdmacm->event_channel,
                        &rdmacm_id->resolve_id, rdmacm_id, RDMA_PS_UDP);
    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    rdmacm_id->resolve_addr = address;

    evpl_address_incref(address);

    rc = rdma_resolve_addr(rdmacm_id->resolve_id, NULL, address->addr,
                           evpl_shared->config->resolve_timeout_ms);

    evpl_rdmacm_abort_if(rc, "Failed to resolve rdmacm address");

} /* evpl_rdmacm_ud_resolve */

static inline void
evpl_rdmacm_flush_rdma_reads(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_dgram     *dgram;
    struct ibv_qp_ex      *qp = rdmacm_id->qp;
    struct ibv_mr        **mrset, *mr;
    struct evpl_iovec     *cur;
    struct ibv_sge        *sge;
    int                    i;

    while (rdmacm_id->cur_rdma_reads < rdmacm_id->max_rdma_reads &&
           bind->dgram_read.waist != bind->dgram_read.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_read);

        rdmacm_id->cur_rdma_reads++;

        sge = alloca(sizeof(struct ibv_sge) * dgram->niov);

        for (i = 0; i < dgram->niov; ++i) {

            evpl_rdmacm_abort_if(bind->iovec_rdma_read.waist == bind->iovec_rdma_read.head,
                                 "iovec_rdma_read ring is empty");

            cur = evpl_iovec_ring_waist(&bind->iovec_rdma_read);

            mrset = evpl_memory_framework_private(cur, EVPL_FRAMEWORK_RDMACM);

            mr = mrset[rdmacm_id->devindex];

            sge[i].addr   = (uint64_t) cur->data;
            sge[i].length = cur->length;
            sge[i].lkey   = mr->lkey;

            bind->iovec_rdma_read.waist = (bind->iovec_rdma_read.waist + 1) & bind->iovec_rdma_read.mask;
        }

        rdmacm_id->reads_posted = (rdmacm_id->reads_posted + 1) & EVPL_RDMACM_WR_MASK;
        qp->wr_id               = (rdmacm_id->reads_posted << 2) | EVPL_RDMACM_WR_READ;
        qp->wr_flags            = IBV_SEND_SIGNALED;

        ibv_wr_rdma_read(qp, dgram->remote_key, dgram->remote_address);

        ibv_wr_set_sge_list(qp, dgram->niov, sge);

        bind->dgram_read.waist = (bind->dgram_read.waist + 1) & bind->dgram_read.mask;
    }
} /* evpl_rdmacm_flush_rdma_read */

void
evpl_rdmacm_flush_datagram(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_iovec     *cur;
    struct evpl_dgram     *dgram;
    struct ibv_qp_ex      *qp = rdmacm_id->qp;
    struct ibv_mr         *mr, **mrset;
    struct ibv_sge        *sge;
    struct ibv_data_buf   *dbuf;
    struct evpl_rdmacm_ah *ah;
    int                    nsge, rc, send_inline, need_signal;
    int                    send_limit = evpl_shared->config->rdmacm_sq_size;

    if (unlikely(!qp || (!rdmacm_id->ud && !rdmacm_id->connected))) {
        return;
    }

    ibv_wr_start(qp);

    evpl_rdmacm_flush_rdma_reads(evpl, bind);

    while (rdmacm_id->cur_sends < send_limit &&
           bind->dgram_send.waist != bind->dgram_send.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_send);

        if (rdmacm_id->ud) {
            ah = evpl_address_private(dgram->addr, EVPL_FRAMEWORK_RDMACM);

            if (!ah) {
                if (!rdmacm_id->resolve_addr) {
                    evpl_rdmacm_ud_resolve(evpl, rdmacm_id, dgram->addr);
                }
                break;
            }

            if (ah->ahset[rdmacm_id->devindex] == NULL) {
                ah->ahset[rdmacm_id->devindex] = ibv_create_ah(
                    rdmacm_id->dev->pd, &ah->ah_attr);
            }
        }

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_SEND &&
            dgram->length <= evpl_shared->config->rdmacm_max_inline) {
            send_inline = 1;

            nsge = 0;

            dbuf = alloca(sizeof(struct ibv_data_buf) * dgram->niov);

            while (nsge < dgram->niov) {

                evpl_rdmacm_abort_if(bind->iovec_send.waist == bind->iovec_send.head, "iovec_send ring is empty");


                cur = evpl_iovec_ring_waist(&bind->iovec_send);

                dbuf[nsge].addr   = cur->data;
                dbuf[nsge].length = cur->length;

                nsge++;

                bind->iovec_send.waist = (bind->iovec_send.waist + 1) & bind->iovec_send.mask;
            }

        } else {

            send_inline = 0;

            nsge = 0;

            sge = alloca(sizeof(struct ibv_sge) * dgram->niov);

            while (nsge < dgram->niov) {

                evpl_rdmacm_abort_if(bind->iovec_send.waist == bind->iovec_send.head, "iovec_send ring is empty");

                cur = evpl_iovec_ring_waist(&bind->iovec_send);

                mrset = evpl_memory_framework_private(cur, EVPL_FRAMEWORK_RDMACM);

                mr = mrset[rdmacm_id->devindex];

                sge[nsge].addr   = (uint64_t) cur->data;
                sge[nsge].length = cur->length;
                sge[nsge].lkey   = mr->lkey;

                nsge++;

                bind->iovec_send.waist = (bind->iovec_send.waist + 1) & bind->iovec_send.mask;
            }

        }

        ++rdmacm_id->cur_sends;

        bind->dgram_send.waist = (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

        need_signal =  rdmacm_id->cur_sends == send_limit ||
            bind->dgram_send.waist == bind->dgram_send.head;


        rdmacm_id->sends_posted = (rdmacm_id->sends_posted + 1) & EVPL_RDMACM_WR_MASK;
        qp->wr_id               = (rdmacm_id->sends_posted << 2) | EVPL_RDMACM_WR_SEND;
        qp->wr_flags            = (need_signal ? IBV_SEND_SIGNALED : 0) |
            (send_inline ? IBV_SEND_INLINE : 0);

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_SEND) {
            ibv_wr_send(qp);
            rdmacm_id->dbg_reply_sent++;
            if (++rdmacm_id->dbg_send_inflight > rdmacm_id->dbg_send_hwm) {
                rdmacm_id->dbg_send_hwm = rdmacm_id->dbg_send_inflight;
            }
        } else {
            ibv_wr_rdma_write(qp, dgram->remote_key, dgram->remote_address);
        }

        if (send_inline) {
            ibv_wr_set_inline_data_list(qp, nsge, dbuf);
        } else {
            ibv_wr_set_sge_list(qp, nsge, sge);
        }

        if (rdmacm_id->ud) {
            ah = evpl_address_private(dgram->addr, EVPL_FRAMEWORK_RDMACM);

            ibv_wr_set_ud_addr(qp, ah->ahset[rdmacm_id->devindex],
                               ah->qp_num, ah->qkey);

            evpl_address_release(dgram->addr);
        }

    }

    rc = ibv_wr_complete(qp);

    evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(
                             errno));

    if (unlikely(rdmacm_id->cur_sends == 0 &&
                 evpl_iovec_ring_is_empty(&bind->iovec_send))) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

} /* evpl_rdmacm_datagram */

void
evpl_rdmacm_bind(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    int                    rc;

    rdmacm_id->stream         = 0;
    rdmacm_id->ud             = 1;
    rdmacm_id->cur_rdma_reads = 0;
    rdmacm_id->cur_sends      = 0;
    rdmacm                    = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm_id->rdmacm = rdmacm;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id,
                        RDMA_PS_UDP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    evpl_rdmacm_set_options(rdmacm_id->id);

    rc = rdma_bind_addr(rdmacm_id->id, bind->local->addr);

    evpl_rdmacm_abort_if(rc, "rdma_bind_addr error %s", strerror(errno));

    evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);

    rc = rdma_listen(rdmacm_id->id, 256);

    evpl_rdmacm_abort_if(rc, "Failed to listen on rdmacm id");

} /* evpl_rdmacm_bind */

void
evpl_rdmacm_destroy_qp(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id)
{
    if (rdmacm_id->qp) {
        ibv_destroy_qp((struct ibv_qp *) rdmacm_id->qp);
        rdmacm_id->qp = NULL;
    }

    if (rdmacm_id->id) {
        rdma_destroy_id(rdmacm_id->id);
        rdmacm_id->id = NULL;
    }

    if (rdmacm_id->resolve_id) {
        rdma_destroy_id(rdmacm_id->resolve_id);
        rdmacm_id->resolve_id = NULL;
    }

    if (rdmacm_id->resolve_addr) {
        evpl_address_release(rdmacm_id->resolve_addr);
        rdmacm_id->resolve_addr = NULL;
    }
} /* evpl_rdmacm_destroy_qp */

void
evpl_rdmacm_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);

    if (rdmacm_id->connected) {
        /* rdma_disconnect() is asynchronous: the cm_id stays valid and a
         * RDMA_CM_EVENT_DISCONNECTED event is still owed to us.  Park the bind
         * until that event arrives (see evpl_rdmacm_event_callback) so the
         * cm_id is not torn down, and so the core does not free the bind's
         * private state out from under the still-live cm_id. */
        bind->flags |= EVPL_BIND_CLOSE_DEFERRED;
        rdma_disconnect(rdmacm_id->id);
    }

    /* The cm_id is destroyed in evpl_rdmacm_close(), which the core invokes
     * once the bind is no longer deferred. */

} /* evpl_rdmacm_pending_close */

void
evpl_rdmacm_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id     *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm        *rdmacm    = rdmacm_id->rdmacm;
    struct evpl_rdmacm_device *dev       = rdmacm_id->dev;

    if (dev) {
        --dev->num_qp;

        if (dev->num_qp == 0) {
            if (rdmacm->num_active_devices > 1) {
                for (int i = 0; i < rdmacm->num_active_devices; ++i) {
                    if (rdmacm->active_devices[i] == dev) {
                        if (i < rdmacm->num_active_devices - 1) {
                            rdmacm->active_devices[i] = rdmacm->active_devices[rdmacm->num_active_devices - 1];
                        }
                        break;
                    }
                }
            }
            rdmacm->num_active_devices--;
        }

        evpl_rdmacm_qp_lookup_del(rdmacm_id->dev, rdmacm_id->qp_num);
    }

    evpl_rdmacm_destroy_qp(evpl, rdmacm_id);
} /* evpl_rdmacm_close */

void
evpl_rdmacm_release_address(
    void *address_private,
    void *thread_private)
{
    struct evpl_rdmacm_ah      *ah             = address_private;
    struct evpl_rdmacm_devices *rdmacm_devices = thread_private;
    int                         i;

    for (i = 0; i < rdmacm_devices->num_devices; ++i) {
        if (ah->ahset[i]) {
            ibv_destroy_ah(ah->ahset[i]);
        }
    }

    evpl_free(ah->ahset);
    evpl_free(ah);
} /* evpl_rdmacm_release_address */

struct evpl_framework evpl_framework_rdmacm = {
    .id                = EVPL_FRAMEWORK_RDMACM,
    .name              = "RDMACM",
    .init              = evpl_rdmacm_init,
    .cleanup           = evpl_rdmacm_cleanup,
    .create            = evpl_rdmacm_create,
    .destroy           = evpl_rdmacm_destroy,
    .register_memory   = evpl_rdmacm_register,
    .unregister_memory = evpl_rdmacm_unregister,
    .get_rdma_address  = evpl_rdmacm_get_rdma_address,
    .release_address   = evpl_rdmacm_release_address,
};

struct evpl_protocol  evpl_rdmacm_rc_datagram = {
    .id               = EVPL_DATAGRAM_RDMACM_RC,
    .connected        = 1,
    .stream           = 0,
    .rdma             = 1,
    .name             = "DATAGRAM_RDMACM_RC",
    .framework        = &evpl_framework_rdmacm,
    .listen           = evpl_rdmacm_listen,
    .attach           = evpl_rdmacm_attach,
    .discard_accepted = evpl_rdmacm_discard,
    .connect          = evpl_rdmacm_connect,
    .pending_close    = evpl_rdmacm_pending_close,
    .close            = evpl_rdmacm_close,
    .flush            = evpl_rdmacm_flush_datagram,
};

struct evpl_protocol  evpl_rdmacm_rc_stream = {
    .id               = EVPL_STREAM_RDMACM_RC,
    .connected        = 1,
    .stream           = 1,
    .rdma             = 1,
    .name             = "STREAM_RDMACM_RC",
    .framework        = &evpl_framework_rdmacm,
    .listen           = evpl_rdmacm_listen,
    .attach           = evpl_rdmacm_attach,
    .discard_accepted = evpl_rdmacm_discard,
    .connect          = evpl_rdmacm_connect,
    .pending_close    = evpl_rdmacm_pending_close,
    .close            = evpl_rdmacm_close,
    .flush            = evpl_rdmacm_flush_datagram,
};

struct evpl_protocol  evpl_rdmacm_ud_datagram = {
    .id            = EVPL_DATAGRAM_RDMACM_UD,
    .connected     = 0,
    .stream        = 0,
    .name          = "DATAGRAM_RDMACM_UD",
    .framework     = &evpl_framework_rdmacm,
    .bind          = evpl_rdmacm_bind,
    .pending_close = evpl_rdmacm_pending_close,
    .close         = evpl_rdmacm_close,
    .flush         = evpl_rdmacm_flush_datagram,
};
