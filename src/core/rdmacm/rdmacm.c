// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
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

<<<<<<< HEAD
struct evpl_rdmacm_sr {
    struct evpl_rdmacm_id *rdmacm_id;
    int                    is_rw;

    union {
        struct {
            void  (*callback)(
                int   status,
                void *private_data);
            void *private_data;
        } rw;
        struct {
            uint64_t               length;
            int                    n_iov_ref;
            struct evpl_iovec_ref *iov_ref[32];
        } send;

    };
};

=======
>>>>>>> origin/main
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

    qp_attr.send_ops_flags = IBV_QP_EX_WITH_SEND |
        IBV_QP_EX_WITH_RDMA_READ |
        IBV_QP_EX_WITH_RDMA_WRITE;

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
    struct rdma_conn_param          conn_param;
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
            conn_param.private_data        = rdmacm_id;
            conn_param.retry_count         = evpl_shared->config->rdmacm_retry_count;
            conn_param.rnr_retry_count     = evpl_shared->config->rdmacm_rnr_retry_count;
            conn_param.initiator_depth     = 0;
            conn_param.responder_resources = 16;

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

                listen_bind->accept_callback(
                    evpl,
                    listen_bind,
                    remote_addr,
                    accepted_id,
                    listen_bind->private_data);

            } else {
                /* XXX why is this necessary? */
                cm_event->id->qp = (struct ibv_qp *) rdmacm_id->qp;

                rc = rdma_accept(cm_event->id, &conn_param);

                evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno)
                                     );
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
                                         bind->protocol->id,  ah);

                evpl_address_release(rdmacm_id->resolve_addr);
                rdmacm_id->resolve_addr = NULL;

            } else {
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

            evpl_close(evpl, bind);
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

        wr->wr_id = (uint64_t) req;
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

static const char *
ibv_wc_opcode_str(enum ibv_wc_opcode opcode)
{
    switch (opcode) {
        case IBV_WC_SEND:
            return "send";
        case IBV_WC_RECV:
            return "recv";
        case IBV_WC_RDMA_READ:
            return "read";
        case IBV_WC_RDMA_WRITE:
            return "write";
        default:
            return "unknown";
    } /* switch */
} /* ibv_wc_opcode_str */

static inline void
evpl_rdmacm_process_send_completions(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id,
    struct evpl_dgram     *signaled_dgram,
    int                    status)
{
    struct evpl_dgram *dgram;
    struct evpl_bind  *bind = evpl_private2bind(rdmacm_id);
    struct evpl_iovec *iovec;
    struct evpl_notify notify;
    int                i, seen_completed = 0;
    uint64_t           total_bytes = 0;
    uint64_t           total_msgs  = 0;

    while (bind->dgram_send.tail != bind->dgram_send.waist && !seen_completed) {

        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

<<<<<<< HEAD
        ring->tail = (ring->tail + 1) & ring->mask;

        if (sr->is_rw) {
            --rdmacm_id->cur_rdma_rw;
            sr->rw.callback(0, sr->rw.private_data);
        } else {
            for (i = 0; i < sr->send.n_iov_ref; ++i) {
                evpl_iovec_ref_release(sr->send.iov_ref[i]);
            }
            total_bytes += sr->send.length;
            total_msgs++;
            --rdmacm_id->cur_sends;
=======
        if (dgram == signaled_dgram) {
            seen_completed = 1;
>>>>>>> origin/main
        }

        evpl_dgram_ring_remove(&bind->dgram_send);

<<<<<<< HEAD
    if (completed_sr->is_rw) {
        --rdmacm_id->cur_rdma_rw;

        completed_sr->rw.callback(status, completed_sr->rw.private_data);
    } else {

        for (i = 0; i < completed_sr->send.n_iov_ref; ++i) {
            evpl_iovec_ref_release(completed_sr->send.iov_ref[i]);
=======
        for (i = 0; i < dgram->niov; ++i) {
            iovec = evpl_iovec_ring_tail(&bind->iovec_send);
            evpl_iovec_decref(iovec);
            evpl_iovec_ring_remove(&bind->iovec_send);
>>>>>>> origin/main
        }

        --rdmacm_id->cur_sends;

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
            if (dgram->callback) {
                dgram->callback(status, dgram->private_data);
            }
        } else {
            total_bytes += dgram->length;
            total_msgs++;
        }
    }

    if (unlikely(!seen_completed)) {
        evpl_rdmacm_error("completed dgram %p not found", signaled_dgram);
        return;
    }

    bind = evpl_private2bind(rdmacm_id);

    if (likely(rdmacm_id->id)) {

        if ((total_bytes || total_msgs) && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
            notify.notify_type   = EVPL_NOTIFY_SENT;
            notify.notify_status = 0;
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
    struct evpl_dgram     *signaled_dgram,
    int                    status)
{
    struct evpl_dgram *dgram;
    struct evpl_bind  *bind = evpl_private2bind(rdmacm_id);
    int                i, seen_completed = 0;

    while (bind->dgram_read.tail != bind->dgram_read.waist && !seen_completed) {

        dgram = evpl_dgram_ring_tail(&bind->dgram_read);

        if (dgram == signaled_dgram) {
            seen_completed = 1;
        }

        evpl_dgram_ring_remove(&bind->dgram_read);

        for (i = 0; i < dgram->niov; ++i) {
            evpl_iovec_ring_remove(&bind->iovec_rdma_read);
        }

        --rdmacm_id->cur_rdma_reads;

        if (dgram->callback) {
            dgram->callback(status, dgram->private_data);
        }

    }

    if (unlikely(!seen_completed)) {
        evpl_rdmacm_error("completed dgram %p not found", signaled_dgram);
        return;
    }

    bind = evpl_private2bind(rdmacm_id);


    if (rdmacm_id->cur_rdma_reads < rdmacm_id->max_rdma_reads && !evpl_dgram_ring_is_empty(&bind->dgram_read)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_rdmacm_process_send_completions */


static FORCE_INLINE void
evpl_rdmacm_poll_cq(
    struct evpl               *evpl,
    struct evpl_rdmacm_device *dev,
    int                        drain)
{
    struct evpl_rdmacm            *rdmacm = dev->rdmacm;
    struct evpl_rdmacm_id         *rdmacm_id;
    struct evpl_rdmacm_request    *req;
    struct evpl_dgram             *dgram;
    struct evpl_bind              *bind;
    struct evpl_notify             notify;
    struct ibv_cq_ex              *cq      = (struct ibv_cq_ex *) dev->cq;
    static struct ibv_poll_cq_attr cq_attr = { .comp_mask = 0 };
    int                            rc, n;
    uint32_t                       qp_num, wc_flags;

 again:

    rc = ibv_start_poll(cq, &cq_attr);

    if (rc) {
        return;
    }

    n = 0;

    evpl_activity(evpl);

    do {

        n++;

        if (unlikely(cq->status)) {
            switch (ibv_wc_read_opcode(cq)) {
                case IBV_WC_RECV:
                    evpl_rdmacm_error(
                        "receive completion error wr_id %lu type %u status %u vendor_err %u",
                        cq->wr_id,
                        ibv_wc_read_opcode(cq),
                        cq->status,
                        ibv_wc_read_vendor_err(cq));
                    break;
                case IBV_WC_SEND:
                case IBV_WC_RDMA_READ:
                case IBV_WC_RDMA_WRITE:
                    evpl_rdmacm_error(
                        "rdma %s completion error wr_id %lu type %u status %u vendor_err %u",
                        ibv_wc_opcode_str(ibv_wc_read_opcode(cq)),
                        cq->wr_id,
                        ibv_wc_read_opcode(cq),
                        cq->status,
                        ibv_wc_read_vendor_err(cq));

                    dgram     = (struct evpl_dgram *) cq->wr_id;
                    rdmacm_id = evpl_bind_private(dgram->bind);

                    if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_READ) {
                        evpl_rdmacm_process_rdma_read_completions(evpl, rdmacm_id, dgram, EIO);
                    } else {
                        evpl_rdmacm_process_send_completions(evpl, rdmacm_id, dgram, EIO);
                    }

                    break;
                default:
                    abort();
            } /* switch */
        } else {
            switch (ibv_wc_read_opcode(cq)) {
                case IBV_WC_RECV:

                    req               = (struct evpl_rdmacm_request *) cq->wr_id;
                    req->iovec.length = ibv_wc_read_byte_len(cq);

                    qp_num = ibv_wc_read_qp_num(cq);

                    rdmacm_id = evpl_rdmacm_qp_lookup_find(dev, qp_num);

                    if (unlikely(!rdmacm_id)) {
                        evpl_iovec_release(&req->iovec);
                    } else if (rdmacm_id->stream) {

                        bind = evpl_private2bind(rdmacm_id);

                        evpl_iovec_ring_add(&bind->iovec_recv, &req->iovec);

                        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
                        notify.notify_status = 0;

                        bind->notify_callback(evpl, bind, &notify,
                                              bind->private_data);
                    } else {

                        bind = evpl_private2bind(rdmacm_id);

                        wc_flags = ibv_wc_read_wc_flags(cq);

                        if (wc_flags & IBV_WC_GRH) {
                            req->iovec.length -= 40;
                            req->iovec.data   += 40;
                        }

                        notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
                        notify.notify_status   = 0;
                        notify.recv_msg.iovec  = &req->iovec;
                        notify.recv_msg.niov   = 1;
                        notify.recv_msg.addr   = bind->remote;
                        notify.recv_msg.length = req->iovec.length;

                        bind->notify_callback(evpl, bind, &notify,
                                              bind->private_data);
                    }

                    --dev->srq_fill;
                    req->used = 0;
                    LL_PREPEND(dev->srq_free_reqs, req);

                    break;
                case IBV_WC_SEND:
                case IBV_WC_RDMA_READ:
                case IBV_WC_RDMA_WRITE:

                    dgram     = (struct evpl_dgram *) cq->wr_id;
                    rdmacm_id = evpl_bind_private(dgram->bind);

                    if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_READ) {
                        evpl_rdmacm_process_rdma_read_completions(evpl, rdmacm_id, dgram, 0);
                    } else {
                        evpl_rdmacm_process_send_completions(evpl, rdmacm_id, dgram, 0);
                    }

                    break;
                default:
                    evpl_rdmacm_error("Unhandled RDMA completion opcode %u",
                                      ibv_wc_read_opcode(cq));
            } /* switch */
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

        dev->context = rdmacm_devices->context[i];
        dev->index   = i;

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

        memset(&pd_attr, 0, sizeof(pd_attr));

        pd_attr.pd        = dev->parent_pd;
        pd_attr.td        = dev->td;
        pd_attr.comp_mask = 0;

        dev->pd = ibv_alloc_parent_domain(dev->context, &pd_attr);

        evpl_rdmacm_abort_if(!dev->pd,
                             "Failed to create protection domain for rdma device");

        memset(&cq_attr, 0, sizeof(cq_attr));

        cq_attr.cqe           = evpl_shared->config->rdmacm_cq_size;
        cq_attr.cq_context    = dev;
        cq_attr.channel       = dev->comp_channel;
        cq_attr.comp_vector   = 0;
        cq_attr.parent_domain = dev->pd;
        cq_attr.wc_flags      = IBV_WC_EX_WITH_BYTE_LEN | IBV_WC_EX_WITH_QP_NUM;
        cq_attr.flags         = IBV_CREATE_CQ_ATTR_SINGLE_THREADED;
        cq_attr.comp_mask     = IBV_CQ_INIT_ATTR_MASK_FLAGS |
            IBV_CQ_INIT_ATTR_MASK_PD;

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
                evpl_iovec_release(&req->iovec);
            }
        }

        evpl_free(dev->srq_reqs);

        ibv_destroy_cq(dev->cq);
        ibv_dealloc_pd(dev->pd);
        ibv_destroy_comp_channel(dev->comp_channel);
        ibv_dealloc_td(dev->td);
    }

    evpl_free(rdmacm->devices);
    evpl_free(rdmacm->active_devices);
    evpl_free(rdmacm);
} /* evpl_rdmacm_destroy */

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
    rdmacm_id->stream      = rdmacm_id->stream;
    rdmacm_id->connected   = 0;
    rdmacm_id->id          = accepted_id->id;
    rdmacm_id->id->context = rdmacm_id;

    evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.private_data        = rdmacm;
    conn_param.retry_count         = evpl_shared->config->rdmacm_retry_count;
    conn_param.rnr_retry_count     = evpl_shared->config->rdmacm_rnr_retry_count;
    conn_param.responder_resources = accepted_id->conn_param.initiator_depth;
    conn_param.initiator_depth     = accepted_id->conn_param.initiator_depth;//responder_resources;

    rdmacm_id->max_rdma_reads = accepted_id->conn_param.initiator_depth;
    rdmacm_id->cur_rdma_reads = 0;

    rc = rdma_accept(accepted_id->id, &conn_param);

    evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));

    evpl_free(accepted_id);
} /* evpl_rdmacm_attach */

void
evpl_rdmacm_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    int                    rc;

    rdmacm_id->stream         = bind->protocol->stream;
    rdmacm_id->ud             = 0;
    rdmacm_id->cur_rdma_reads = 0;

    rdmacm_id->resolve_id = NULL;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id listen error %s", strerror(rc));

    rc = rdma_bind_addr(rdmacm_id->id, bind->local->addr);

    evpl_rdmacm_abort_if(rc, "Failed to bind to address: %s", strerror(errno));

    rdma_listen(rdmacm_id->id, 1024);

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

        evpl_rdmacm_abort_if(!mrset[i], "Failed to register RDMA memory region")
        ;
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
    struct ibv_mr        **mrset     = evpl_memory_framework_private(iov, EVPL_FRAMEWORK_RDMACM);
    struct ibv_mr         *mr        = mrset[rdmacm_id->devindex];

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

        qp->wr_id    = (uint64_t) dgram;
        qp->wr_flags = IBV_SEND_SIGNALED;

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

    if (unlikely(!qp || !rdmacm_id->connected)) {
        return;
    }

    ibv_wr_start(qp);

    evpl_rdmacm_flush_rdma_reads(evpl, bind);

    while (rdmacm_id->cur_sends < send_limit &&
           bind->dgram_send.waist != bind->dgram_send.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_send);

        if (rdmacm_id->ud) {
            ah = evpl_address_private(dgram->addr, bind->protocol->id);

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

<<<<<<< HEAD
                sr->send.iov_ref[nsge] = cur->ref;

=======
>>>>>>> origin/main
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

<<<<<<< HEAD
                sr->send.iov_ref[nsge] = cur->ref;

=======
>>>>>>> origin/main
                nsge++;

                bind->iovec_send.waist = (bind->iovec_send.waist + 1) & bind->iovec_send.mask;
            }

        }

<<<<<<< HEAD
        sr->send.n_iov_ref = nsge;
        sr->send.length    = dgram->length;
        sr->is_rw          = 0;

=======
>>>>>>> origin/main
        ++rdmacm_id->cur_sends;

        bind->dgram_send.waist = (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

        need_signal =  rdmacm_id->cur_sends == send_limit ||
            bind->dgram_send.waist == bind->dgram_send.head;


        qp->wr_id    = (uint64_t) dgram;
        qp->wr_flags = need_signal ? IBV_SEND_SIGNALED : 0;

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_SEND) {
            ibv_wr_send(qp);
        } else {
            ibv_wr_rdma_write(qp, dgram->remote_key, dgram->remote_address);
        }

        if (send_inline) {
            ibv_wr_set_inline_data_list(qp, nsge, dbuf);
        } else {
            ibv_wr_set_sge_list(qp, nsge, sge);
        }

        if (rdmacm_id->ud) {
            ah = evpl_address_private(dgram->addr, bind->protocol->id);

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
<<<<<<< HEAD
evpl_rdmacm_flush_stream(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id     *rdmacm_id = evpl_bind_private(bind);
    struct evpl_global_config *config    = evpl_shared->config;
    struct evpl_rdmacm_sr     *sr;
    struct evpl_iovec         *cur;
    struct ibv_qp_ex          *qp = rdmacm_id->qp;
    struct ibv_mr             *mr, **mrset;
    struct ibv_sge            *sge;
    int                        nsge, rc;

    if (unlikely(!qp || !rdmacm_id->connected)) {
        return;
    }

    evpl_rdmacm_flush_rdma_rw(evpl, bind);

    sge = alloca(sizeof(struct ibv_sge) * config->max_num_iovec);

    while (!evpl_iovec_ring_is_empty(&bind->iovec_send)) {

        sr = evpl_rdmacm_sr_alloc(rdmacm_id);

        nsge = 0;

        sr->send.length = 0;

        while (nsge < config->max_num_iovec &&
               !evpl_iovec_ring_is_empty(&bind->iovec_send)) {

            cur = evpl_iovec_ring_tail(&bind->iovec_send);

            if (sr->send.length + cur->length > config->max_datagram_size) {
                break;
            }

            mrset = evpl_memory_framework_private(cur,
                                                  EVPL_FRAMEWORK_RDMACM);

            mr = mrset[rdmacm_id->devindex];

            sge[nsge].addr   = (uint64_t) cur->data;
            sge[nsge].length = cur->length;
            sge[nsge].lkey   = mr->lkey;

            sr->send.iov_ref[nsge] = cur->ref;

            nsge++;
            sr->send.length += cur->length;

            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        sr->send.n_iov_ref = nsge;
        sr->send.length    = 0;
        sr->is_rw          = 0;

        ibv_wr_start(qp);

        qp->wr_id    = (uint64_t) sr;
        qp->wr_flags = evpl_iovec_ring_is_empty(&bind->iovec_send) ? IBV_SEND_SIGNALED : 0;
        ibv_wr_send(qp);
        ibv_wr_set_sge_list(qp, nsge, sge);

        rc = ibv_wr_complete(qp);

        evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(
                                 errno));

        ++rdmacm_id->active_sends;
    }

    if (rdmacm_id->active_sends == 0 &&
        evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

} /* evpl_rdmacm_flush_strean */

void
=======
>>>>>>> origin/main
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

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->resolve_id,
                        rdmacm_id,
                        RDMA_PS_UDP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));


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
        rdma_disconnect(rdmacm_id->id);
    } else {
        evpl_rdmacm_destroy_qp(evpl, rdmacm_id);
    }

} /* evpl_rdmacm_pending_close */

void
evpl_rdmacm_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id     *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm        *rdmacm    = rdmacm_id->rdmacm;
    struct evpl_rdmacm_device *dev       = rdmacm_id->dev;

    if (rdmacm) {
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
    .id            = EVPL_DATAGRAM_RDMACM_RC,
    .connected     = 1,
    .stream        = 0,
    .rdma          = 1,
    .name          = "DATAGRAM_RDMACM_RC",
    .framework     = &evpl_framework_rdmacm,
    .listen        = evpl_rdmacm_listen,
    .attach        = evpl_rdmacm_attach,
    .connect       = evpl_rdmacm_connect,
    .pending_close = evpl_rdmacm_pending_close,
    .close         = evpl_rdmacm_close,
    .flush         = evpl_rdmacm_flush_datagram,
};

struct evpl_protocol  evpl_rdmacm_rc_stream = {
    .id            = EVPL_STREAM_RDMACM_RC,
    .connected     = 1,
    .stream        = 1,
    .rdma          = 1,
    .name          = "STREAM_RDMACM_RC",
    .framework     = &evpl_framework_rdmacm,
    .listen        = evpl_rdmacm_listen,
    .attach        = evpl_rdmacm_attach,
    .connect       = evpl_rdmacm_connect,
    .pending_close = evpl_rdmacm_pending_close,
    .close         = evpl_rdmacm_close,
    .flush         = evpl_rdmacm_flush_datagram,
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
