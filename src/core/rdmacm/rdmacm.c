// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

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

#include "uthash/uthash.h"
#include "uthash/utlist.h"

#include "core/rdmacm/rdmacm.h"
#include "core/internal.h"
#include "evpl/evpl.h"
#include "core/protocol.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/thread/thread.h"

#define evpl_rdmacm_debug(...) evpl_debug("rdmacm", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rdmacm_info(...)  evpl_info("rdmacm", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rdmacm_error(...) evpl_error("rdmacm", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rdmacm_fatal(...) evpl_fatal("rdmacm", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rdmacm_abort(...) evpl_abort("rdmacm", __FILE__, __LINE__, __VA_ARGS__)

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

struct evpl_rdmacm_sr {
    struct evpl_rdmacm_id *rdmacm_id;
    struct evpl_buffer    *bufref[32];
    int                    nbufref;
    uint64_t               length;

    void                   (*callback)(
        int   status,
        void *private_data);
    void                  *private_data;

    struct evpl_rdmacm_sr *next;
};

struct evpl_rdmacm_new_id {
    struct rdma_cm_event             *event;
    struct evpl_rdmacm_listen_member *listen_member;
    struct evpl_rdmacm_new_id        *next;
};

struct evpl_rdmacm_listen_member {
    struct evpl_rdmacm               *rdmacm;
    struct evpl_bind                 *bind;
    struct evpl_rdmacm_listen_member *prev;
    struct evpl_rdmacm_listen_member *next;
};

struct evpl_rdmacm_listen_id {
    struct sockaddr_storage           addr;
    unsigned int                      addrlen;
    struct evpl_rdmacm_id            *rdmacm_id;
    struct evpl_rdmacm_listen_member *members;
    struct UT_hash_handle             hh;
};


struct evpl_rdmacm_listener {
    int                           started;
    struct evpl_thread           *thread;
    pthread_mutex_t               mutex;
    struct evpl_rdmacm_listen_id *listen_ids;
};

struct evpl_rdmacm_devices {
    struct ibv_context        **context;
    struct ibv_pd             **pd;
    int                         num_devices;
    struct evpl_rdmacm_listener listener;
};

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
};

struct evpl_rdmacm {
    struct rdma_event_channel   *event_channel;
    struct evpl_config          *config;
    struct evpl_event            event;
    struct evpl_poll            *poll;
    struct evpl_rdmacm_id       *ids;
    struct evpl_rdmacm_listener *listener;
    struct evpl_rdmacm_device   *devices;
    int                          num_devices;
    struct evpl_rdmacm_sr       *free_sr;
    pthread_mutex_t              mutex;
    int                          new_id_eventfd;
    struct evpl_event            new_id_event;
    struct evpl_rdmacm_new_id   *new_ids;
};

#define evpl_event_rdmacm(eventp) \
        container_of((eventp), struct evpl_rdmacm, event)

#define evpl_event_rdmacm_device(eventp) \
        container_of((eventp), struct evpl_rdmacm_device, event)


struct evpl_rdmacm_id {
    struct evpl_rdmacm           *rdmacm;
    struct evpl_rdmacm_device    *dev;
    struct rdma_cm_id            *id;
    struct rdma_cm_id            *resolve_id;
    struct ibv_qp_ex             *qp;
    int                           stream;
    int                           ud;

    struct evpl_address          *resolve_addr;

    struct evpl_rdmacm_listen_id *listen_id;

    uint32_t                      qp_num;
    int                           devindex;
    int                           active_sends;
    struct UT_hash_handle         hh;
};

static inline struct evpl_rdmacm_sr *
evpl_rdmacm_sr_alloc(struct evpl_rdmacm *rdmacm)
{
    struct evpl_rdmacm_sr *sr;

    if (rdmacm->free_sr) {
        sr = rdmacm->free_sr;
        LL_DELETE(rdmacm->free_sr, sr);
    } else {
        sr = evpl_zalloc(sizeof(*sr));
    }

    return sr;
} /* evpl_rdmacm_sr_alloc */

static inline void
evpl_rdmacm_sr_free(
    struct evpl_rdmacm    *rdmacm,
    struct evpl_rdmacm_sr *sr)
{
    LL_PREPEND(rdmacm->free_sr, sr);
} /* evpl_rdmacm_sr_free */

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

    rdmacm_id->dev      = dev;
    rdmacm_id->devindex = dev->index;

    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.pd = dev->pd;

    if (rdmacm_id->ud) {
        qp_attr.qp_type = IBV_QPT_UD;
    } else {
        qp_attr.qp_type = IBV_QPT_RC;
    }

    qp_attr.send_cq          = dev->cq;
    qp_attr.recv_cq          = dev->cq;
    qp_attr.srq              = dev->srq;
    qp_attr.cap.max_send_wr  = rdmacm->config->rdmacm_sq_size;
    qp_attr.cap.max_recv_wr  = rdmacm->config->rdmacm_sq_size;
    qp_attr.cap.max_send_sge = rdmacm->config->max_num_iovec;
    qp_attr.cap.max_recv_sge = rdmacm->config->max_num_iovec;
    qp_attr.sq_sig_all       = 1;

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

    HASH_ADD(hh, rdmacm->ids, qp_num, sizeof(rdmacm_id->qp_num), rdmacm_id);

} /* evpl_rdmacm_create_qp */

static void
evpl_rdmacm_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm               *rdmacm = evpl_event_rdmacm(event);
    struct evpl_rdmacm_id            *rdmacm_id;
    struct evpl_bind                 *bind;
    struct evpl_rdmacm_listener      *listener;
    struct evpl_rdmacm_listen_id     *listen_id;
    struct evpl_rdmacm_listen_member *listen_member;
    struct evpl_rdmacm_ah            *ah;
    struct rdma_cm_event             *cm_event;
    struct rdma_conn_param            conn_param;
    struct evpl_notify                notify;
    int                               rc;
    struct evpl_rdmacm_new_id        *new_id;
    const uint64_t                    one = 1;

    if (rdma_get_cm_event(rdmacm->event_channel, &cm_event)) {
        evpl_event_mark_unreadable(event);
        return;
    }

    rdmacm_id = cm_event->id->context;

    switch (cm_event->event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED:

            rc = rdma_resolve_route(cm_event->id,
                                    rdmacm->config->resolve_timeout_ms);

            evpl_rdmacm_abort_if(rc, "rdma_resolve_route error %s", strerror(
                                     errno));
            break;
        case RDMA_CM_EVENT_ROUTE_RESOLVED:

            if (cm_event->id != rdmacm_id->resolve_id) {
                evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);
            }

            memset(&conn_param, 0, sizeof(conn_param));
            conn_param.private_data    = rdmacm_id;
            conn_param.retry_count     = rdmacm->config->rdmacm_retry_count;
            conn_param.rnr_retry_count = rdmacm->config->rdmacm_rnr_retry_count;

            rc = rdma_connect(cm_event->id, &conn_param);

            evpl_rdmacm_abort_if(rc, "rdma_connect error %s", strerror(errno));

            break;
        case RDMA_CM_EVENT_CONNECT_REQUEST:


            if (!rdmacm_id->ud) {

                listener = rdmacm->listener;

                listen_id = rdmacm_id->listen_id;

                new_id        = evpl_zalloc(sizeof(*new_id));
                new_id->event = cm_event;

                pthread_mutex_lock(&listener->mutex);
                listen_member = listen_id->members;
                DL_DELETE(listen_id->members, listen_member);
                DL_APPEND(listen_id->members, listen_member);

                pthread_mutex_lock(&listen_member->rdmacm->mutex);
                new_id->listen_member = listen_member;
                LL_PREPEND(listen_member->rdmacm->new_ids, new_id);
                pthread_mutex_unlock(&listen_member->rdmacm->mutex);

                write(listen_member->rdmacm->new_id_eventfd, &one, sizeof(one));

                pthread_mutex_unlock(&listener->mutex);

                cm_event = NULL;

            } else {
                /* XXX why is this necessary? */
                cm_event->id->qp = (struct ibv_qp *) rdmacm_id->qp;

                rc = rdma_accept(cm_event->id, &conn_param);

                evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));
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

                evpl_address_release(evpl, rdmacm_id->resolve_addr);
                rdmacm_id->resolve_addr = NULL;

            } else {

                notify.notify_type   = EVPL_NOTIFY_CONNECTED;
                notify.notify_status = 0;
                bind->notify_callback(evpl, bind, &notify, bind->private_data);
            }

            evpl_defer(evpl, &bind->flush_deferral);
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

            evpl_defer(evpl, &bind->close_deferral);
            break;
        case RDMA_CM_EVENT_REJECTED:

            bind = evpl_private2bind(rdmacm_id);

            evpl_defer(evpl, &bind->close_deferral);

            break;
        default:
            evpl_rdmacm_debug("unhandled rdmacm event %u", cm_event->event);
    } /* switch */

    if (cm_event) {
        rdma_ack_cm_event(cm_event);
    }

} /* evpl_rdmacm_event_callback */

void
evpl_rdmacm_fill_srq(
    struct evpl               *evpl,
    struct evpl_rdmacm        *rdmacm,
    struct evpl_rdmacm_device *dev)
{
    struct evpl_rdmacm_request *req;
    struct ibv_mr             **mrset, *mr;
    struct ibv_recv_wr          wr, *bad_wr;
    int                         rc;
    int                         size;

    if (rdmacm->config->rdmacm_datagram_size_override) {
        size = rdmacm->config->rdmacm_datagram_size_override;
    } else {
        size = rdmacm->config->max_datagram_size;
    }

    while (dev->srq_free_reqs) {

        req = dev->srq_free_reqs;
        LL_DELETE(dev->srq_free_reqs, req);

        req->used = 1;

        evpl_iovec_alloc_datagram(evpl, &req->iovec, size);

        mrset = evpl_buffer_framework_private(req->iovec.buffer,
                                              EVPL_FRAMEWORK_RDMACM);

        mr = mrset[dev->index];

        req->sge.addr   = (uint64_t) req->iovec.data;
        req->sge.length = req->iovec.length;
        req->sge.lkey   = mr->lkey;

        wr.wr_id = (uint64_t) req;
        wr.next  = NULL;

        wr.sg_list = &req->sge;
        wr.num_sge = 1;

        rc = ibv_post_srq_recv(dev->srq, &wr, &bad_wr);

        evpl_rdmacm_abort_if(rc, "ibv_post_srq_recv error %s", strerror(rc));

        ++dev->srq_fill;
    }
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
        evpl_rdmacm_fill_srq(evpl, rdmacm, dev);
    }
} /* evpl_rdmacm_fill_all_srq */


static void
evpl_rdmacm_poll_cq(
    struct evpl               *evpl,
    struct evpl_rdmacm_device *dev)
{
    struct evpl_rdmacm         *rdmacm = dev->rdmacm;
    struct evpl_rdmacm_id      *rdmacm_id;
    struct evpl_rdmacm_request *req;
    struct evpl_rdmacm_sr      *sr;
    struct evpl_bind           *bind;
    struct evpl_notify          notify;
    struct ibv_cq_ex           *cq      = (struct ibv_cq_ex *) dev->cq;
    struct ibv_poll_cq_attr     cq_attr = { .comp_mask = 0 };
    int                         rc, i, n;
    uint32_t                    qp_num, wc_flags;

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
                    evpl_rdmacm_abort(
                        "receive completion error wr_id %lu type %u status %u vendor_err %u",
                        cq->wr_id,
                        ibv_wc_read_opcode(cq),
                        cq->status,
                        ibv_wc_read_vendor_err(cq));
                    break;
                case IBV_WC_SEND:
                    evpl_rdmacm_abort(
                        "send completion error wr_id %lu type %u status %u vendor_err %u",
                        cq->wr_id,
                        ibv_wc_read_opcode(cq),
                        cq->status,
                        ibv_wc_read_vendor_err(cq));
                    break;
                case IBV_WC_RDMA_WRITE:
                    evpl_rdmacm_error("rdma write completion error wr_id %lu type %u status %u vendor_err %u",
                                      cq->wr_id,
                                      ibv_wc_read_opcode(cq),
                                      cq->status,
                                      ibv_wc_read_vendor_err(cq));
                    sr = (struct evpl_rdmacm_sr *) cq->wr_id;
                    sr->callback(EIO, sr->private_data);
                    evpl_rdmacm_sr_free(rdmacm, sr);
                    break;
                case IBV_WC_RDMA_READ:
                    evpl_rdmacm_error("rdma read completion error wr_id %lu type %u status %u vendor_err %u",
                                      cq->wr_id,
                                      ibv_wc_read_opcode(cq),
                                      cq->status,
                                      ibv_wc_read_vendor_err(cq));
                    sr = (struct evpl_rdmacm_sr *) cq->wr_id;
                    sr->callback(EIO, sr->private_data);
                    evpl_rdmacm_sr_free(rdmacm, sr);
                    break;
                default:
                    abort();
            } /* switch */
        }

        switch (ibv_wc_read_opcode(cq)) {
            case IBV_WC_RECV:

                req               = (struct evpl_rdmacm_request *) cq->wr_id;
                req->iovec.length = ibv_wc_read_byte_len(cq);

                qp_num = ibv_wc_read_qp_num(cq);



                HASH_FIND(hh, rdmacm->ids, &qp_num, sizeof(qp_num), rdmacm_id);

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

                    evpl_iovec_release(&req->iovec);

                }

                --dev->srq_fill;
                req->used = 0;
                LL_PREPEND(dev->srq_free_reqs, req);

                break;
            case IBV_WC_SEND:

                sr = (struct evpl_rdmacm_sr *) cq->wr_id;

                for (i = 0; i < sr->nbufref; ++i) {
                    evpl_buffer_release(sr->bufref[i]);
                }

                rdmacm_id = sr->rdmacm_id;

                bind = evpl_private2bind(rdmacm_id);

                --rdmacm_id->active_sends;

                if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
                    notify.notify_type   = EVPL_NOTIFY_SENT;
                    notify.notify_status = 0;
                    notify.sent.bytes    = sr->length;
                    notify.sent.msgs     = 1;

                    bind->notify_callback(evpl, bind, &notify,
                                          bind->private_data);
                }

                if (rdmacm_id->active_sends == 0 &&
                    evpl_iovec_ring_is_empty(&bind->iovec_send)) {
                    if (bind->flags & EVPL_BIND_FINISH) {
                        evpl_defer(evpl, &bind->close_deferral);
                    }
                }

                evpl_rdmacm_sr_free(rdmacm, sr);

                break;
            case IBV_WC_RDMA_READ:
                sr = (struct evpl_rdmacm_sr *) cq->wr_id;
                sr->callback(0, sr->private_data);
                evpl_rdmacm_sr_free(rdmacm, sr);
                break;
            case IBV_WC_RDMA_WRITE:
                sr = (struct evpl_rdmacm_sr *) cq->wr_id;
                sr->callback(0, sr->private_data);
                evpl_rdmacm_sr_free(rdmacm, sr);
                break;
            default:
                evpl_rdmacm_error("Unhandled RDMA completion opcode %u",
                                  ibv_wc_read_opcode(cq));
        } /* switch */


    } while (n < 16 && ibv_next_poll(cq) == 0);

    ibv_end_poll(cq);

    evpl_rdmacm_fill_srq(evpl, rdmacm, dev);

    if (n) {
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
        evpl_event_mark_unreadable(event);
        return;
    }

    rc = ibv_req_notify_cq(dev->cq, 0);

    evpl_rdmacm_abort_if(rc, "ibv_req_notify_cq error %s", strerror(errno));

    evpl_rdmacm_poll_cq(evpl, dev);

    ibv_ack_cq_events(dev->cq, 1);
} /* evpl_rdmacm_comp_callback */


static void
evpl_rdmacm_listener_wake(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_rdmacm_listener  *listener = arg;
    struct evpl_rdmacm           *rdmacm;
    struct evpl_rdmacm_id        *rdmacm_id;
    struct evpl_rdmacm_listen_id *listen_id, *tmp;
    int                           rc;

    evpl_attach_framework(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    pthread_mutex_lock(&listener->mutex);

    HASH_ITER(hh, listener->listen_ids, listen_id, tmp)
    {

        if (listen_id->rdmacm_id) {
            continue;
        }

        rdmacm_id = evpl_zalloc(sizeof(*rdmacm_id));

        listen_id->rdmacm_id = rdmacm_id;

        rdmacm_id->listen_id = listen_id;

        rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id,
                            RDMA_PS_TCP);

        evpl_rdmacm_abort_if(rc, "rdma_create_id listen error %s", strerror(rc));

        rc = rdma_bind_addr(rdmacm_id->id, (struct sockaddr *) &listen_id->addr);

        evpl_rdmacm_abort_if(rc, "Failed to bind to address: %s", strerror(errno));

        rdma_listen(rdmacm_id->id, 64);

    }

    pthread_mutex_unlock(&listener->mutex);
} /* evpl_rdmacm_listener_wake */

void *
evpl_rdmacm_init()
{
    struct evpl_rdmacm_devices *devices;
    int                         i;


    devices = evpl_zalloc(sizeof(*devices));

    devices->context = rdma_get_devices(&devices->num_devices);

    devices->pd = evpl_zalloc(sizeof(struct ibv_pd *) * devices->num_devices);

    for (i = 0; i < devices->num_devices; ++i) {
        devices->pd[i] = ibv_alloc_pd(devices->context[i]);

        evpl_rdmacm_abort_if(!devices->pd[i],
                             "Failed to create parent protection domain for rdma device");
    }

    pthread_mutex_init(&devices->listener.mutex, NULL);
    devices->listener.started = 0;

    return devices;
} /* evpl_rdmacm_init */

void
evpl_rdmacm_cleanup(void *private_data)
{
    struct evpl_rdmacm_devices *devices = private_data;
    int                         i;

    if (devices->listener.started) {
        evpl_thread_destroy(devices->listener.thread);
    }

    for (i = 0; i < devices->num_devices; ++i) {
        ibv_dealloc_pd(devices->pd[i]);
    }

    rdma_free_devices(devices->context);
    evpl_free(devices->pd);
    evpl_free(devices);

} /* evpl_rdmacm_cleanup */

static void
evpl_rdmacm_new_id_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm               *rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);
    struct evpl_rdmacm_listen_member *listen_member;
    struct evpl_rdmacm_new_id        *new_id;
    struct evpl_address              *remote_addr;
    struct evpl_rdmacm_id            *new_rdmacm_id;
    struct rdma_cm_event             *cm_event;
    struct evpl_bind                 *listen_bind, *bind;
    uint64_t                          value;
    int                               rc;
    struct rdma_conn_param            conn_param;

    rc = read(event->fd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(event);
        return;
    }

    pthread_mutex_lock(&rdmacm->mutex);

    while (rdmacm->new_ids) {

        new_id = rdmacm->new_ids;
        LL_DELETE(rdmacm->new_ids, new_id);

        listen_member = new_id->listen_member;

        listen_bind = listen_member->bind;

        cm_event = new_id->event;

        memset(&conn_param, 0, sizeof(conn_param));

        remote_addr = evpl_address_init(evpl,
                                        &cm_event->id->route.addr.
                                        src_addr,
                                        sizeof(cm_event->id->route.addr.
                                               src_addr));

        bind = evpl_bind_prepare(evpl,
                                 listen_bind->protocol,
                                 listen_bind->local,
                                 remote_addr);

        --remote_addr->refcnt;

        new_rdmacm_id = evpl_bind_private(bind);

        new_rdmacm_id->rdmacm      = rdmacm;
        new_rdmacm_id->stream      = listen_bind->protocol->stream;
        new_rdmacm_id->id          = cm_event->id;
        new_rdmacm_id->id->context = new_rdmacm_id;

        evpl_rdmacm_create_qp(evpl, rdmacm, new_rdmacm_id);

        conn_param.private_data        = rdmacm;
        conn_param.retry_count         = rdmacm->config->rdmacm_retry_count;
        conn_param.rnr_retry_count     = rdmacm->config->rdmacm_rnr_retry_count;
        conn_param.responder_resources = cm_event->param.conn.initiator_depth;
        conn_param.initiator_depth     = cm_event->param.conn.initiator_depth;

        listen_bind->accept_callback(
            evpl,
            listen_bind,
            bind,
            &bind->notify_callback,
            &bind->segment_callback,
            &bind->private_data,
            listen_bind->private_data);


        rc = rdma_migrate_id(cm_event->id, rdmacm->event_channel);

        evpl_rdmacm_abort_if(rc, "rdma_migrate_id error %s", strerror(errno));

        rc = rdma_accept(cm_event->id, &conn_param);

        evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));

        evpl_free(new_id);

        rdma_ack_cm_event(cm_event);

    } /* evpl_rdmacm_new_id_callback */

    pthread_mutex_unlock(&rdmacm->mutex);


} /* evpl_rdmacm_new_id_callback */

static void
evpl_rdmacm_poll(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_rdmacm        *rdmacm = arg;
    struct evpl_rdmacm_device *dev;
    int                        i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];
        evpl_rdmacm_poll_cq(evpl, dev);
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

    rdmacm->config   = evpl_config(evpl);
    rdmacm->listener = &rdmacm_devices->listener;

    rdmacm->num_devices = rdmacm_devices->num_devices;

    rdmacm->devices = evpl_zalloc(
        sizeof(struct evpl_rdmacm_device) * rdmacm->num_devices);

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        dev->rdmacm = rdmacm;

        dev->context = rdmacm_devices->context[i];
        dev->index   = i;

        dev->parent_pd = rdmacm_devices->pd[i];

        dev->comp_channel = ibv_create_comp_channel(dev->context);

        evpl_rdmacm_abort_if(!dev->comp_channel,
                             "Failed to create completion chnanel for rdma device");

        flags = fcntl(dev->comp_channel->fd, F_GETFL, 0);

        evpl_rdmacm_abort_if(flags == -1, "fcntl(F_GETFL) failed");

        flags |= O_NONBLOCK;

        rc = fcntl(dev->comp_channel->fd, F_SETFL, flags);

        evpl_rdmacm_abort_if(rc == -1, "fcntl(F_SETFL, O_NONBLOCK) failed");

        dev->event.fd            = dev->comp_channel->fd;
        dev->event.read_callback = evpl_rdmacm_comp_callback;

        evpl_add_event(evpl, &dev->event);
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

        cq_attr.cqe           = rdmacm->config->rdmacm_cq_size;
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

        ibv_req_notify_cq(dev->cq, 0);

        memset(&srq_init_attr, 0, sizeof(srq_init_attr));

        srq_init_attr.attr.max_wr  = rdmacm->config->rdmacm_srq_size;
        srq_init_attr.attr.max_sge = 1;

        dev->srq = ibv_create_srq(dev->pd, &srq_init_attr);

        dev->srq_max = rdmacm->config->rdmacm_srq_size;
        dev->srq_min = rdmacm->config->rdmacm_srq_min;

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

    rdmacm->event.fd            = rdmacm->event_channel->fd;
    rdmacm->event.read_callback = evpl_rdmacm_event_callback;

    evpl_add_event(evpl, &rdmacm->event);
    evpl_event_read_interest(evpl, &rdmacm->event);

    pthread_mutex_init(&rdmacm->mutex, NULL);

    rdmacm->new_id_eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_rdmacm_abort_if(rdmacm->new_id_eventfd < 0, "Failed to create eventfd for new id");

    rdmacm->new_id_event.fd            = rdmacm->new_id_eventfd;
    rdmacm->new_id_event.read_callback = evpl_rdmacm_new_id_callback;

    evpl_add_event(evpl, &rdmacm->new_id_event);
    evpl_event_read_interest(evpl, &rdmacm->new_id_event);

    rdmacm->poll = evpl_add_poll(evpl, evpl_rdmacm_poll, rdmacm);

    if (rdmacm->config->rdmacm_srq_prefill) {
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
    struct evpl_rdmacm_sr      *sr;
    int                         i, j;

    evpl_remove_poll(evpl, rdmacm->poll);

    evpl_remove_event(evpl, &rdmacm->new_id_event);
    close(rdmacm->new_id_eventfd);

    evpl_remove_event(evpl, &rdmacm->event);

    rdma_destroy_event_channel(rdmacm->event_channel);

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        evpl_remove_event(evpl, &dev->event);

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

    while (rdmacm->free_sr) {
        sr = rdmacm->free_sr;
        LL_DELETE(rdmacm->free_sr, sr);
        evpl_free(sr);
    }

    evpl_free(rdmacm->devices);
    evpl_free(rdmacm);
} /* evpl_rdmacm_destroy */

void
evpl_rdmacm_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm               *rdmacm;
    struct evpl_rdmacm_listener      *listener;
    struct evpl_rdmacm_listen_id     *listen_id;
    struct evpl_rdmacm_listen_member *listen_member;
    struct evpl_rdmacm_id            *rdmacm_id = evpl_bind_private(bind);

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    listener = rdmacm->listener;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    listen_member         = evpl_zalloc(sizeof(*listen_member));
    listen_member->rdmacm = rdmacm;
    listen_member->bind   = bind;

    rdmacm_id->stream     = bind->protocol->stream;
    rdmacm_id->ud         = 0;
    rdmacm_id->resolve_id = NULL;

    pthread_mutex_lock(&listener->mutex);

    if (!listener->started) {
        listener->started = 1;
        listener->thread  = evpl_thread_create(NULL,
                                               evpl_rdmacm_listener_wake,
                                               NULL,
                                               NULL,
                                               1000,
                                               listener);
    }

    HASH_FIND(hh, listener->listen_ids, bind->local->addr, bind->local->addrlen, listen_id);

    if (!listen_id) {
        listen_id          = evpl_zalloc(sizeof(*listen_id));
        listen_id->addrlen = bind->local->addrlen;
        memcpy(&listen_id->addr, bind->local->addr, bind->local->addrlen);
        HASH_ADD(hh, listener->listen_ids, addr, listen_id->addrlen, listen_id);

        evpl_thread_wake(listener->thread);
    }

    DL_APPEND(listen_id->members, listen_member);

    pthread_mutex_unlock(&listener->mutex);

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
    rdmacm_id->resolve_id = NULL;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm_id->rdmacm = rdmacm;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id,
                        RDMA_PS_TCP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    rc = rdma_resolve_addr(rdmacm_id->id, NULL, bind->remote->addr,
                           rdmacm->config->resolve_timeout_ms);

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
        mrset = evpl_zalloc(sizeof(struct ibv_mr *) * rdmacm_devices->num_devices);
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
evpl_rdmacm_ud_resolve(
    struct evpl           *evpl,
    struct evpl_rdmacm_id *rdmacm_id,
    struct evpl_address   *address)
{
    int rc;

    rdmacm_id->resolve_addr = address;

    address->refcnt++;

    rc = rdma_resolve_addr(rdmacm_id->resolve_id, NULL, address->addr,
                           rdmacm_id->rdmacm->config->resolve_timeout_ms);

    evpl_rdmacm_abort_if(rc, "Failed to resolve rdmacm address");

} /* evpl_rdmacm_ud_resolve */

void
evpl_rdmacm_flush_datagram(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm    *rdmacm    = rdmacm_id->rdmacm;
    struct evpl_rdmacm_sr *sr;
    struct evpl_iovec     *cur;
    struct evpl_dgram     *dgram;
    struct ibv_qp_ex      *qp = rdmacm_id->qp;
    struct ibv_mr         *mr, **mrset;
    struct ibv_sge        *sge;
    struct evpl_rdmacm_ah *ah;
    int                    nsge, rc;
    uint64_t               len = 0;

    if (!qp) {
        return;
    }

    while (!evpl_dgram_ring_is_empty(&bind->dgram_send)) {

        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

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

        sr = evpl_rdmacm_sr_alloc(rdmacm);

        sr->rdmacm_id = rdmacm_id;

        nsge = 0;

        sge = alloca(sizeof(struct ibv_sge) * dgram->niov);


        len = 0;
        while (nsge < dgram->niov) {

            cur = evpl_iovec_ring_tail(&bind->iovec_send);

            mrset = evpl_buffer_framework_private(cur->buffer,
                                                  EVPL_FRAMEWORK_RDMACM);

            mr = mrset[rdmacm_id->devindex];

            sge[nsge].addr   = (uint64_t) cur->data;
            sge[nsge].length = cur->length;
            sge[nsge].lkey   = mr->lkey;

            sr->bufref[nsge] = cur->buffer;

            len += cur->length;

            nsge++;

            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        sr->nbufref = nsge;
        sr->length  = len;

        ibv_wr_start(qp);

        qp->wr_id    = (uint64_t) sr;
        qp->wr_flags = 0;

        ibv_wr_send(qp);

        ibv_wr_set_sge_list(qp, nsge, sge);

        if (rdmacm_id->ud) {
            ah = evpl_address_private(dgram->addr, bind->protocol->id);

            ibv_wr_set_ud_addr(qp, ah->ahset[rdmacm_id->devindex],
                               ah->qp_num, ah->qkey);

            evpl_address_release(evpl, dgram->addr);
        }

        rc = ibv_wr_complete(qp);

        evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(
                                 errno));

        evpl_dgram_ring_remove(&bind->dgram_send);


        ++rdmacm_id->active_sends;
    }

    if (rdmacm_id->active_sends == 0 &&
        evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_defer(evpl, &bind->close_deferral);
        }
    }

} /* evpl_rdmacm_datagram */

void
evpl_rdmacm_flush_stream(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm    *rdmacm    = rdmacm_id->rdmacm;
    struct evpl_config    *config    = rdmacm->config;
    struct evpl_rdmacm_sr *sr;
    struct evpl_iovec     *cur;
    struct ibv_qp_ex      *qp = rdmacm_id->qp;
    struct ibv_mr         *mr, **mrset;
    struct ibv_sge        *sge;
    int                    nsge, rc;

    if (!qp) {
        return;
    }

    sge = alloca(sizeof(struct ibv_sge) * config->max_num_iovec);

    while (!evpl_iovec_ring_is_empty(&bind->iovec_send)) {

        sr = evpl_rdmacm_sr_alloc(rdmacm);

        sr->rdmacm_id = rdmacm_id;

        nsge = 0;

        sr->length = 0;

        while (nsge < config->max_num_iovec &&
               !evpl_iovec_ring_is_empty(&bind->iovec_send)) {

            cur = evpl_iovec_ring_tail(&bind->iovec_send);

            if (sr->length + cur->length > config->max_datagram_size) {
                break;
            }

            mrset = evpl_buffer_framework_private(cur->buffer,
                                                  EVPL_FRAMEWORK_RDMACM);

            mr = mrset[rdmacm_id->devindex];

            sge[nsge].addr   = (uint64_t) cur->data;
            sge[nsge].length = cur->length;
            sge[nsge].lkey   = mr->lkey;

            sr->bufref[nsge] = cur->buffer;

            nsge++;
            sr->length += cur->length;

            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        sr->nbufref = nsge;

        ibv_wr_start(qp);

        qp->wr_id    = (uint64_t) sr;
        qp->wr_flags = 0;
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
            evpl_defer(evpl, &bind->close_deferral);
        }
    }

} /* evpl_rdmacm_flush_strean */

void
evpl_rdmacm_bind(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    int                    rc;

    rdmacm_id->stream = 0;
    rdmacm_id->ud     = 1;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm_id->rdmacm = rdmacm;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id,
                        RDMA_PS_UDP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->resolve_id,
                        rdmacm_id,
                        RDMA_PS_UDP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));


    rc = rdma_bind_addr(rdmacm_id->id, bind->local->addr);

    evpl_rdmacm_abort_if(rc, "rdma_bind_addr error %s", strerror(errno));

    evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);

    rc = rdma_listen(rdmacm_id->id, 64);

    evpl_rdmacm_abort_if(rc, "Failed to listen on rdmacm id");

} /* evpl_rdmacm_bind */

void
evpl_rdmacm_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm    *rdmacm    = rdmacm_id->rdmacm;

    if (rdmacm_id->qp) {
        HASH_DELETE(hh, rdmacm->ids, rdmacm_id);
    }

    if (rdmacm_id->id) {
        rdma_destroy_id(rdmacm_id->id);
    }

    if (rdmacm_id->resolve_id) {
        rdma_destroy_id(rdmacm_id->resolve_id);
    }

    if (rdmacm_id->resolve_addr) {
        evpl_address_release(evpl, rdmacm_id->resolve_addr);
    }

    evpl_bind_destroy(evpl, bind);

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

void
evpl_rdmacm_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm    *rdmacm    = rdmacm_id->rdmacm;
    struct ibv_qp_ex      *qp        = rdmacm_id->qp;
    struct ibv_mr        **mrset, *mr;
    struct evpl_iovec     *cur;
    struct evpl_rdmacm_sr *sr;
    struct ibv_sge        *sge;
    int                    len = 0, i, rc;

    sr = evpl_rdmacm_sr_alloc(rdmacm);

    sr->callback     = callback;
    sr->private_data = private_data;

    sge = alloca(sizeof(struct ibv_sge) * niov);

    for (i = 0; i < niov; ++i) {

        cur = &iov[i];

        mrset = evpl_buffer_framework_private(cur->buffer,
                                              EVPL_FRAMEWORK_RDMACM);

        mr = mrset[rdmacm_id->devindex];

        sge[i].addr   = (uint64_t) cur->data;
        sge[i].length = cur->length;
        sge[i].lkey   = mr->lkey;

        len += cur->length;
    }

    sr->length = len;

    ibv_wr_start(qp);

    qp->wr_id    = (uint64_t) sr;
    qp->wr_flags = 0;

    ibv_wr_rdma_read(qp, remote_key, remote_address);

    ibv_wr_set_sge_list(qp, niov, sge);

    rc = ibv_wr_complete(qp);

    evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(errno));

} /* evpl_rdmacm_rdma_read */

void
evpl_rdmacm_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_bind_private(bind);
    struct evpl_rdmacm    *rdmacm    = rdmacm_id->rdmacm;
    struct ibv_qp_ex      *qp        = rdmacm_id->qp;
    struct ibv_mr        **mrset, *mr;
    struct evpl_iovec     *cur;
    struct evpl_rdmacm_sr *sr;
    struct ibv_sge        *sge;
    int                    len = 0, i, rc;

    sr = evpl_rdmacm_sr_alloc(rdmacm);

    sr->callback     = callback;
    sr->private_data = private_data;

    sge = alloca(sizeof(struct ibv_sge) * niov);

    for (i = 0; i < niov; ++i) {

        cur = &iov[i];

        mrset = evpl_buffer_framework_private(cur->buffer,
                                              EVPL_FRAMEWORK_RDMACM);

        mr = mrset[rdmacm_id->devindex];

        sge[i].addr   = (uint64_t) cur->data;
        sge[i].length = cur->length;
        sge[i].lkey   = mr->lkey;

        len += cur->length;
    }

    sr->length = len;

    ibv_wr_start(qp);

    qp->wr_id    = (uint64_t) sr;
    qp->wr_flags = 0;

    ibv_wr_rdma_write(qp, remote_key, remote_address);

    ibv_wr_set_sge_list(qp, niov, sge);

    rc = ibv_wr_complete(qp);

    evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(errno));
} /* evpl_rdmacm_rdma_write */


struct evpl_framework evpl_framework_rdmacm = {
    .id                = EVPL_FRAMEWORK_RDMACM,
    .name              = "RDMACM",
    .init              = evpl_rdmacm_init,
    .cleanup           = evpl_rdmacm_cleanup,
    .create            = evpl_rdmacm_create,
    .destroy           = evpl_rdmacm_destroy,
    .register_memory   = evpl_rdmacm_register,
    .unregister_memory = evpl_rdmacm_unregister,
    .release_address   = evpl_rdmacm_release_address,
};

struct evpl_protocol  evpl_rdmacm_rc_datagram = {
    .id         = EVPL_DATAGRAM_RDMACM_RC,
    .connected  = 1,
    .stream     = 0,
    .name       = "DATAGRAM_RDMACM_RC",
    .framework  = &evpl_framework_rdmacm,
    .listen     = evpl_rdmacm_listen,
    .connect    = evpl_rdmacm_connect,
    .close      = evpl_rdmacm_close,
    .flush      = evpl_rdmacm_flush_datagram,
    .rdma_read  = evpl_rdmacm_rdma_read,
    .rdma_write = evpl_rdmacm_rdma_write,
};

struct evpl_protocol  evpl_rdmacm_rc_stream = {
    .id         = EVPL_STREAM_RDMACM_RC,
    .connected  = 1,
    .stream     = 1,
    .name       = "STREAM_RDMACM_RC",
    .framework  = &evpl_framework_rdmacm,
    .listen     = evpl_rdmacm_listen,
    .connect    = evpl_rdmacm_connect,
    .close      = evpl_rdmacm_close,
    .flush      = evpl_rdmacm_flush_stream,
    .rdma_read  = evpl_rdmacm_rdma_read,
    .rdma_write = evpl_rdmacm_rdma_write,
};

struct evpl_protocol  evpl_rdmacm_ud_datagram = {
    .id        = EVPL_DATAGRAM_RDMACM_UD,
    .connected = 0,
    .stream    = 0,
    .name      = "DATAGRAM_RDMACM_UD",
    .framework = &evpl_framework_rdmacm,
    .bind      = evpl_rdmacm_bind,
    .close     = evpl_rdmacm_close,
    .flush     = evpl_rdmacm_flush_datagram,
};
