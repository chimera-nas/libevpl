#include <fcntl.h>
#include <stdlib.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "uthash.h"
#include "utlist.h"

#include "core/protocol.h"
#include "core/internal.h"
#include "core/conn.h"
#include "core/endpoint.h"

#define evpl_rdmacm_debug(...) evpl_debug("rdmacm", __VA_ARGS__)
#define evpl_rdmacm_info(...)  evpl_info("rdmacm", __VA_ARGS__)
#define evpl_rdmacm_error(...) evpl_error("rdmacm", __VA_ARGS__)
#define evpl_rdmacm_fatal(...) evpl_fatal("rdmacm", __VA_ARGS__)
#define evpl_rdmacm_abort(...) evpl_abort("rdmacm", __VA_ARGS__)

#define evpl_rdmacm_fatal_if(cond, ...) \
    evpl_fatal_if(cond, "rdmacm", __VA_ARGS__)

#define evpl_rdmacm_abort_if(cond, ...) \
    evpl_abort_if(cond, "rdmacm", __VA_ARGS__)

struct ibv_context **context = NULL;

struct evpl_rdmacm_request {
    struct evpl_bvec            bvec;
    struct ibv_sge              sge;
    int                         used;
    struct evpl_rdmacm_request *next;
};

struct evpl_rdmacm_sr {
    struct evpl_buffer *bufref[8];
    int                 nbufref;
};

struct evpl_rdmacm_devices {
    struct ibv_context    **context;
    struct ibv_pd         **pd;
    int                     num_devices;
};

struct evpl_rdmacm_device {
    struct evpl_event   event;
    struct evpl_rdmacm *rdmacm;
    struct ibv_context *context;
    struct ibv_comp_channel *comp_channel;
    struct ibv_td      *td;
    struct ibv_pd      *parent_pd;
    struct ibv_pd      *pd;
    struct ibv_cq      *cq;
    struct ibv_srq     *srq;
    struct evpl_rdmacm_request *srq_reqs;
    struct evpl_rdmacm_request *srq_free_reqs; 
    int                 srq_max;
    int                 srq_min;
    int                 srq_fill;
    int                 index;
};

struct evpl_rdmacm {
    struct rdma_event_channel *event_channel;
    struct evpl_event          event;
    struct evpl_rdmacm_id     *ids;
    struct evpl_rdmacm_device *devices;
    int                        num_devices;
};

#define evpl_event_rdmacm(eventp) \
    container_of((eventp), struct evpl_rdmacm, event)

#define evpl_event_rdmacm_device(eventp) \
    container_of((eventp), struct evpl_rdmacm_device, event)


struct evpl_rdmacm_id {
    struct evpl_rdmacm     *rdmacm;
    struct rdma_cm_id      *id;
    struct ibv_qp_ex       *qp;
    uint32_t                qp_num;
    int                     devindex;
    struct UT_hash_handle   hh;
};

static struct evpl_rdmacm_device *
evpl_rdmacm_map_device(
    struct evpl_rdmacm *rdmacm,
    struct ibv_context *context)
{
    struct evpl_rdmacm_device *dev;
    int i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        if (dev->context == context) {
            return dev;
        }
    }

    evpl_rdmacm_abort("Unable to map RDMA device context");

    return NULL;
}

static void
evpl_rdmacm_create_qp(
    struct evpl *evpl,
    struct evpl_rdmacm *rdmacm,
    struct evpl_rdmacm_id *rdmacm_id)
{
    struct evpl_rdmacm_device *dev;
    struct ibv_qp_init_attr_ex qp_attr;
    int rc;

    dev = evpl_rdmacm_map_device(rdmacm, rdmacm_id->id->verbs);

    rdmacm_id->devindex = dev->index;

    memset(&qp_attr, 0, sizeof(qp_attr));

    qp_attr.pd = dev->pd;
    qp_attr.qp_type = IBV_QPT_RC;
    qp_attr.send_cq = dev->cq;
    qp_attr.recv_cq = dev->cq;
    qp_attr.srq = dev->srq;
    qp_attr.cap.max_send_wr = 10;
    qp_attr.cap.max_recv_wr = 10;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;
    qp_attr.sq_sig_all       = 1;

    qp_attr.send_ops_flags = IBV_QP_EX_WITH_SEND;
    qp_attr.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD|IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;

    rc = rdma_create_qp_ex(rdmacm_id->id, &qp_attr);

    evpl_rdmacm_abort_if(rc, "rdma_create_qp error %s", strerror(errno));

    rdmacm_id->qp = ibv_qp_to_qp_ex(rdmacm_id->id->qp);
    rdmacm_id->qp_num = rdmacm_id->id->qp->qp_num;

    HASH_ADD(hh, rdmacm->ids, qp_num, sizeof(rdmacm_id->qp_num), rdmacm_id);

}

static void
evpl_rdmacm_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm *rdmacm = evpl_event_rdmacm(event);
    struct evpl_rdmacm_id *rdmacm_id, *new_rdmacm_id;
    struct evpl_endpoint *endpoint;
    struct evpl_conn *conn;
    struct evpl_listener *listener;
    struct rdma_cm_event *cm_event;
    struct rdma_conn_param conn_param;
    struct sockaddr_in         *dst_addr, *src_addr;
    int rc;

    if (rdma_get_cm_event(rdmacm->event_channel, &cm_event)) {
        evpl_event_mark_unreadable(event);        
        return;
    }

    rdmacm_id = cm_event->id->context;

    switch (cm_event->event) {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        evpl_rdmacm_debug("address resolved");
        rc = rdma_resolve_route(cm_event->id, 5000);
        evpl_rdmacm_abort_if(rc, "rdma_resolve_route error %s", strerror(errno));
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        evpl_rdmacm_debug("route resolved");

        evpl_rdmacm_create_qp(evpl, rdmacm, rdmacm_id);

        memset(&conn_param, 0, sizeof(conn_param));
        conn_param.private_data = rdmacm_id;
        conn_param.retry_count = 1;
        conn_param.rnr_retry_count = 1;

        rc = rdma_connect(cm_event->id, &conn_param);
        evpl_rdmacm_abort_if(rc, "rdma_connect error %s", strerror(errno));

        break;
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        evpl_rdmacm_debug("received connect request");

        listener = evpl_private2listener(rdmacm_id);

        src_addr = (struct sockaddr_in *)&cm_event->id->route.addr.src_addr;
        dst_addr = (struct sockaddr_in *)&cm_event->id->route.addr.dst_addr;

        evpl_rdmacm_debug("Accepted new rdma connection from %s to %s",
            inet_ntoa(dst_addr->sin_addr),
            inet_ntoa(src_addr->sin_addr));

        endpoint = evpl_endpoint_create(evpl, 
            inet_ntoa(src_addr->sin_addr), src_addr->sin_port);

        conn = evpl_alloc_conn(evpl, endpoint);

        conn->protocol = listener->protocol;

        new_rdmacm_id = evpl_conn_private(conn);

        new_rdmacm_id->rdmacm = rdmacm;
        new_rdmacm_id->id = cm_event->id;
        new_rdmacm_id->id->context = new_rdmacm_id;
 
        evpl_endpoint_close(evpl, endpoint); /* drop our reference */

        evpl_rdmacm_create_qp(evpl, rdmacm, new_rdmacm_id);

        memset(&conn_param, 0, sizeof(conn_param));
        conn_param.private_data = rdmacm;
        conn_param.retry_count = 1;
        conn_param.rnr_retry_count = 1;
        conn_param.responder_resources = 1;
        conn_param.initiator_depth = 16;

        rc = rdma_accept(cm_event->id, &conn_param);

        evpl_rdmacm_abort_if(rc, "rdma_accept error %s", strerror(errno));

        evpl_accept(evpl, listener, conn);

        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        evpl_rdmacm_debug("established");

        conn = evpl_private2conn(rdmacm_id);

        evpl_defer(evpl, &conn->flush_deferral);
        break;
    case RDMA_CM_EVENT_CONNECT_RESPONSE:
        evpl_rdmacm_debug("connected");
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        evpl_rdmacm_debug("disconnected");

        conn = evpl_private2conn(rdmacm_id);

        evpl_defer(evpl, &conn->close_deferral);
        break;
    case RDMA_CM_EVENT_REJECTED:
        evpl_rdmacm_debug("rejected");

        conn = evpl_private2conn(rdmacm_id);

        evpl_defer(evpl, &conn->close_deferral);

        break;
    default:
        evpl_rdmacm_debug("unhandled rdmacm event %u", cm_event->event);
    }

    rdma_ack_cm_event(cm_event);

}

void
evpl_rdmacm_fill_srq(
    struct evpl *evpl,
    struct evpl_rdmacm_device *dev)
{
    struct evpl_rdmacm_request  *req;
    struct ibv_mr **mrset, *mr;
    struct ibv_recv_wr wr, *bad_wr;
    int rc;

    while (dev->srq_free_reqs) {

        req = dev->srq_free_reqs;
        LL_DELETE(dev->srq_free_reqs, req);

        req->used = 1;

        evpl_bvec_alloc(evpl, 2*1024*1024, 4096, 1, &req->bvec);

        mrset = evpl_buffer_private(req->bvec.buffer, EVPL_FRAMEWORK_RDMACM);

        mr = mrset[dev->index];

        req->sge.addr = (uint64_t)req->bvec.data;
        req->sge.length = req->bvec.length;
        req->sge.lkey = mr->lkey;

        wr.wr_id = (uint64_t)req;
        wr.next  = NULL;

        wr.sg_list = &req->sge;
        wr.num_sge = 1;

        rc = ibv_post_srq_recv(dev->srq, &wr, &bad_wr);

        evpl_rdmacm_abort_if(rc,"ibv_post_srq_recv error %s", strerror(rc));
 
        ++dev->srq_fill;
    }
        
}

void
evpl_rdmacm_fill_all_srq(
    struct evpl *evpl,
    struct evpl_rdmacm *rdmacm)
{
    struct evpl_rdmacm_device *dev;
    int i;

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        if (dev->srq_fill < dev->srq_min) {
            evpl_rdmacm_fill_srq(evpl, dev);
        }
    }
}


static void
evpl_rdmacm_poll_cq(
    struct evpl *evpl,
    struct evpl_rdmacm_device *dev)
{
    struct evpl_rdmacm *rdmacm = dev->rdmacm;;
    struct evpl_rdmacm_id *rdmacm_id;
    struct evpl_rdmacm_request *req;
    struct evpl_rdmacm_sr *sr;
    struct evpl_conn *conn;
    struct ibv_cq_ex *cq = (struct ibv_cq_ex *)dev->cq;
    struct ibv_poll_cq_attr  cq_attr = { .comp_mask = 0 };
    int rc, i, n = 0;
    uint32_t qp_num;

    evpl_rdmacm_debug("poll_cq");

    rc = ibv_start_poll(cq, &cq_attr);

    if (rc) return;

    do {

        n++;

        evpl_rdmacm_debug("got cqe n %d", n);

        if (unlikely(cq->status)) {
            evpl_rdmacm_error("evpl_rdmacm_poll_cq wr_id %lu type %u status %u vendor_err %u",
                cq->wr_id,
                ibv_wc_read_opcode(cq),
                cq->status,
                ibv_wc_read_vendor_err(cq));
        }

        switch (ibv_wc_read_opcode(cq)) {
        case IBV_WC_RECV:
            qp_num = ibv_wc_read_qp_num(cq);

            HASH_FIND(hh, rdmacm->ids, &qp_num, sizeof(qp_num), rdmacm_id);

            evpl_rdmacm_abort_if(!rdmacm_id,"Failed to map receive qp_num to rdmacm_id");

            conn = evpl_private2conn(rdmacm_id);

            req = (struct evpl_rdmacm_request *)cq->wr_id;

            evpl_rdmacm_debug("req %p", req);
            evpl_bvec_ring_add(&conn->recv_ring, &req->bvec, 1);

            evpl_rdmacm_debug("recv completion qp_num %u rdmacm_id %p conn %p req %p bytelen %u",
                qp_num, rdmacm_id, conn, req,  ibv_wc_read_byte_len(cq));

            conn->callback(evpl, conn, EVPL_EVENT_RECEIVED, 0, conn->private_data);

            --dev->srq_fill;
            req->used = 0;
            LL_PREPEND(dev->srq_free_reqs, req);

            break;
        case IBV_WC_SEND:
            evpl_rdmacm_debug("send completion");
            sr = (struct evpl_rdmacm_sr *)cq->wr_id; 

            for (i = 0; i < sr->nbufref; ++i) {
                evpl_buffer_release(evpl, sr->bufref[i]);
            }

            break;
        default:
            evpl_rdmacm_error("Unhandled RDMA completion opcode %u", ibv_wc_read_opcode(cq));
        }



    } while (ibv_next_poll(cq) == 0);

    ibv_end_poll(cq);

    if (dev->srq_fill < dev->srq_min) {
        evpl_rdmacm_fill_srq(evpl, dev);
    }
}


static void
evpl_rdmacm_comp_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_rdmacm_device *dev = evpl_event_rdmacm_device(event);
    struct ibv_cq *ev_cq;
    void *ev_ctx;
    int rc;

    rc = ibv_get_cq_event(dev->comp_channel, &ev_cq, &ev_ctx);

    if (rc) {
        evpl_event_mark_unreadable(event);
        return;
    }

    evpl_rdmacm_debug("completion callback");

    rc = ibv_req_notify_cq(dev->cq, 0);

    evpl_rdmacm_abort_if(rc, "ibv_req_notify_cq error %s", strerror(errno));

    evpl_rdmacm_poll_cq(evpl, dev); 

    ibv_ack_cq_events(dev->cq, 1);
}


void *
evpl_rdmacm_init()
{
    struct evpl_rdmacm_devices *devices;
    int i;

    devices = evpl_zalloc(sizeof(*devices));

    devices->context = rdma_get_devices(&devices->num_devices);

    evpl_rdmacm_debug("found %d rdmacm devices", devices->num_devices);

    devices->pd = evpl_zalloc(sizeof(struct ibv_pd *) * devices->num_devices);

    for (i = 0; i < devices->num_devices; ++i) {
        devices->pd[i] = ibv_alloc_pd(devices->context[i]);

        evpl_rdmacm_abort_if(!devices->pd[i], "Failed to create parent protection domain for rdma device");
    }

    return devices;
}

void

evpl_rdmacm_cleanup(void *private_data)
{
    struct evpl_rdmacm_devices *devices = private_data;
    int i;

    for (i = 0; i < devices->num_devices; ++i) {
        ibv_dealloc_pd(devices->pd[i]);
    }

    rdma_free_devices(devices->context);
    evpl_free(devices->pd);
    evpl_free(devices);

}

void *
evpl_rdmacm_create(
    struct evpl *evpl,
    void *private_data)
{
    struct evpl_rdmacm_devices *rdmacm_devices = private_data;
    struct evpl_rdmacm_device *dev;
    struct evpl_rdmacm *rdmacm;
    struct ibv_srq_init_attr srq_init_attr;
    struct ibv_cq_init_attr_ex cq_attr;
    struct ibv_td_init_attr td_attr;
    struct ibv_parent_domain_init_attr pd_attr;
    int flags, rc, i;

    rdmacm = evpl_zalloc(sizeof(*rdmacm));
   
    rdmacm->num_devices = rdmacm_devices->num_devices;

    rdmacm->devices = evpl_zalloc(
        sizeof(struct evpl_rdmacm_device) * rdmacm->num_devices);

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];

        dev->rdmacm = rdmacm;

        dev->context = rdmacm_devices->context[i];
        dev->index = i;

        dev->parent_pd = rdmacm_devices->pd[i];

        dev->comp_channel = ibv_create_comp_channel(dev->context);

        evpl_rdmacm_abort_if(!dev->comp_channel,
                      "Failed to create completion chnanel for rdma device");

        flags = fcntl(dev->comp_channel->fd, F_GETFL, 0);

        evpl_rdmacm_abort_if(flags == -1,"fcntl(F_GETFL) failed");

        flags |= O_NONBLOCK;

        rc = fcntl(dev->comp_channel->fd, F_SETFL, flags);

        evpl_rdmacm_abort_if(rc == -1, "fcntl(F_SETFL, O_NONBLOCK) failed");

        dev->event.fd = dev->comp_channel->fd;
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

        evpl_rdmacm_abort_if(!dev->pd, "Failed to create protection domain for rdma device");

        memset(&cq_attr, 0, sizeof(cq_attr));

        cq_attr.cqe = 255;
        cq_attr.cq_context = dev;
        cq_attr.channel = dev->comp_channel;
        cq_attr.comp_vector = 0;
        cq_attr.parent_domain = dev->pd;
        cq_attr.wc_flags = IBV_WC_EX_WITH_BYTE_LEN | IBV_WC_EX_WITH_QP_NUM;
        cq_attr.flags = IBV_CREATE_CQ_ATTR_SINGLE_THREADED; 
        cq_attr.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS |
                            IBV_CQ_INIT_ATTR_MASK_PD;

        dev->cq = (struct ibv_cq *)ibv_create_cq_ex(dev->context, &cq_attr);

        evpl_rdmacm_abort_if(!dev->cq, "Failed to create completion queue for rdma device");

        ibv_req_notify_cq(dev->cq, 0);

        memset(&srq_init_attr, 0, sizeof(srq_init_attr));

        srq_init_attr.attr.max_wr = 256;
        srq_init_attr.attr.max_sge = 8;

        dev->srq = ibv_create_srq(dev->pd, &srq_init_attr);

        dev->srq_max = 16;
        dev->srq_min = 8;

        dev->srq_reqs = evpl_zalloc(sizeof(struct evpl_rdmacm_request) * dev->srq_max);

        for (i = 0; i < dev->srq_max; ++i) {
            LL_PREPEND(dev->srq_free_reqs, &dev->srq_reqs[i]);
        }
    }

    evpl_rdmacm_debug("creating rdma event channel");
    rdmacm->event_channel = rdma_create_event_channel();

    flags = fcntl(rdmacm->event_channel->fd, F_GETFL, 0);

    evpl_rdmacm_abort_if(flags == -1,"fcntl(F_GETFL) failed");

    flags |= O_NONBLOCK;

    rc = fcntl(rdmacm->event_channel->fd, F_SETFL, flags);

    evpl_rdmacm_abort_if(rc == -1, "fcntl(F_SETFL, O_NONBLOCK) failed");

    rdmacm->event.fd             = rdmacm->event_channel->fd;
    rdmacm->event.read_callback  = evpl_rdmacm_event_callback;

    evpl_add_event(evpl, &rdmacm->event);
    evpl_event_read_interest(evpl, &rdmacm->event);

    evpl_rdmacm_debug("returning rdmacm private %p", rdmacm);
    return rdmacm;
}

void
evpl_rdmacm_destroy(
    struct evpl *evpl,
    void *private_data)
{
    struct evpl_rdmacm *rdmacm = private_data;
    struct evpl_rdmacm_device *dev;
    struct evpl_rdmacm_request *req;
    int i;

    evpl_rdmacm_debug("destroying rdma event channel");
    rdma_destroy_event_channel(rdmacm->event_channel);

    for (i = 0; i < rdmacm->num_devices; ++i) {
        dev = &rdmacm->devices[i];
        ibv_destroy_srq(dev->srq);

        for (i = 0; i < dev->srq_max; ++i) {
            req = &dev->srq_reqs[i];

            if (req->used) {
                evpl_bvec_release(evpl, &req->bvec);
            }
        }

        evpl_free(dev->srq_reqs);
        ibv_destroy_cq(dev->cq);
        ibv_dealloc_pd(dev->pd);
        ibv_destroy_comp_channel(dev->comp_channel);
        ibv_dealloc_td(dev->td);
    }

    evpl_free(rdmacm->devices);
    evpl_free(rdmacm);
}

void
evpl_rdmacm_listen(
    struct evpl        *evpl,
    struct evpl_listener *listener)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_listener_private(listener);
    struct addrinfo *p;
    int rc;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rdmacm_id = evpl_listener_private(listener);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    evpl_rdmacm_debug("rdma_create_id rc %d", rc);

    for (p = listener->endpoint->ai; p != NULL; p = p->ai_next) {

        if (rdma_bind_addr(rdmacm_id->id, p->ai_addr) == -1) {
            continue;
        }

        break;
    }

    if (p == NULL) {
        evpl_rdmacm_debug("Failed to bind to any addr");
        return;
    }

    rdma_listen(rdmacm_id->id, 64);

}

void
evpl_rdmacm_connect(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_conn_private(conn);
    int rc;

    rdmacm = evpl_framework_private(evpl, EVPL_FRAMEWORK_RDMACM);

    rdmacm_id->rdmacm = rdmacm;

    evpl_rdmacm_fill_all_srq(evpl, rdmacm);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    evpl_rdmacm_abort_if(rc, "rdma_create_id error %s", strerror(errno));

    rc = rdma_resolve_addr(rdmacm_id->id, NULL, conn->endpoint->ai->ai_addr, 5000);

    evpl_rdmacm_abort_if(rc, "rdma_resolve_addr error %s", strerror(errno));
}

void *
evpl_rdmacm_register(
    void *buffer,
    int size,
    void *private_data)
{
    struct evpl_rdmacm_devices *rdmacm_devices = private_data;
    struct ibv_mr **mrset;
    int i;

    mrset = evpl_zalloc(sizeof(struct ibv_mr) * rdmacm_devices->num_devices);

    for (i = 0; i < rdmacm_devices->num_devices; ++i) {

        mrset[i] = ibv_reg_mr(rdmacm_devices->pd[i], buffer, size,
            IBV_ACCESS_LOCAL_WRITE |
            IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE |
            IBV_ACCESS_RELAXED_ORDERING);


        evpl_rdmacm_debug("registered buffer %p to mr %p", buffer, mrset[i]);

    }
    return mrset;
}

void 
evpl_rdmacm_unregister(
    void *buffer_private,
    void *private_data)
{
    struct evpl_rdmacm_devices *rdmacm_devices = private_data;
    struct ibv_mr **mrset = buffer_private;
    int i;

    for (i = 0; i < rdmacm_devices->num_devices; ++i) {
        evpl_rdmacm_debug("Dereg mr %p", mrset[i]);

        ibv_dereg_mr(mrset[i]);
    }

    evpl_free(mrset);

}

void
evpl_rdmacm_flush(
    struct evpl *evpl,
    struct evpl_conn *conn)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_conn_private(conn);
    struct evpl_rdmacm_sr *sr;
    struct evpl_bvec *cur;
    struct ibv_qp_ex *qp = rdmacm_id->qp;
    struct ibv_mr *mr, **mrset;
    struct ibv_sge sge[8];
    int nsge = 0, eom, rc;

    if (!qp) return;

    evpl_rdmacm_debug("rdma flush called");

    while (!evpl_bvec_ring_is_empty(&conn->send_ring)) {

        sr = evpl_zalloc(sizeof(*sr));

        while (!evpl_bvec_ring_is_empty(&conn->send_ring)) {

            cur = evpl_bvec_ring_tail(&conn->send_ring);

            mrset = evpl_buffer_private(cur->buffer, EVPL_FRAMEWORK_RDMACM);

            mr = mrset[rdmacm_id->devindex];

            sge[nsge].addr = (uint64_t)cur->data;
            sge[nsge].length = cur->length;
            sge[nsge].lkey = mr->lkey;

            sr->bufref[nsge] = cur->buffer;

            nsge++;
       
            eom = cur->eom; 

            evpl_bvec_ring_remove(&conn->send_ring);

            if (eom) break;
        }

        sr->nbufref = nsge;

        ibv_wr_start(qp);

        qp->wr_id    = (uint64_t)sr;
        qp->wr_flags = 0;
        ibv_wr_send(qp);
        ibv_wr_set_sge_list(qp, nsge, sge);

        rc = ibv_wr_complete(qp);

        evpl_rdmacm_abort_if(rc, "ibv_wr_complete error error %s", strerror(errno));
    }
   
    evpl_rdmacm_debug("after rdmacm send ring empty %d finish %d",
        evpl_bvec_ring_is_empty(&conn->send_ring),
        !!(conn->flags & EVPL_CONN_FINISH));
 
    if (evpl_bvec_ring_is_empty(&conn->send_ring)) {
        if (conn->flags & EVPL_CONN_FINISH) {
            evpl_rdmacm_debug("arming close deferral");
            evpl_defer(evpl, &conn->close_deferral);
        }
    }

}

void
evpl_rdmacm_close_conn(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_rdmacm_id *rdmacm_id = evpl_conn_private(conn);
    struct evpl_rdmacm *rdmacm = rdmacm_id->rdmacm;

    evpl_rdmacm_debug("rdmacm close conn rdmacm_id %p", rdmacm_id);

    HASH_DELETE(hh, rdmacm->ids, rdmacm_id);

    rdma_destroy_id(rdmacm_id->id);

}

void
evpl_rdmacm_close_listen(
    struct evpl        *evpl,
    struct evpl_listener *listener)
{
    struct evpl_rdmacm_id *rdmacm_id  = evpl_listener_private(listener);

    rdma_destroy_id(rdmacm_id->id);
}

struct evpl_framework evpl_rdmacm = {
    .id = EVPL_FRAMEWORK_RDMACM,
    .name = "RDMACM",
    .init = evpl_rdmacm_init,
    .cleanup = evpl_rdmacm_cleanup,
    .create = evpl_rdmacm_create,
    .destroy = evpl_rdmacm_destroy,
    .register_buffer = evpl_rdmacm_register,
    .unregister_buffer = evpl_rdmacm_unregister,
};

struct evpl_conn_protocol evpl_rdmacm_rc = {
    .id = EVPL_CONN_RDMACM_RC,
    .name = "RDMACM_RC",
    .listen = evpl_rdmacm_listen,
    .connect = evpl_rdmacm_connect,
    .close_conn = evpl_rdmacm_close_conn,
    .close_listen = evpl_rdmacm_close_listen,
    .flush = evpl_rdmacm_flush,
};
