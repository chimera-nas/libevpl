// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Real tcp-provider transfers with controlled CQ delivery.  Delay/reorder
 * successful completions, and optionally replace a non-final RMA completion
 * with an error.  Provider operations and data movement remain real. */
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include "core/test_log.h"
#include "core/bind.h"
#include "evpl/evpl.h"
#include "evpl/evpl_libfabric.h"
#include "test_common.h"

#define OPERATIONS  3
#define CHUNKS      3
#define CHUNK_SIZE  65536
#define LENGTH      (CHUNKS * CHUNK_SIZE)
#define COMPLETIONS (OPERATIONS * CHUNKS)

struct cq_hook {
    struct fid_cq    *cq;
    struct fi_ops_cq  ops;
    struct fi_ops_cq *real;
};

static struct fi_info                                *info;
static struct fid_fabric                             *fabric;
static struct fid_domain                             *domain;
static struct fi_ops_domain                           domain_ops, *real_domain_ops;
static struct fid_ep                                 *client_ep;
static struct fi_ops_msg                              msg_ops, *real_msg_ops;
static struct fi_ops_rma                              rma_ops, *real_rma_ops;
static struct cq_hook                                 cq_hooks[8];
static unsigned int                                   num_cqs;
static pthread_t                                      test_thread;
static struct fid_cq                                 *tx_cq;
static struct fi_cq_msg_entry                         completions[COMPLETIONS];
static void                                          *contexts[COMPLETIONS];
static unsigned int                                   posted, captured, returned, delivered[OPERATIONS], callbacks;
static unsigned int                                   connected, received, stage;
static int                                            reorder, inject_error, retry_injected, error_pending;
static const unsigned int                             order[COMPLETIONS] = { 8, 7, 6, 5, 4, 3, 1, 0, 2 };
static struct evpl_bind                              *client_bind, *server_bind;
static struct evpl_iovec buffers[OPERATIONS][CHUNKS], remote_buffer;
static uint32_t                                       remote_key;
static uint64_t                                       remote_address;
static unsigned int                                   operation_ids[OPERATIONS] = { 0, 1, 2 };

static unsigned int
next_completion(void)
{
    /* Keep the error case ordered to isolate lost non-final errors from
     * the independent out-of-order lifetime regression. */
    return reorder && !inject_error ? order[returned] : returned;
} /* next_completion */

static ssize_t
tracked_read(
    struct fid_cq *cq,
    void          *buf,
    size_t         count)
{
    struct cq_hook        *hook = NULL;
    struct fi_cq_msg_entry entry;
    unsigned int           i, index;
    ssize_t                rc;

    for (i = 0; i < num_cqs; i++) {
        if (cq_hooks[i].cq == cq) {
            hook = &cq_hooks[i];
            break;
        }
    }
    evpl_test_abort_if(!hook, "invalid CQ read");
    if (!count) {
        return hook->real->read(cq, buf, count);
    }
    if (cq == tx_cq && error_pending) {
        return -FI_EAVAIL;
    }
    if (cq != tx_cq || captured < (reorder ? COMPLETIONS : posted)) {
        rc = hook->real->read(cq, &entry, 1);
        if (rc > 0) {
            if (!(entry.flags & (FI_SEND | FI_READ | FI_WRITE))) {
                memcpy(buf, &entry, sizeof(entry));
                return 1;
            }
            evpl_test_abort_if(tx_cq && tx_cq != cq, "unexpected transmit CQ");
            tx_cq = cq;
            for (index = 0; index < posted; index++) {
                if (contexts[index] == entry.op_context) {
                    break;
                }
            }
            evpl_test_abort_if(index == posted, "completion has unknown context");
            completions[index] = entry;
            contexts[index]    = NULL;
            captured++;
        } else if (rc != -FI_EAGAIN) {
            return rc;
        }
    }
    if (cq != tx_cq || returned == captured ||
        (reorder && captured < COMPLETIONS)) {
        return -FI_EAGAIN;
    }
    index = next_completion();
    if (inject_error && stage && index == 0) {
        error_pending = 1;
        return -FI_EAVAIL;
    }
    memcpy(buf, &completions[index], sizeof(entry));
    delivered[index / CHUNKS]++;
    returned++;
    return 1;
} /* tracked_read */

static ssize_t
tracked_readerr(
    struct fid_cq          *cq,
    struct fi_cq_err_entry *error,
    uint64_t                flags)
{
    unsigned int i;

    if (cq == tx_cq && error_pending) {
        memset(error, 0, sizeof(*error));
        error->op_context = completions[0].op_context;
        error->flags      = completions[0].flags;
        error->err        = FI_EIO;
        error_pending     = 0;
        delivered[0]++;
        returned++;
        return 1;
    }
    for (i = 0; i < num_cqs; i++) {
        if (cq_hooks[i].cq == cq) {
            return cq_hooks[i].real->readerr(cq, error, flags);
        }
    }
    evpl_test_abort("unknown error CQ");
    return -FI_EINVAL;
} /* tracked_readerr */

static int
tracked_cq_open(
    struct fid_domain *dom,
    struct fi_cq_attr *attr,
    struct fid_cq    **cq,
    void              *context)
{
    struct cq_hook *hook;
    int             rc = real_domain_ops->cq_open(dom, attr, cq, context);

    if (rc || !pthread_equal(pthread_self(), test_thread)) {
        return rc;
    }
    evpl_test_abort_if(num_cqs == 8, "too many CQs");
    hook              = &cq_hooks[num_cqs++];
    hook->cq          = *cq;
    hook->real        = (*cq)->ops;
    hook->ops         = *hook->real;
    hook->ops.read    = tracked_read;
    hook->ops.readerr = tracked_readerr;
    (*cq)->ops        = &hook->ops;
    return 0;
} /* tracked_cq_open */

static int
retry_post(void)
{
    if (posted == 1 && !retry_injected) {
        retry_injected = 1;
        return 1;
    }
    return 0;
} /* retry_post */

static void
record_post(
    void   *context,
    ssize_t rc)
{
    if (!rc) {
        evpl_test_abort_if(posted == COMPLETIONS, "too many chunks");
        contexts[posted++] = context;
    }
} /* record_post */

static ssize_t
tracked_sendmsg(
    struct fid_ep       *ep,
    const struct fi_msg *msg,
    uint64_t             flags)
{
    ssize_t rc;

    if (retry_post()) {
        return -FI_EAGAIN;
    }
    rc = real_msg_ops->sendmsg(ep, msg, flags);
    record_post(msg->context, rc);
    return rc;
} /* tracked_sendmsg */

static ssize_t
tracked_readmsg(
    struct fid_ep           *ep,
    const struct fi_msg_rma *msg,
    uint64_t                 flags)
{
    ssize_t rc;

    if (retry_post()) {
        return -FI_EAGAIN;
    }
    rc = real_rma_ops->readmsg(ep, msg, flags);
    record_post(msg->context, rc);
    return rc;
} /* tracked_readmsg */

static ssize_t
tracked_writemsg(
    struct fid_ep           *ep,
    const struct fi_msg_rma *msg,
    uint64_t                 flags)
{
    ssize_t rc;

    if (retry_post()) {
        return -FI_EAGAIN;
    }
    rc = real_rma_ops->writemsg(ep, msg, flags);
    record_post(msg->context, rc);
    return rc;
} /* tracked_writemsg */

static int
tracked_endpoint(
    struct fid_domain *dom,
    struct fi_info    *ep_info,
    struct fid_ep    **ep,
    void              *context)
{
    int rc = real_domain_ops->endpoint(dom, ep_info, ep, context);

    /* The initiating endpoint is created before the accepted endpoint. */
    if (!rc && !client_ep) {
        client_ep        = *ep;
        real_msg_ops     = (*ep)->msg;
        msg_ops          = *real_msg_ops;
        msg_ops.sendmsg  = tracked_sendmsg;
        (*ep)->msg       = &msg_ops;
        real_rma_ops     = (*ep)->rma;
        rma_ops          = *real_rma_ops;
        rma_ops.readmsg  = tracked_readmsg;
        rma_ops.writemsg = tracked_writemsg;
        (*ep)->rma       = &rma_ops;
    }
    return rc;
} /* tracked_endpoint */

static void
check_callback(
    unsigned int id,
    int          status)
{
    unsigned int i;
    int          expected = inject_error && stage && id == 0 ? EIO : 0;

    evpl_test_abort_if(id != callbacks, "callback retired the wrong operation");
    for (i = 0; i <= id; i++) {
        evpl_test_abort_if(delivered[i] != CHUNKS,
                           "operation %u retired with only %u/%u chunks completed",
                           i, delivered[i], CHUNKS);
    }
    evpl_test_abort_if(status != expected, "operation %u status %d, expected %d",
                       id, status, expected);
    callbacks++;
} /* check_callback */

static void
rdma_complete(
    int   status,
    void *private_data)
{
    check_callback(*(unsigned int *) private_data, status);
} /* rdma_complete */

static void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    if (notify->notify_type == EVPL_NOTIFY_CONNECTED) {
        connected++;
    } else if (notify->notify_type == EVPL_NOTIFY_SENT) {
        evpl_test_abort_if(notify->sent.bytes != LENGTH || notify->sent.msgs != 1,
                           "incorrect sent notification");
        check_callback(callbacks, notify->notify_status);
    }
} /* client_callback */

static void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    unsigned char data[8192];
    int           n, i;

    if (notify->notify_type == EVPL_NOTIFY_CONNECTED) {
        connected++;
        evpl_rdma_get_address(evpl, bind, &remote_buffer, &remote_key, &remote_address);
    } else if (notify->notify_type == EVPL_NOTIFY_RECV_DATA) {
        while ((n = evpl_recv(evpl, bind, data, sizeof(data), 0)) > 0) {
            for (i = 0; i < n; i++) {
                evpl_test_abort_if(data[i] != (unsigned char) (0x40 + received / LENGTH),
                                   "stream payload mismatch at %u", received);
                received++;
            }
        }
    }
} /* server_callback */

static void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    server_bind      = bind;
    *notify_callback = server_callback;
} /* accept_callback */

static void
queue_operation(
    struct evpl *evpl,
    unsigned int id)
{
    if (!stage) {
        evpl_sendv(evpl, client_bind, buffers[id], CHUNKS, LENGTH, 0);
    } else if (stage == 1) {
        evpl_rdma_write(evpl, client_bind, remote_key, remote_address + id * LENGTH,
                        buffers[id], CHUNKS, 0, rdma_complete, &operation_ids[id]);
    } else {
        evpl_rdma_read(evpl, client_bind, remote_key, remote_address + id * LENGTH,
                       buffers[id], CHUNKS, rdma_complete, &operation_ids[id]);
    }
} /* queue_operation */

static void
close_external(void)
{
    evpl_test_abort_if(fi_close(&domain->fid), "external domain still has children");
    evpl_test_abort_if(fi_close(&fabric->fid), "external fabric close failed");
    fi_freeinfo(info);
} /* close_external */

int
main(void)
{
    struct evpl_global_config    *config;
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;
    struct fi_info               *hints;
    const char                   *mode = getenv("EVPL_TEST_TX_MODE");
    unsigned int                  i, j, k;
    int                           old_size, rc, match;

    alarm(30);
    test_thread                 = pthread_self();
    reorder                     = mode && strcmp(mode, "window");
    inject_error                = mode && !strcmp(mode, "error");
    hints                       = fi_allocinfo();
    hints->ep_attr->type        = FI_EP_MSG;
    hints->caps                 = FI_MSG | FI_RMA;
    hints->addr_format          = FI_SOCKADDR_IN;
    hints->mode                 = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
        FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->fabric_attr->prov_name = strdup("tcp");
    rc                            = fi_getinfo(FI_VERSION(1, 17), "127.0.0.1", NULL, FI_SOURCE, hints, &info);
    evpl_test_abort_if(rc, "fi_getinfo: %s", fi_strerror(-rc));
    fi_freeinfo(hints);
    evpl_test_abort_if(fi_fabric(info->fabric_attr, &fabric, NULL), "fi_fabric failed");
    evpl_test_abort_if(fi_domain(fabric, info, &domain, NULL), "fi_domain failed");
    /* Exercise segmentation even on providers accepting many iovecs. */
    info->tx_attr->iov_limit = 1;
    real_domain_ops          = domain->ops;
    domain_ops               = *real_domain_ops;
    domain_ops.cq_open       = tracked_cq_open;
    domain_ops.endpoint      = tracked_endpoint;
    domain->ops              = &domain_ops;
    atexit(close_external);

    config = evpl_global_config_init();
    test_evpl_set_core_mech(config);
    evpl_global_config_set_libfabric_provider(config, "tcp");
    evpl_global_config_set_libfabric_external_domain(config, fabric, domain, info);
    evpl_global_config_set_libfabric_tx_size(config, reorder ? 16 : 1);
    evpl_global_config_set_iovec_ring_size(config, 4);
    evpl_global_config_set_dgram_ring_size(config, 2);
    evpl_init(config);
    evpl = evpl_create(NULL);
    evpl_iovec_alloc(evpl, OPERATIONS * LENGTH, 1, 1, 0, &remote_buffer);
    memset(remote_buffer.data, 0, OPERATIONS * LENGTH);
    endpoint = evpl_endpoint_create("127.0.0.1", 8000);
    listener = evpl_listener_create();
    binding  = evpl_listener_attach(evpl, listener, accept_callback, NULL);
    evpl_test_abort_if(evpl_listen(listener, EVPL_STREAM_LIBFABRIC_MSG, endpoint),
                       "listen failed");
    client_bind = evpl_connect(evpl, EVPL_STREAM_LIBFABRIC_MSG, NULL,
                               endpoint, client_callback, NULL, NULL);
    evpl_bind_request_send_notifications(evpl, client_bind);
    while (connected != 2) {
        evpl_continue(evpl);
    }
    for (i = 0; i < OPERATIONS; i++) {
        for (j = 0; j < CHUNKS; j++) {
            evpl_iovec_alloc(evpl, CHUNK_SIZE, 1, 1, 0, &buffers[i][j]);
            memset(buffers[i][j].data, 0x40 + i, CHUNK_SIZE);
        }
    }
    for (stage = 0; stage < 3; stage++) {
        posted         = captured = returned = callbacks = 0;
        retry_injected = 0;
        memset(delivered, 0, sizeof(delivered));
        memset(contexts, 0, sizeof(contexts));
        old_size = stage == 2 ? client_bind->dgram_read.size : client_bind->dgram_send.size;
        queue_operation(evpl, 0);
        if (reorder) {
            while (captured < CHUNKS) {
                evpl_continue(evpl);
            }
        }
        for (i = 1; i < OPERATIONS; i++) {
            queue_operation(evpl, i);
        }
        if (reorder && stage != 1) {
            evpl_test_abort_if((stage == 2 ? client_bind->dgram_read.size :
                                client_bind->dgram_send.size) <= old_size,
                               "dgram ring did not grow with work in flight");
        }
        while (callbacks != OPERATIONS || (!stage && received != OPERATIONS * LENGTH)) {
            evpl_continue(evpl);
        }
        evpl_test_abort_if(posted != COMPLETIONS || returned != COMPLETIONS || !retry_injected,
                           "segmentation/retry path was not exercised");
        /* Local write completion need not imply remote visibility.  Drive
         * the receiving endpoint until the target bytes are present. */
        if (stage == 1) {
            do {
                match = 1;
                for (i = 0; i < OPERATIONS * LENGTH; i++) {
                    if (((unsigned char *) remote_buffer.data)[i] != 0x40 + i / LENGTH) {
                        match = 0;
                        break;
                    }
                }
                if (!match) {
                    evpl_continue(evpl);
                }
            } while (!match);
        }
        if (stage) {
            for (i = 0; i < OPERATIONS; i++) {
                for (j = 0; j < CHUNKS; j++) {
                    for (k = 0; k < CHUNK_SIZE; k++) {
                        unsigned char *data = stage == 1 ?
                            (unsigned char *) remote_buffer.data + i * LENGTH + j * CHUNK_SIZE :
                            buffers[i][j].data;
                        evpl_test_abort_if(data[k] != 0x40 + i, "RMA payload mismatch");
                    }
                }
            }
        }
        if (stage == 1) {
            for (i = 0; i < OPERATIONS; i++) {
                for (j = 0; j < CHUNKS; j++) {
                    memset(buffers[i][j].data, 0, CHUNK_SIZE);
                }
            }
        }
    }
    if (reorder) {
        /* Close with provider completions deliberately withheld.  Teardown
         * must release the remaining chunk and transfer bookkeeping. */
        stage  = 0;
        posted = captured = returned = callbacks = 0;
        memset(delivered, 0, sizeof(delivered));
        memset(contexts, 0, sizeof(contexts));
        received = 0;
        for (j = 0; j < CHUNKS; j++) {
            memset(buffers[0][j].data, 0x40, CHUNK_SIZE);
        }
        queue_operation(evpl, 0);
        while (captured < CHUNKS) {
            evpl_continue(evpl);
        }
    }
    evpl_close(evpl, client_bind);
    evpl_close(evpl, server_bind);
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    for (i = 0; i < OPERATIONS; i++) {
        evpl_iovecs_release(evpl, buffers[i], CHUNKS);
    }
    evpl_iovec_release(evpl, &remote_buffer);
    evpl_destroy(evpl);
    evpl_test_info("transmit completion regression passed (%s)", mode ? mode : "window");
    return 0;
} /* main */
