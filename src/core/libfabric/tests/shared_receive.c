// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Exercise a real tcp-provider SRX, observing provider calls through an
 * externally owned domain.  The observations distinguish actual buffer
 * sharing from a private-RQ implementation that passes the same exchanges. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include "core/test_log.h"
#include "evpl/evpl.h"
#include "evpl/evpl_libfabric.h"
#include "test_common.h"

#define PEERS   4
#define RQ_SIZE 8
#define ROUNDS  32

struct message {
    unsigned int peer;
    unsigned int sequence;
    unsigned int generation;
    unsigned int magic;
};

struct client {
    struct evpl_bind *bind;
    unsigned int      id;
    unsigned int      sequence;
};

struct server {
    unsigned int id;
    int          identified;
};

static struct client         clients[PEERS];
static struct server         servers[PEERS + 1];
static unsigned int          accepted, connected, disconnected, replies, generation;
static unsigned int          srx_attempts, srx_opens, srx_closes, receive_posts;
static int                   unsupported, disabled, inject_eagain, eagain_injected;
static struct fi_info       *external_info;
static struct fid_fabric    *external_fabric;
static struct fid_domain    *external_domain;
static struct fi_ops_domain  domain_ops;
static struct fi_ops_domain *real_domain_ops;
static struct fi_ops_msg     msg_ops;
static struct fi_ops_msg    *real_msg_ops;
static struct fi_ops         fid_ops;
static struct fi_ops        *real_fid_ops;

static ssize_t
tracked_recvmsg(
    struct fid_ep       *ep,
    const struct fi_msg *msg,
    uint64_t             flags)
{
    ssize_t rc;

    /* Fail the first refill, after initial preposting has succeeded. */
    if (inject_eagain && !eagain_injected && receive_posts >= RQ_SIZE) {
        eagain_injected = 1;
        return -FI_EAGAIN;
    }
    rc = real_msg_ops->recvmsg(ep, msg, flags);
    if (!rc) {
        receive_posts++;
    }
    return rc;
} /* tracked_recvmsg */

static int
tracked_close(struct fid *fid)
{
    int rc = real_fid_ops->close(fid);

    if (!rc) {
        srx_closes++;
    }
    return rc;
} /* tracked_close */

static int
tracked_srx(
    struct fid_domain *domain,
    struct fi_rx_attr *attr,
    struct fid_ep    **ep,
    void              *context)
{
    int rc;

    srx_attempts++;
    if (unsupported) {
        return -FI_ENOSYS;
    }
    rc = real_domain_ops->srx_ctx(domain, attr, ep, context);
    evpl_test_abort_if(rc, "tcp SRX unavailable: %s", fi_strerror(-rc));
    srx_opens++;
    real_msg_ops    = (*ep)->msg;
    msg_ops         = *real_msg_ops;
    msg_ops.recvmsg = tracked_recvmsg;
    (*ep)->msg      = &msg_ops;
    real_fid_ops    = (*ep)->fid.ops;
    fid_ops         = *real_fid_ops;
    fid_ops.close   = tracked_close;
    (*ep)->fid.ops  = &fid_ops;
    return 0;
} /* tracked_srx */

static void
close_external(void)
{
    int rc = fi_close(&external_domain->fid);

    evpl_test_abort_if(rc, "external domain still has children: %s", fi_strerror(-rc));
    rc = fi_close(&external_fabric->fid);
    evpl_test_abort_if(rc, "external fabric close: %s", fi_strerror(-rc));
    fi_freeinfo(external_info);
} /* close_external */

static void
read_message(
    struct evpl        *evpl,
    struct evpl_notify *notify,
    struct message     *msg)
{
    evpl_test_abort_if(notify->recv_msg.length != sizeof(*msg) ||
                       notify->recv_msg.niov != 1,
                       "invalid message size");
    memcpy(msg, notify->recv_msg.iovec[0].data, sizeof(*msg));
    evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
    evpl_test_abort_if(msg->magic != 0x53525131 || msg->generation != generation ||
                       msg->peer >= PEERS, "invalid message contents");
} /* read_message */

static void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client *client = private_data;
    struct message msg;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            connected++;
            break;
        case EVPL_NOTIFY_RECV_MSG:
            read_message(evpl, notify, &msg);
            evpl_test_abort_if(msg.peer != client->id || msg.sequence != client->sequence,
                               "reply delivered to the wrong connection or out of order");
            replies++;
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            client->bind = NULL;
            disconnected++;
            break;
    } /* switch */
} /* client_callback */

static void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct server *server = private_data;
    struct message msg;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            connected++;
            break;
        case EVPL_NOTIFY_RECV_MSG:
            read_message(evpl, notify, &msg);
            if (!server->identified) {
                server->id         = msg.peer;
                server->identified = 1;
            }
            evpl_test_abort_if(server->id != msg.peer,
                               "shared receive delivered to the wrong server connection");
            evpl_send(evpl, bind, &msg, sizeof(msg));
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            disconnected++;
            break;
    } /* switch */
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
    evpl_test_abort_if(accepted >= PEERS + 1, "unexpected connection");
    *notify_callback   = server_callback;
    *conn_private_data = &servers[accepted++];
} /* accept_callback */

static void
connect_client(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint,
    unsigned int          i)
{
    clients[i].id   = i;
    clients[i].bind = evpl_connect(evpl, EVPL_DATAGRAM_LIBFABRIC_MSG, NULL,
                                   endpoint, client_callback, NULL, &clients[i]);
} /* connect_client */

int
main(void)
{
    struct evpl_global_config    *config;
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;
    struct fi_info               *hints;
    struct message                msg;
    const char                   *mode = getenv("EVPL_TEST_SRQ_MODE");
    unsigned int                  i, round, initial_posts, expected_replies;
    int                           rc;

    alarm(30);
    unsupported                 = mode && !strcmp(mode, "unsupported");
    disabled                    = mode && !strcmp(mode, "disabled");
    inject_eagain               = mode && !strcmp(mode, "eagain");
    hints                       = fi_allocinfo();
    hints->ep_attr->type        = FI_EP_MSG;
    hints->caps                 = FI_MSG | FI_RMA;
    hints->addr_format          = FI_SOCKADDR_IN;
    hints->mode                 = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
        FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->fabric_attr->prov_name = strdup("tcp");
    rc                            = fi_getinfo(FI_VERSION(1, 17), "127.0.0.1", NULL, FI_SOURCE,
                                               hints, &external_info);
    evpl_test_abort_if(rc, "fi_getinfo: %s", fi_strerror(-rc));
    fi_freeinfo(hints);
    rc = fi_fabric(external_info->fabric_attr, &external_fabric, NULL);
    evpl_test_abort_if(rc, "fi_fabric: %s", fi_strerror(-rc));
    rc = fi_domain(external_fabric, external_info, &external_domain, NULL);
    evpl_test_abort_if(rc, "fi_domain: %s", fi_strerror(-rc));
    real_domain_ops      = external_domain->ops;
    domain_ops           = *real_domain_ops;
    domain_ops.srx_ctx   = tracked_srx;
    external_domain->ops = &domain_ops;
    atexit(close_external);

    config = evpl_global_config_init();
    test_evpl_set_core_mech(config);
    evpl_global_config_set_libfabric_provider(config, "tcp");
    evpl_global_config_set_libfabric_external_domain(config, external_fabric,
                                                     external_domain, external_info);
    evpl_global_config_set_libfabric_srq_enabled(config, !disabled);
    evpl_global_config_set_libfabric_rq_size(config, RQ_SIZE);
    evpl_global_config_set_libfabric_rq_batch(config, 4);
    evpl_init(config);
    evpl     = evpl_create(NULL);
    endpoint = evpl_endpoint_create("127.0.0.1", 8000);
    listener = evpl_listener_create();
    binding  = evpl_listener_attach(evpl, listener, accept_callback, NULL);
    evpl_test_abort_if(evpl_listen(listener, EVPL_DATAGRAM_LIBFABRIC_MSG, endpoint),
                       "listen failed");

    /* Two waves prove that the last close releases the pool, and later
     * connections on the same thread can create and use a fresh pool. */
    for (generation = 0; generation < 2; generation++) {
        accepted = connected = disconnected = replies = 0;
        memset(servers, 0, sizeof(servers));
        initial_posts = receive_posts;
        for (i = 0; i < PEERS; i++) {
            connect_client(evpl, endpoint, i);
        }
        while (connected < 2 * PEERS) {
            evpl_continue(evpl);
        }
        if (!unsupported && !disabled) {
            evpl_test_abort_if(srx_opens != generation + 1 ||
                               receive_posts - initial_posts != RQ_SIZE,
                               "expected one pool of %u buffers for %u endpoints, got %u posts",
                               RQ_SIZE, 2 * PEERS, receive_posts - initial_posts);
        }

        for (round = 0; round < ROUNDS; round++) {
            expected_replies = replies + PEERS;
            for (i = 0; i < PEERS; i++) {
                clients[i].sequence = round;
                msg                 = (struct message) { i, round, generation, 0x53525131 };
                evpl_send(evpl, clients[i].bind, &msg, sizeof(msg));
            }
            while (replies < expected_replies) {
                evpl_continue(evpl);
            }
            if (round == ROUNDS / 2) {
                evpl_close(evpl, clients[0].bind);
                while (disconnected < 2) {
                    evpl_continue(evpl);
                }
                evpl_test_abort_if(srx_closes != generation && !unsupported && !disabled,
                                   "closing one connection destroyed the shared pool");
                connect_client(evpl, endpoint, 0);
                while (connected < 2 * (PEERS + 1)) {
                    evpl_continue(evpl);
                }
                evpl_test_abort_if(srx_opens != generation + 1 && !unsupported && !disabled,
                                   "replacement connection allocated a new receive pool");
            }
        }
        for (i = 0; i < PEERS; i++) {
            evpl_close(evpl, clients[i].bind);
        }
        while (disconnected < 2 * (PEERS + 1)) {
            evpl_continue(evpl);
        }
        evpl_test_abort_if(srx_closes != generation + 1 && !unsupported && !disabled,
                           "last endpoint close did not release the shared pool");
    }
    evpl_test_abort_if(disabled && srx_attempts, "disabled SRQ was attempted");
    evpl_test_abort_if(unsupported && (srx_attempts != 1 || srx_opens || receive_posts),
                       "unsupported SRQ fallback was not cached");
    evpl_test_abort_if(inject_eagain && !eagain_injected, "refill retry was not exercised");
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    evpl_destroy(evpl);
    evpl_test_info("SRQ integration passed: %u opens, %u closes, %u receive posts",
                   srx_opens, srx_closes, receive_posts);
    return 0;
} /* main */
