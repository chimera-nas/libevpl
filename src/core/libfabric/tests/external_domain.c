// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Exercise the externally provided libfabric domain path: the
 * application opens the fabric/domain itself, hands it to evpl, runs a
 * connected-datagram exchange over it, and afterwards closes its own
 * objects -- which only succeeds if evpl closed all of its children and
 * left the external objects alone. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_errno.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "evpl/evpl_libfabric.h"
#include "test_common.h"

const char            hello[]  = "Hello World!";
const int             hellolen = strlen(hello) + 1;

enum evpl_protocol_id proto       = EVPL_DATAGRAM_LIBFABRIC_MSG;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;

static struct fi_info    *external_info;
static struct fid_fabric *external_fabric;
static struct fid_domain *external_domain;

static void
close_external(void)
{
    int rc;

    rc = fi_close(&external_domain->fid);

    if (rc) {
        fprintf(stderr,
                "external domain close failed (%s): evpl left children open\n",
                fi_strerror(-rc));
        _exit(1);
    }

    rc = fi_close(&external_fabric->fid);

    if (rc) {
        fprintf(stderr, "external fabric close failed (%s)\n",
                fi_strerror(-rc));
        _exit(1);
    }

    fi_freeinfo(external_info);
} /* close_external */

int
test_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    return hellolen;
} /* test_segment_callback */

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    int *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            evpl_test_info("client received '%s'",
                           notify->recv_msg.iovec[0].data);

            evpl_iovecs_release(evpl, notify->recv_msg.iovec,
                                notify->recv_msg.niov);

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            *run = 0;
            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *ep;
    struct evpl_bind     *bind;
    int                   run = 1;

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, ep, client_callback,
                        test_segment_callback, &run);

    evpl_send(evpl, bind, hello, hellolen);

    while (run) {
        evpl_continue(evpl);
    }

    evpl_endpoint_close(ep);

    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    int *run = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_DISCONNECTED:
            *run = 0;
            break;
        case EVPL_NOTIFY_RECV_MSG:

            evpl_test_info("server received '%s'",
                           notify->recv_msg.iovec[0].data);

            evpl_send(evpl, bind, hello, hellolen);

            evpl_iovecs_release(evpl, notify->recv_msg.iovec,
                                notify->recv_msg.niov);

            evpl_finish(evpl, bind);
            break;
    } /* switch */

} /* server_callback */

void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *segment_callback  = test_segment_callback;
    *conn_private_data = private_data;
} /* accept_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t                     thr;
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_global_config    *config;
    struct fi_info               *hints;
    int                           rc, opt, run = 1;
    struct evpl_endpoint         *ep;

    while ((opt = getopt(argc, argv, "a:p:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-a address] [-p port]\n", argv[0]);
                return 1;
        } /* switch */
    }

    hints = fi_allocinfo();

    hints->ep_attr->type          = FI_EP_MSG;
    hints->caps                   = FI_MSG | FI_RMA;
    hints->addr_format            = FI_SOCKADDR_IN;
    hints->mode                   = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode   = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
        FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->fabric_attr->prov_name = strdup("tcp");

    rc = fi_getinfo(FI_VERSION(1, 18), address, NULL, FI_SOURCE, hints,
                    &external_info);

    fi_freeinfo(hints);

    if (rc) {
        fprintf(stderr, "fi_getinfo: %s\n", fi_strerror(-rc));
        return 1;
    }

    rc = fi_fabric(external_info->fabric_attr, &external_fabric, NULL);

    if (rc) {
        fprintf(stderr, "fi_fabric: %s\n", fi_strerror(-rc));
        return 1;
    }

    rc = fi_domain(external_fabric, external_info, &external_domain, NULL);

    if (rc) {
        fprintf(stderr, "fi_domain: %s\n", fi_strerror(-rc));
        return 1;
    }

    /* registered before evpl_init so it runs after evpl_cleanup */
    atexit(close_external);

    config = evpl_global_config_init();

    test_evpl_set_core_mech(config);

    evpl_global_config_set_libfabric_external_domain(config,
                                                     external_fabric,
                                                     external_domain,
                                                     external_info);

    evpl_init(config);

    evpl = evpl_create(NULL);

    ep = evpl_endpoint_create(address, port);

    listener = evpl_listener_create();

    binding = evpl_listener_attach(evpl, listener, accept_callback, &run);

    evpl_test_abort_if(evpl_listen(listener, proto, ep),
                       "failed to listen");

    pthread_create(&thr, NULL, client_thread, NULL);

    while (run) {
        evpl_continue(evpl);
    }

    pthread_join(thr, NULL);

    evpl_listener_detach(evpl, binding);

    evpl_listener_destroy(listener);

    evpl_endpoint_close(ep);

    evpl_destroy(evpl);

    return 0;
} /* main */
