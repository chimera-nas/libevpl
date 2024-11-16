#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <linux/memfd.h>



#include "core/internal.h"
#include "xlio.h"
#include "core/evpl.h"
#include "core/protocol.h"
#include "core/evpl_shared.h"

extern struct evpl_shared *evpl_shared;

#include "common.h"

void *
evpl_xlio_mem_alloc(size_t size)
{

    evpl_xlio_abort_if(size != evpl_shared->config->slab_size,
                       "XLIO requested allocation of %ld bytes which is not the slab size of %lu bytes",
                       size, evpl_shared->config->slab_size);

    return evpl_allocator_alloc_slab(evpl_shared->allocator);

} /* evpl_xlio_mem_alloc */

void
evpl_xlio_mem_free(void *p)
{
    /* No action needed */
} /* evpl_xlio_mem_free */

typedef int (*getsockopt_fptr_t)(
    int        __fd,
    int        __level,
    int        __optname,
    void      *__optval,
    socklen_t *__optlen);

void *
evpl_xlio_init()
{
    struct evpl_xlio_api *api;
    struct xlio_init_attr init_attr;
    int                   rc;
    socklen_t             len;
    unsigned int          needed_caps;
    getsockopt_fptr_t     xlio_getsockopt;
    char                  tmp[80];

    api = evpl_zalloc(sizeof(*api));

    setenv("XLIO_TRACELEVEL", "2", 0);
    setenv("XLIO_FORK", "0", 0);
    setenv("XLIO_MEM_ALLOC_TYPE", "ANON", 0);
    setenv("XLIO_SOCKETXTREME", "1", 1);

    snprintf(tmp, sizeof(tmp), "%lu", evpl_shared->config->slab_size);
    setenv("XLIO_MEMORY_LIMIT", tmp, 1);

    pthread_mutex_init(&api->pd_lock, NULL);

    api->hdl = dlopen("/opt/nvidia/lib/libxlio.so", RTLD_LAZY);

    evpl_xlio_abort_if(!api->hdl, "Failed to dynamically load XLIO library");

    len = sizeof(api->extra);

    xlio_getsockopt = (getsockopt_fptr_t) dlsym(api->hdl, "getsockopt");

    rc = xlio_getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &api->extra, &len);

    evpl_xlio_abort_if(rc < 0, "Failed to get XLIO extra API");

    evpl_xlio_abort_if(len < sizeof(struct xlio_api_t *) ||
                       api->extra == NULL ||
                       api->extra->magic != XLIO_MAGIC_NUMBER,
                       "XLIO xEtra API does not match header");

    needed_caps = XLIO_EXTRA_API_SOCKETXTREME_POLL |
        XLIO_EXTRA_API_GET_SOCKET_RINGS_NUM;

    evpl_xlio_abort_if((api->extra->cap_mask & needed_caps) != needed_caps,
                       "XLIO is missing socketxtreme capabilities");

    memset(&init_attr, 0, sizeof(init_attr));

    init_attr.memory_alloc = evpl_xlio_mem_alloc;
    init_attr.memory_free  = evpl_xlio_mem_free;

    rc = api->extra->xlio_init_ex(&init_attr);

    return api;
} /* evpl_xlio_init */

typedef void (*xlio_exit_fptr_t)(
    void);

void
evpl_xlio_cleanup(void *private_data)
{
    struct evpl_xlio_api *api = private_data;

    //xlio_exit_fptr_t      exit_fn;

    //exit_fn = (xlio_exit_fptr_t) dlsym(api->hdl, "xlio_exit");

    //exit_fn();

    evpl_free(api);
} /* evpl_xlio_cleanup */

static void
evpl_xlio_socket_event(
    xlio_socket_t,
    uintptr_t userdata_sq,
    int       event,
    int       value)
{
    struct evpl_xlio_socket *s    = (struct evpl_xlio_socket *) userdata_sq;
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl             *evpl;
    struct evpl_xlio        *xlio;
    struct evpl_notify       notify;

    if (!userdata_sq) {
        return;
    }

    evpl = s->evpl;
    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    switch (event) {
        case XLIO_SOCKET_EVENT_ESTABLISHED:
            evpl_xlio_debug("socket %p established", s);
            notify.notify_type   = EVPL_NOTIFY_CONNECTED;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
            s->writable = 1;
            evpl_xlio_socket_check_active(xlio, s);
            break;
        case XLIO_SOCKET_EVENT_TERMINATED:
            evpl_xlio_debug("socket %p terminated", s);
            s->writable = 0;
            s->readable = 0;
            s->closed   = 1;
            evpl_xlio_socket_check_active(xlio, s);
            evpl_bind_destroy(evpl, bind);
            break;
        case XLIO_SOCKET_EVENT_CLOSED:
            evpl_xlio_debug("socket %p closed", s);
            evpl_defer(evpl, &bind->close_deferral);
            break;
        case XLIO_SOCKET_EVENT_ERROR:
            evpl_xlio_debug("socket %p errored", s);
            evpl_defer(evpl, &bind->close_deferral);
            break;
    } /* switch */
} /* evpl_xlio_socket_event */

static void
evpl_xlio_socket_completion(
    xlio_socket_t,
    uintptr_t userdata_sq,
    uintptr_t userdata_op)
{
    struct evpl_xlio_socket *s    = (struct evpl_xlio_socket *) userdata_sq;
    struct evpl             *evpl = s->evpl;
    struct evpl_xlio        *xlio;
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl_xlio_zc     *zc   = (struct evpl_xlio_zc *) userdata_op;
    struct evpl_notify       notify;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = zc->length;
        notify.sent.msgs     = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    evpl_buffer_release(evpl, zc->buffer);

    --s->zc_pending;

    evpl_xlio_free_zc(xlio, zc);
} /* evpl_xlio_socket_completion */

static void
evpl_xlio_socket_accept(
    xlio_socket_t sock,
    xlio_socket_t parent,
    uintptr_t     parent_userdata_sq)
{
    struct evpl             *evpl;
    struct evpl_xlio        *xlio;
    struct evpl_bind        *listen_bind;
    struct evpl_xlio_socket *s, *ls;
    struct evpl_bind        *new_bind;
    struct evpl_address     *srcaddr;
    struct evpl_notify       notify;

    ls = (struct evpl_xlio_socket *) parent_userdata_sq;

    listen_bind = evpl_private2bind(ls);

    evpl = ls->evpl;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    srcaddr = evpl_address_alloc(evpl);

    xlio->extra->xlio_socket_getpeername(sock, srcaddr->addr, &srcaddr->addrlen)
    ;

    new_bind = evpl_bind_prepare(evpl,
                                 listen_bind->protocol,
                                 listen_bind->local, srcaddr);

    --srcaddr->refcnt;

    s = evpl_bind_private(new_bind);

    s->evpl   = evpl;
    s->socket = sock;

    evpl_xlio_socket_init(evpl, xlio, s, 0, 1,
                          ls->read_callback,
                          ls->write_callback);

    xlio->extra->xlio_socket_update(s->socket, 0, (uintptr_t) s);

    listen_bind->accept_callback(
        evpl,
        listen_bind,
        new_bind,
        &new_bind->notify_callback,
        &new_bind->segment_callback,
        &new_bind->private_data,
        listen_bind->private_data);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;

    new_bind->notify_callback(evpl, new_bind, &notify, new_bind->private_data);
} /* evpl_xlio_socket_accept */

static void
evpl_xlio_socket_rx(
    xlio_socket_t,
    uintptr_t        userdata_sq,
    void            *data,
    size_t           len,
    struct xlio_buf *buf)
{
    struct evpl_xlio_socket *s    = (struct evpl_xlio_socket *) userdata_sq;
    struct evpl             *evpl = s->evpl;
    struct evpl_xlio        *xlio;
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl_iovec       *iovec;
    struct evpl_buffer      *buffer;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    buffer = evpl_xlio_buffer_alloc(evpl, xlio, data, len, buf);

    iovec = evpl_iovec_ring_add_new(&bind->iovec_recv);

    iovec->data              = data;
    iovec->length            = len;
    iovec->buffer            = buffer;
    bind->iovec_recv.length += len;

    s->readable = 1;
    evpl_xlio_socket_check_active(xlio, s);
} /* evpl_xlio_socket_rx */

static void
evpl_xlio_poll(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_xlio        *xlio = private_data;
    struct evpl_xlio_socket *s;
    struct evpl_bind        *bind;
    int                      i, res;

    xlio->extra->xlio_poll_group_poll(xlio->poll_group);

    if (xlio->num_active_sockets) {
        evpl_activity(evpl);
    }

    for (i = 0; i < xlio->num_active_sockets; ++i) {

        s = xlio->active_sockets[i];

        bind = evpl_private2bind(s);

        if (s->writable && s->write_interest) {
            res = s->write_callback(evpl, s);

            if (res) {
                s->closed = 1;
                evpl_defer(evpl, &bind->close_deferral);
            }

            if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
                s->write_interest = 0;

                if (bind->flags & EVPL_BIND_FINISH) {
                    evpl_defer(evpl, &bind->close_deferral);
                }
            }
        }

        if (s->readable) {
            s->readable = 0;
            s->read_callback(evpl, s);
        }

        if (s->closed ||  !(s->readable || (s->writable && s->write_interest)))
        {

            s->active = 0;

            if (i + 1 < xlio->num_active_sockets) {
                xlio->active_sockets[i] = xlio->active_sockets[xlio->
                                                               num_active_sockets
                                                               - 1];
                i--;
            }

            xlio->num_active_sockets--;
        }
    }

    xlio->extra->xlio_poll_group_flush(xlio->poll_group);
} /* evpl_xlio_poll */

void *
evpl_xlio_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_xlio_api       *api;
    struct evpl_xlio           *xlio;
    struct xlio_poll_group_attr poll_attr;
    int                         res;

    xlio = evpl_zalloc(sizeof(*xlio));

    api = private_data;

    xlio->api   = api;
    xlio->extra = api->extra;

    memset(&poll_attr, 0, sizeof(poll_attr));

    poll_attr.flags            = XLIO_GROUP_FLAG_DIRTY;
    poll_attr.socket_event_cb  = evpl_xlio_socket_event;
    poll_attr.socket_comp_cb   = evpl_xlio_socket_completion;
    poll_attr.socket_rx_cb     = evpl_xlio_socket_rx;
    poll_attr.socket_accept_cb = evpl_xlio_socket_accept;

    res = xlio->extra->xlio_poll_group_create(
        &poll_attr, &xlio->poll_group);

    evpl_xlio_abort_if(res, "Failed to create XLIO poll group");

    xlio->num_active_sockets = 0;
    xlio->max_active_sockets = 256;

    xlio->active_sockets = evpl_zalloc(sizeof(struct evpl_socket *) * xlio->
                                       max_active_sockets);


    return xlio;
} /* evpl_xlio_create */

void
evpl_xlio_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_xlio *xlio = private_data;

    if (xlio->poll) {
        evpl_remove_poll(evpl, xlio->poll);
    }

    xlio->extra->xlio_poll_group_destroy(xlio->poll_group);

    evpl_free(xlio->active_sockets);
    evpl_free(xlio);
} /* evpl_xlio_destroy */

static int
evpl_xlio_attach_pd(
    struct evpl      *evpl,
    struct evpl_xlio *xlio,
    struct ibv_pd    *pd)
{
    struct evpl_xlio_api *api = xlio->api;
    struct ibv_pd       **cur_pd;
    int                   i;

    evpl_xlio_debug("attaching xlio pd %p", pd);

    pthread_mutex_lock(&api->pd_lock);

    for (i = 0, cur_pd = api->pd; *cur_pd; i++, cur_pd++) {
        if (*cur_pd == pd) {
            break;
        }
    }

    if (*cur_pd != pd) {
        *cur_pd = pd;
        evpl_xlio_debug("pd %p is new, reregistering\n", pd);
        evpl_allocator_reregister(evpl_shared->allocator);
    }

    pthread_mutex_unlock(&api->pd_lock);

    return i;
} /* evpl_xlio_attach_pd */

void
evpl_xlio_socket_init(
    struct evpl               *evpl,
    struct evpl_xlio          *xlio,
    struct evpl_xlio_socket   *s,
    int                        listen,
    int                        connected,
    evpl_xlio_read_callback_t  read_callback,
    evpl_xlio_write_callback_t write_callback)
{
    int res, yes = 1;
    int sndbuf = 2 * 1024 * 1024, rcvbuf = 2 * 1024 * 1024;

    s->evpl      = evpl;
    s->listen    = listen;
    s->connected = connected;
    s->config    = evpl_config(evpl);

    s->read_callback  = read_callback;
    s->write_callback = write_callback;

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

    evpl_xlio_abort_if(res, "Failed to set TCP_QUICKACK on socket");

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, IPPROTO_TCP, TCP_QUICKACK, (char *) &yes, sizeof(yes));

    evpl_xlio_abort_if(res, "Failed to set TCP_QUICKACK on socket");

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_ZEROCOPY, (char *) &yes, sizeof(yes));

    evpl_xlio_abort_if(res, "Failed to set SO_ZEROCOPY on socket");

#if 0
    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, IPPROTO_TCP, TCP_CONGESTION, "reno", strlen("reno"));

    evpl_xlio_abort_if(res, "Failed to set TCP_CONGESTION on socket");
#endif /* if 0 */

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    evpl_xlio_abort_if(res, "Failed to set SO_SNDBUF");

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    evpl_xlio_abort_if(res, "Failed to set SO_RCVBUF");

    if (listen) {
        s->pd = NULL;
    } else {
        s->pd       = xlio->extra->xlio_socket_get_pd(s->socket);
        s->pd_index = evpl_xlio_attach_pd(evpl, xlio, s->pd);
    }

    if (!xlio->poll) {
        xlio->poll = evpl_add_poll(evpl, evpl_xlio_poll, xlio);
    }

    s->readable       = 0;
    s->writable       = connected;
    s->write_interest = 0;
    s->active         = 0;
    s->closed         = 0;
    s->zc_pending     = 0;

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_XLIO_USER_DATA, &s, sizeof(s));

    evpl_xlio_abort_if(res, "Failed to set SO_XLIO_USER_DATA for socket");

} /* evpl_socket_init */

void *
evpl_xlio_register(
    void *buffer,
    int   size,
    void *buffer_private,
    void *private_data)
{
    struct evpl_xlio_api *api = private_data;
    struct ibv_mr       **mrset;
    struct ibv_pd       **pd;
    int                   i;

    evpl_xlio_debug("evpl_xlio_register buffer %p size %d entry", buffer, size);

    if (buffer_private) {
        evpl_xlio_debug("using existing buffer_private");
        mrset = (struct ibv_mr **) buffer_private;
    } else {
        mrset = evpl_zalloc(sizeof(struct ibv_mr *) * EVPL_XLIO_MAX_PD);
    }

    for (i = 0, pd = api->pd; *pd; i++, pd++) {

        if (mrset[i]) {
            continue;
        }

        evpl_xlio_debug("creating mr for %p length %d on pd %p",
                        buffer, size, *pd);

        mrset[i] = ibv_reg_mr(*pd, buffer, size,
                              //0);
                              IBV_ACCESS_LOCAL_WRITE |
                              IBV_ACCESS_RELAXED_ORDERING);

        evpl_xlio_abort_if(!mrset[i], "Failed to register XLIO memory region");
    }

    return mrset;
} /* evpl_xlio_register */

void
evpl_xlio_unregister(
    void *buffer_private,
    void *private_data)
{
    struct evpl_xlio_api *api   = private_data;
    struct ibv_mr       **mrset = buffer_private;
    struct ibv_pd       **pd;
    int                   i;

    if (!mrset) {
        return;
    }

    for (i = 0, pd = api->pd; *pd; ++i, pd++) {
        ibv_dereg_mr(mrset[i]);
    }

    evpl_free(mrset);


} /* evpl_xlio_unregister */

struct evpl_framework evpl_framework_xlio = {
    .id                = EVPL_FRAMEWORK_XLIO,
    .name              = "XLIO",
    .init              = evpl_xlio_init,
    .cleanup           = evpl_xlio_cleanup,
    .create            = evpl_xlio_create,
    .destroy           = evpl_xlio_destroy,
    .register_memory   = evpl_xlio_register,
    .unregister_memory = evpl_xlio_unregister,
};
