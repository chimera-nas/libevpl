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

#include "common.h"

#define XLIO_HUGE_SIZE (2 * 1024 * 1024 * 1024UL)
void *
huge_alloc()
{
    int   fd, rc;
    void *addr;

    fd = memfd_create("hugepage_fd", MFD_HUGETLB);

    rc = ftruncate(fd, XLIO_HUGE_SIZE);

    evpl_xlio_abort_if(rc < 0, "Failed to set huge page memory size");

    addr = mmap(NULL, XLIO_HUGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED |
                MAP_HUGETLB, fd, 0);

    evpl_xlio_abort_if(addr == MAP_FAILED, "Failed to allocate huage pages");

    close(fd);
    return addr;

} /* huge_alloc */

void *
evpl_xlio_mem_alloc(size_t size)
{
    void *p = huge_alloc();

    return p;

} /* evpl_xlio_mem_alloc */

void
evpl_xlio_mem_free(void *p)
{
    //evpl_xlio_debug("xlio_mem_free ptr %p", p);
    munmap(p, XLIO_HUGE_SIZE);

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

    api = evpl_zalloc(sizeof(*api));

    setenv("XLIO_TRACELEVEL", "2", 0);
    setenv("XLIO_FORK", "0", 0);
    setenv("XLIO_MEM_ALLOC_TYPE", "ANON", 0);
    setenv("XLIO_SOCKETXTREME", "1", 1);
    //setenv("XLIO_MEMORY_LIMIT_USER", "1073741824", 1);
    //setenv("XLIO_MEMORY_LIMIT", "2147483648", 1);

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
    xlio_exit_fptr_t      exit_fn;

    exit_fn = (xlio_exit_fptr_t) dlsym(api->hdl, "xlio_exit");

    exit_fn();

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
    struct evpl             *evpl = s->evpl;
    struct evpl_xlio        *xlio;
    struct evpl_notify       notify;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    switch (event) {
        case XLIO_SOCKET_EVENT_ESTABLISHED:
            notify.notify_type   = EVPL_NOTIFY_CONNECTED;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
            s->writable = 1;
            evpl_xlio_socket_check_active(xlio, s);
            break;
        case XLIO_SOCKET_EVENT_TERMINATED:
            notify.notify_type   = EVPL_NOTIFY_DISCONNECTED;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
            s->writable = 0;
            s->readable = 0;
            evpl_xlio_socket_check_active(xlio, s);
            break;
        case XLIO_SOCKET_EVENT_CLOSED:
            break;
        case XLIO_SOCKET_EVENT_ERROR:
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
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl_notify       notify;

    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = (uint64_t) userdata_op;
        notify.sent.msgs     = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
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

    new_bind = evpl_bind_alloc(evpl,
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
    struct evpl_bvec        *bvec;
    struct evpl_buffer      *buffer;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    buffer = evpl_xlio_buffer_alloc(evpl, xlio, data, len, buf);

    bvec = evpl_bvec_ring_add_new(&bind->bvec_recv);

    bvec->data              = data;
    bvec->length            = len;
    bvec->buffer            = buffer;
    bind->bvec_recv.length += len;

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
                evpl_defer(evpl, &bind->close_deferral);
            }

            if (evpl_bvec_ring_is_empty(&bind->bvec_send)) {
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

        if (!(s->readable || (s->writable && s->write_interest))) {

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
    int sndbuf = 16 * 1024 * 1024, rcvbuf = 16 * 1024 * 1024;

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
        s->pd = xlio->extra->xlio_socket_get_pd(s->socket);
    }

    if (!xlio->poll) {
        xlio->poll = evpl_add_poll(evpl, evpl_xlio_poll, xlio);
    }

    s->readable       = 0;
    s->writable       = connected;
    s->write_interest = 0;
    s->active         = 0;

    res = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_XLIO_USER_DATA, &s, sizeof(s));

    evpl_xlio_abort_if(res, "Failed to set SO_XLIO_USER_DATA for socket");

} /* evpl_socket_init */

struct evpl_framework evpl_framework_xlio = {
    .id      = EVPL_FRAMEWORK_XLIO,
    .name    = "XLIO",
    .init    = evpl_xlio_init,
    .cleanup = evpl_xlio_cleanup,
    .create  = evpl_xlio_create,
    .destroy = evpl_xlio_destroy,
};
