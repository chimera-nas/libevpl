#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> // For TCP_NODELAY
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "core/bind.h"
#include "core/io_uring/io_uring.h"
#include "core/io_uring/io_uring_internal.h"

struct evpl_io_uring_socket {
    int                           fd;
    struct evpl_io_uring_request *recv_req;
    struct evpl_io_uring_request *accept_req;
    int                           reqs_inflight;
};

struct evpl_io_uring_accepted_socket {
    int fd;
};

#define evpl_event_io_uring_socket(eventp) container_of((eventp), struct evpl_io_uring_socket, \
                                                        event)


static void
evpl_io_uring_tcp_recv_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req);

static inline void
evpl_io_uring_post_multishot_recv(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s)
{
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    while (s->fd >= 0 && !s->recv_req) {

        req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

        req->callback = evpl_io_uring_tcp_recv_callback;

        req->tcp.socket = s;
        sqe             = io_uring_get_sqe(&ctx->ring);

        io_uring_prep_recv_multishot(sqe, s->fd, NULL, 0, 0);

        sqe->buf_group = EVPL_IO_URING_BUFGROUP_ID;
        sqe->flags    |= IOSQE_BUFFER_SELECT;
        io_uring_sqe_set_data64(sqe, (uint64_t) req);

        s->recv_req = req;

        evpl_defer(evpl, &ctx->flush);
    }
} /* evpl_io_uring_post_multishot_recv */

static void
evpl_io_uring_tcp_recv_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = req->tcp.socket;
    int                           buffer_id, niov, i;
    uint64_t                      length;
    struct evpl_iovec            *iov;
    struct evpl_notify            notify;
    struct evpl_bind             *bind   = evpl_private2bind(req->tcp.socket);
    int                           more   = !!(req->flags & IORING_CQE_F_MORE);
    int                           buffer = !!(req->flags & IORING_CQE_F_BUFFER);

    if (unlikely(!more)) {
        s->recv_req = NULL;
    }

    if (req->res <= 0) {
        evpl_close(evpl, bind);
        return;
    }

    if (buffer) {

        buffer_id = req->flags >> IORING_CQE_BUFFER_SHIFT;

        iov         = &ctx->recv_ring_iov[buffer_id];
        iov->length = req->res;

        evpl_iovec_ring_append(evpl, &bind->iovec_recv, iov, req->res);

        ctx->recv_ring_iov_empty[buffer_id >> 6] |=  (1ULL << (buffer_id & 63));


        if (bind->segment_callback) {

            iov = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);

            while (1) {

                length = bind->segment_callback(evpl, bind, bind->private_data);

                if (length == 0 ||
                    evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                    break;
                }

                if (unlikely(length < 0)) {
                    evpl_close(evpl, bind);
                    return;
                }

                niov = evpl_iovec_ring_copyv(evpl, iov, &bind->iovec_recv, length);

                notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
                notify.recv_msg.iovec  = iov;
                notify.recv_msg.niov   = niov;
                notify.recv_msg.length = length;
                notify.recv_msg.addr   = bind->remote;

                bind->notify_callback(evpl, bind, &notify, bind->private_data);

                for (i = 0; i < niov; ++i) {
                    evpl_iovec_decref(&iov[i]);
                }

            }

        } else {
            notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }
    }

    if (!more) {
        //evpl_close(evpl, bind);
    }

} /* evpl_io_uring_tcp_recv_callback */

static void
evpl_io_uring_tcp_send_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_bind  *bind = evpl_private2bind(req->tcp.socket);
    struct evpl_notify notify;

    evpl_iovec_decref(&req->tcp.iov);

    if (req->res > 0 && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = req->res;
        notify.sent.msgs     = req->tcp.msgs_sent;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    req->tcp.socket->reqs_inflight--;

    if (req->tcp.socket->reqs_inflight == 0) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }


    if (req->res <= 0) {
        evpl_close(evpl, bind);
        return;
    }

} /* evpl_io_uring_tcp_send_callback */

static inline void
evpl_io_uring_pump(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s)
{
    int                           do_flush = 0;
    struct evpl_bind             *bind     = evpl_private2bind(s);
    struct io_uring_sqe          *sqe;
    struct evpl_io_uring_request *req;

    while (!evpl_iovec_ring_is_empty(&bind->iovec_send)) {

        req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

        req->callback      = evpl_io_uring_tcp_send_callback;
        req->tcp.socket    = s;
        req->tcp.msgs_sent = 0;
        sqe                = io_uring_get_sqe(&ctx->ring);

        req->tcp.iov = *evpl_iovec_ring_tail(&bind->iovec_send);
        evpl_iovec_ring_remove(&bind->iovec_send);

        evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe returned NULL");

        io_uring_prep_send(sqe, s->fd, req->tcp.iov.data, req->tcp.iov.length, 0);

        io_uring_sqe_set_data64(sqe, (uint64_t) req);

        if (bind->segment_callback) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (!dgram) {
                break;
            }

            dgram->niov--;

            if (dgram->niov == 0) {
                req->tcp.msgs_sent++;
                evpl_dgram_ring_remove(&bind->dgram_send);
            }
        }

        s->reqs_inflight++;

        do_flush = 1;
    }

    if (do_flush) {
        evpl_defer(evpl, &ctx->flush);
    }
} /* evpl_io_uring_pump */

static inline void
evpl_io_uring_setup_socket(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s,
    int                           listen)
{
    int flags, rc, yes = 1;

    evpl_io_uring_fill_recv_ring(evpl, ctx);

    s->recv_req      = NULL;
    s->accept_req    = NULL;
    s->reqs_inflight = 0;

    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_io_uring_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_io_uring_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                               errno));


    if (!listen) {
        rc = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

        evpl_io_uring_abort_if(rc, "Failed to set TCP_NODELAY on socket");


        evpl_io_uring_post_multishot_recv(evpl, ctx, s);
    }

} /* evpl_io_uring_setup_socket */

static void
evpl_io_uring_tcp_connect_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx  = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s    = req->tcp.socket;
    struct evpl_bind             *bind = evpl_private2bind(s);
    struct evpl_notify            notify;

    if (req->res < 0) {
        evpl_close(evpl, bind);
        return;
    }

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_connect_callback */

static void
evpl_io_uring_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct io_uring_sqe          *sqe = io_uring_get_sqe(&ctx->ring);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);
    struct evpl_io_uring_request *req;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    req->tcp.socket = s;
    req->callback   = evpl_io_uring_tcp_connect_callback;

    s->fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);

    evpl_io_uring_abort_if(s->fd < 0, "Failed to create tcp socket: %s", strerror(
                               errno));

    evpl_io_uring_setup_socket(evpl, ctx, s, 0);

    io_uring_prep_connect(sqe, s->fd, (struct sockaddr *) bind->remote->addr, bind->remote->addrlen);

    io_uring_sqe_set_data(sqe, req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_connect */

static void
evpl_io_uring_tcp_close_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
} /* evpl_io_uring_tcp_close_callback */

static void
evpl_io_uring_tcp_cancel_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_socket  *s   = req->tcp.socket;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *close_req;
    struct io_uring_sqe          *sqe;

    close_req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    sqe = io_uring_get_sqe(&ctx->ring);

    close_req->tcp.socket = s;
    close_req->callback   = evpl_io_uring_tcp_close_callback;

    io_uring_prep_close(sqe, s->fd);

    io_uring_sqe_set_data(sqe, close_req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_close */


static void
evpl_io_uring_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    sqe = io_uring_get_sqe(&ctx->ring);

    req->tcp.socket = s;
    req->callback   = evpl_io_uring_tcp_cancel_callback;

    io_uring_prep_cancel_fd(sqe, s->fd, IORING_ASYNC_CANCEL_ALL);

    io_uring_sqe_set_data(sqe, req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_close */

static void
evpl_io_uring_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);

    if (s->recv_req) {
        evpl_io_uring_request_free(ctx, s->recv_req);
    }

    if (s->accept_req) {
        evpl_io_uring_request_free(ctx, s->accept_req);
    }
} /* evpl_io_uring_tcp_close */


static void
evpl_io_uring_tcp_accept_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_socket          *ls          = req->tcp.socket;
    struct evpl_bind                     *listen_bind = evpl_private2bind(ls);
    struct evpl_address                  *remote_addr;
    struct evpl_io_uring_accepted_socket *accepted_socket;
    int                                   more = !!(req->flags & IORING_CQE_F_MORE);

    if (unlikely(!more)) {
        ls->accept_req = NULL;
    }

    if (req->res < 0) {
        return;
    }

    remote_addr = evpl_address_alloc();

    remote_addr->addrlen = sizeof(remote_addr->sa);

    accepted_socket = evpl_zalloc(sizeof(*accepted_socket));

    accepted_socket->fd = req->res;

    listen_bind->accept_callback(evpl, listen_bind, remote_addr, accepted_socket, listen_bind->private_data);

} /* evpl_accept_tcp */

static void
evpl_io_uring_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_io_uring_socket  *s   = evpl_bind_private(listen_bind);
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;
    int                           rc;
    const int                     yes = 1;

    s->fd = socket(listen_bind->local->addr->sa_family, SOCK_STREAM, 0);

    evpl_io_uring_abort_if(s->fd < 0, "Failed to create tcp listen socket: %s",
                           strerror(errno));

    rc = setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    evpl_io_uring_abort_if(rc < 0, "Failed to set socket options: %s", strerror(
                               errno));

    rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);

    evpl_io_uring_abort_if(rc < 0, "Failed to bind listen socket: %s", strerror(
                               errno));

    evpl_io_uring_setup_socket(evpl, ctx, s, 1);

    rc = listen(s->fd, evpl_shared->config->max_pending);

    evpl_io_uring_fatal_if(rc, "Failed to listen on listener fd");

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    req->callback   = evpl_io_uring_tcp_accept_callback;
    req->tcp.socket = s;
    sqe             = io_uring_get_sqe(&ctx->ring);

    io_uring_prep_multishot_accept(sqe, s->fd, NULL, 0, 0);

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    s->accept_req = req;

    evpl_defer(evpl, &ctx->flush);

} /* evpl_io_uring_tcp_listen */

static void
evpl_io_uring_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_io_uring_context         *ctx             = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket          *s               = evpl_bind_private(bind);
    struct evpl_io_uring_accepted_socket *accepted_socket = accepted;
    struct evpl_notify                    notify;

    s->fd = accepted_socket->fd;

    evpl_free(accepted_socket);

    evpl_io_uring_setup_socket(evpl, ctx, s, 0);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_attach */

static void
evpl_io_uring_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_flush */

struct evpl_protocol evpl_io_uring_tcp = {
    .id            = EVPL_STREAM_IO_URING_TCP,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_IO_URING_TCP",
    .framework     = &evpl_framework_io_uring,
    .connect       = evpl_io_uring_tcp_connect,
    .pending_close = evpl_io_uring_pending_close,
    .close         = evpl_io_uring_close,
    .listen        = evpl_io_uring_tcp_listen,
    .attach        = evpl_io_uring_attach,
    .flush         = evpl_io_uring_flush,
};
