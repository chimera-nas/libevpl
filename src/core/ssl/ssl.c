
#include "ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "core/protocol.h"
#include "core/internal.h"
#include "core/socket/common.h"
#include "core/socket/tcp.h"
#include "core/bind.h"

#define evpl_ssl_private(bind) \
        (evpl_bind_private(bind) + sizeof(struct evpl_socket))

struct evpl_ssl_socket {
    SSL_CTX *ctx;
    int      handshake;
};

static void *
evpl_ssl_init()
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    return NULL;
} /* evpl_ssl_init */

static void
evpl_ssl_cleanup(void *ctx)
{
    EVP_cleanup();

} /* evpl_ssl_cleanup */

static void *
evpl_ssl_create(
    struct evpl *evpl,
    void        *ctx)
{
    return NULL;
} /* evpl_ssl_create */

static void
evpl_ssl_destroy(
    struct evpl *evpl,
    void        *ctx)
{

} /* evpl_ssl_destroy */

static void
evpl_tcp_ssl_accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *listen_bind,
    struct evpl_bind        *accepted_bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data);

static void
evpl_socket_tcp_ssl_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_ssl_socket *ssl = evpl_ssl_private(bind);

    ssl->ctx = SSL_CTX_new(TLS_server_method());

    evpl_socket_tcp.listen(evpl, bind);

} /* evpl_socket_tcp_ssl_listen */

static void
evpl_socket_tcp_ssl_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_socket_tcp.connect(evpl, bind);
} /* evpl_socket_tcp_ssl_connect */

static void
evpl_socket_tcp_ssl_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_ssl_socket *ssl = evpl_ssl_private(bind);

    SSL_CTX_free(ssl->ctx);

    evpl_socket_tcp.pending_close(evpl, bind);
} /* evpl_socket_tcp_ssl_pending_close */

static void
evpl_socket_tcp_ssl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_socket_tcp.close(evpl, bind);
} /* evpl_socket_tcp_ssl_close */

static void
evpl_socket_tcp_ssl_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_socket_tcp.flush(evpl, bind);
} /* evpl_socket_tcp_ssl_flush */

struct evpl_framework evpl_framework_ssl = {
    .id      = EVPL_FRAMEWORK_SSL,
    .name    = "SSL",
    .init    = evpl_ssl_init,
    .cleanup = evpl_ssl_cleanup,
    .create  = evpl_ssl_create,
    .destroy = evpl_ssl_destroy,
};


struct evpl_protocol  evpl_tcp_ssl = {
    .id            = EVPL_STREAM_SOCKET_TCP_SSL,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_SOCKET_TCP_SSL",
    .framework     = &evpl_framework_ssl,
    .listen        = evpl_socket_tcp_ssl_listen,
    .connect       = evpl_socket_tcp_ssl_connect,
    .pending_close = evpl_socket_tcp_ssl_pending_close,
    .close         = evpl_socket_tcp_ssl_close,
    .flush         = evpl_socket_tcp_ssl_flush,
};