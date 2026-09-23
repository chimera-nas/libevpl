// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/ec.h>
#endif /* ifdef HAVE_TLS */
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "backpressure_cases.h"

/* An independent peer is essential: an evpl receiver would keep draining the
 * kernel even when the application stopped consuming. Each burst exceeds
 * both the socket send buffer and SPDK's 16 x 64-iovec in-flight window. */
#define VECTOR_COUNT 4096
#define VECTOR_BYTES 4093
#define BURST_BYTES  ((size_t) VECTOR_COUNT * VECTOR_BYTES)
#define MAX_VECTORS  (2 * VECTOR_COUNT)

struct buffer {
    struct evpl_iovec_ref ref;
    unsigned char        *data;
    unsigned int          released;
};
struct replay {
    struct evpl       *evpl;
    struct evpl_bind  *bind;
    struct buffer     *buffers;
    struct evpl_iovec *iov;
    size_t             queued, received, sent;
    unsigned int       connected, disconnected, serial, count;
    int                fd, take;
#ifdef HAVE_TLS
    SSL_CTX           *tls_context;
    SSL               *tls;
#endif /* ifdef HAVE_TLS */
};

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

static void
progress(
    struct replay *r,
    uint64_t       deadline)
{
    evpl_test_abort_if(now_ms() > deadline,
                       "pressure timeout: queued=%zu received=%zu sent=%zu connected=%u disconnected=%u",
                       r->queued, r->received, r->sent, r->connected, r->disconnected);
    test_mbt_continue(r->evpl);
} /* progress */

static unsigned char
payload(
    size_t       offset,
    unsigned int serial)
{
    return (unsigned char) (offset * 7 + (offset >> 12) * 11 + serial * 31);
} /* payload */

static void
release_buffer(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct buffer *b = (struct buffer *) ref;

    evpl_test_abort_if(b->released++, "buffer released twice");
    free(b->data);
    b->data = NULL;
} /* release_buffer */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *n,
    void               *arg)
{
    struct replay *r = arg;

    evpl_test_abort_if(r->disconnected, "callback after disconnect");
    switch (n->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_abort_if(n->notify_status || r->connected++, "connect failed or repeated");
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            r->disconnected++;
            r->bind = NULL;
            break;
        case EVPL_NOTIFY_SENT:
            evpl_test_abort_if(n->notify_status, "failed send reported as successful completion");
            r->sent += n->sent.bytes;
            evpl_test_abort_if(r->sent > r->queued, "duplicate send completion");
            break;
        default: evpl_test_abort_if(1, "unexpected peer notification %u", n->notify_type);
    } /* switch */
} /* notify */

#ifdef HAVE_TLS
static SSL_CTX *
peer_context(void)
{
    SSL_CTX      *ctx    = SSL_CTX_new(TLS_server_method());
    EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY     *key    = NULL;
    X509         *cert   = X509_new();

    evpl_test_abort_if(!ctx || !keyctx || !cert, "TLS allocation failed");
    evpl_test_abort_if(EVP_PKEY_keygen_init(keyctx) <= 0 ||
                       EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyctx, NID_X9_62_prime256v1) <= 0 ||
                       EVP_PKEY_keygen(keyctx, &key) <= 0, "TLS key generation failed");
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), -60);
    X509_gmtime_adj(X509_get_notAfter(cert), 3600);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "localhost", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    evpl_test_abort_if(!X509_sign(cert, key, EVP_sha256()) || SSL_CTX_use_certificate(ctx, cert) != 1 ||
                       SSL_CTX_use_PrivateKey(ctx, key) != 1, "TLS certificate setup failed");
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keyctx);
    return ctx;
} /* peer_context */
#endif /* ifdef HAVE_TLS */

static void
nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    evpl_test_abort_if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK), "fcntl failed");
} /* nonblock */

static void
connect_peer(
    struct replay *r,
    int            take)
{
    int                listener = socket(AF_INET, SOCK_STREAM, 0);
    int                window   = 128 * 1024;
    struct sockaddr_in addr     = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t          addrlen  = sizeof(addr);

    evpl_test_abort_if(listener < 0, "socket failed");
    evpl_test_abort_if(setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) ||
                       bind(listener, (struct sockaddr *) &addr, sizeof(addr)) || listen(listener, 1) ||
                       getsockname(listener, (struct sockaddr *) &addr, &addrlen), "listen failed");
    nonblock(listener);
    r->take = take;
    r->serial++;
    r->connected = r->disconnected = r->count = 0;
    r->queued    = r->received = r->sent = 0;
    struct evpl_endpoint *endpoint = evpl_endpoint_create("127.0.0.1", ntohs(addr.sin_port));
    r->bind = evpl_connect(r->evpl, test_mbt_stream_protocol(), NULL, endpoint, notify, NULL, r);
    evpl_endpoint_close(endpoint);
    evpl_test_abort_if(!r->bind, "evpl_connect failed");
    evpl_bind_request_send_notifications(r->evpl, r->bind);
    uint64_t              deadline = now_ms() + 15000;
    do {
        r->fd = accept(listener, NULL, NULL);
        evpl_test_abort_if(r->fd < 0 && errno != EAGAIN && errno != EWOULDBLOCK, "accept failed");
        progress(r, deadline);
    } while (r->fd < 0);
    close(listener);
    nonblock(r->fd);
#ifdef HAVE_TLS
    if (r->tls_context) {
        r->tls = SSL_new(r->tls_context);
        evpl_test_abort_if(!r->tls || SSL_set_fd(r->tls, r->fd) != 1, "TLS peer setup failed");
        for (;;) {
            int rc = SSL_accept(r->tls);
            if (rc == 1) {
                break;
            }
            int error = SSL_get_error(r->tls, rc);
            evpl_test_abort_if(error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE,
                               "TLS handshake failed: %d", error);
            progress(r, deadline);
        }
    }
#endif /* ifdef HAVE_TLS */
    while (!r->connected) {
        progress(r, deadline);
    }
} /* connect_peer */

static void
queue_burst(struct replay *r)
{
    unsigned int start = r->count;

    evpl_test_abort_if(start + VECTOR_COUNT > MAX_VECTORS, "too many bursts");
    for (unsigned int i = start; i < start + VECTOR_COUNT; i++) {
        struct buffer *b = &r->buffers[i];
        memset(b, 0, sizeof(*b));
        b->data = malloc(VECTOR_BYTES);
        evpl_test_abort_if(!b->data, "buffer allocation failed");
        b->ref.flags = EVPL_IOVEC_FLAG_SHARED;
        atomic_init(&b->ref.refcnt_atomic, 1);
        b->ref.release = release_buffer;
        for (unsigned int j = 0; j < VECTOR_BYTES; j++) {
            b->data[j] = payload((size_t) i * VECTOR_BYTES + j, r->serial);
        }
        r->iov[i].data   = b->data;
        r->iov[i].length = VECTOR_BYTES;
        evpl_iovec_set_ref(&r->iov[i], &b->ref);
    }
    r->count  += VECTOR_COUNT;
    r->queued += BURST_BYTES;
    evpl_sendv(r->evpl, r->bind, &r->iov[start], VECTOR_COUNT, BURST_BYTES,
               r->take ? EVPL_SEND_FLAG_TAKE_REF : 0);
} /* queue_burst */

static void
hold(struct replay *r)
{
    /* Establish a blocked suffix, not a particular callback batching pattern.
     * The peer must receive nothing here. A quarter-burst prefix is larger
     * than the bounded peer window plus ordinary socket send buffering. */
    uint64_t until = now_ms() + 100;

    while (now_ms() < until) {
        progress(r, until + 1000);
    }
    evpl_test_abort_if(r->disconnected || r->sent == r->queued,
                       "paused peer did not retain an outstanding suffix: %zu/%zu", r->sent, r->queued);
    evpl_test_abort_if(r->received && !r->sent, "delivered prefix has no send completion");
} /* hold */

static void
read_until(
    struct replay *r,
    size_t         target)
{
    unsigned char data[65536];
    uint64_t      deadline = now_ms() + 20000;

    evpl_test_abort_if(r->fd < 0 || target > r->queued, "invalid peer read obligation");
    while (r->received < target) {
        size_t length = target - r->received;
        if (length > sizeof(data)) {
            length = sizeof(data);
        }
        int    n;
#ifdef HAVE_TLS
        if (r->tls) {
            n = SSL_read(r->tls, data, length);
            if (n <= 0) {
                int error = SSL_get_error(r->tls, n);
                evpl_test_abort_if(error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE,
                                   "TLS read failed before expected prefix: %d", error);
            }
        } else
#endif /* ifdef HAVE_TLS */
        {
            n = recv(r->fd, data, length, 0);
            evpl_test_abort_if(n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK),
                               "peer closed before expected prefix");
        }
        if (n > 0) {
            for (int j = 0; j < n; j++) {
                evpl_test_abort_if(data[j] != payload(r->received + j, r->serial),
                                   "wrong byte at %zu", r->received + j);
            }
            r->received += n;
        }
        progress(r, deadline);
    }
} /* read_until */

static void
check_buffers(
    struct replay *r,
    int            release)
{
    for (unsigned int i = 0; i < r->count; i++) {
        struct buffer *b = &r->buffers[i];
        evpl_test_abort_if(atomic_load(&b->ref.refcnt_atomic) != (r->take ? 0 : 1) ||
                           b->released != (r->take ? 1 : 0), "transport retained or prematurely freed buffer %u", i);
        if (!r->take) {
            for (unsigned int j = 0; j < VECTOR_BYTES; j++) {
                evpl_test_abort_if(b->data[j] != payload((size_t) i * VECTOR_BYTES + j, r->serial),
                                   "borrowed buffer mutated");
            }
            if (release) {
                evpl_iovec_release(r->evpl, &r->iov[i]);
                evpl_test_abort_if(b->released != 1, "application reference not released");
            }
        }
    }
    if (release) {
        r->count = 0;
    }
} /* check_buffers */

static void
close_peer(
    struct replay *r,
    int            reset)
{
#ifdef HAVE_TLS
    if (r->tls) {
        SSL_free(r->tls);
        r->tls = NULL;
    }
#endif /* ifdef HAVE_TLS */
    if (r->fd >= 0) {
        if (reset) {
            struct linger linger = { .l_onoff = 1, .l_linger = 0 };
            evpl_test_abort_if(setsockopt(r->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)), "linger failed");
        }
        close(r->fd);
        r->fd = -1;
    }
} /* close_peer */

static void
await_close(struct replay *r)
{
    uint64_t deadline = now_ms() + 15000;

    while (!r->disconnected) {
        progress(r, deadline);
    }
    /* DISCONNECTED precedes deferred destruction in some adapters. */
    for (int i = 0; i < 16; i++) {
        progress(r, deadline);
    }
    check_buffers(r, 1);
    close_peer(r, 0);
} /* await_close */

static void
cleanup(struct replay *r)
{
    if (r->bind) {
        evpl_close(r->evpl, r->bind);
        await_close(r);
    }
} /* cleanup */

int
main(void)
{
    signal(SIGPIPE, SIG_IGN);
    struct replay              r      = { .fd = -1 };
    struct evpl_global_config *config = evpl_global_config_init();
    test_evpl_set_core_mech(config);
    test_mbt_tls_config(config);
    evpl_init(config);
    struct evpl_thread_config *thread = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(thread, 0);
    evpl_thread_config_set_poll_mode(thread, getenv("EVPL_TEST_INTERRUPT") ? 0 : 1);
    r.evpl    = test_mbt_create(thread);
    r.buffers = calloc(MAX_VECTORS, sizeof(*r.buffers));
    r.iov     = calloc(MAX_VECTORS, sizeof(*r.iov));
    evpl_test_abort_if(!r.buffers || !r.iov, "ledger allocation failed");
#ifdef HAVE_TLS
    if (getenv("EVPL_TEST_TLS_MODE")) {
        r.tls_context = peer_context();
    }
#endif /* ifdef HAVE_TLS */
    for (size_t i = 0; i < sizeof(pressure_steps) / sizeof(pressure_steps[0]); i++) {
        const struct pressure_step *s = &pressure_steps[i];
        fprintf(stderr, "pressure step %zu op %d\n", i, s->op);
        switch (s->op) {
            case pressure_Reset: cleanup(&r); break;
            case pressure_Connect: connect_peer(&r, s->take); break;
            case pressure_Queue: queue_burst(&r); break;
            case pressure_Hold: hold(&r); break;
            case pressure_Prefix: read_until(&r, s->read * (BURST_BYTES / 4)); break;
            case pressure_Drain: {
                read_until(&r, r.queued);
                uint64_t deadline = now_ms() + 15000;
                while (r.sent != r.queued) {
                    progress(&r, deadline);
                }
                if (s->finishing) {
                    await_close(&r);
                } else {
                    check_buffers(&r, 0);
                }
                break;
            }
            case pressure_Finish: evpl_finish(r.evpl, r.bind); break;
            case pressure_Close: evpl_close(r.evpl, r.bind); await_close(&r); break;
            case pressure_PeerClose: close_peer(&r, 1); await_close(&r); break;
            default: abort();
        } /* switch */
        if (s->op != pressure_Reset) {
            evpl_test_abort_if(r.queued != s->queued * BURST_BYTES ||
                               r.received != s->read * (BURST_BYTES / 4) || !!r.bind != s->live,
                               "implementation differs from pressure model at step %zu", i);
        }
    }
    cleanup(&r);
    test_mbt_destroy(r.evpl);
#ifdef HAVE_TLS
    SSL_CTX_free(r.tls_context);
#endif /* ifdef HAVE_TLS */
    free(r.iov);
    free(r.buffers);
    return 0;
} /* main */
