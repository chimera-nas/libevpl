// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <utlist.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/evpl_shared.h"
#include "core/tls/tls.h"

extern struct evpl_shared *evpl_shared;

#define evpl_tls_debug(...) evpl_debug("tls", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_tls_info(...)  evpl_info("tls", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_tls_error(...) evpl_error("tls", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_tls_fatal(...) evpl_fatal("tls", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_tls_abort(...) evpl_abort("tls", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_tls_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "tls", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_tls_abort_if(cond, ...) \
        evpl_abort_if(cond, "tls", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_tls_datagram {
    struct evpl_iovec         iovec;
    struct evpl_tls_datagram *next;
};

struct evpl_accepted_tls {
    int fd;
};

enum evpl_tls_state {
    EVPL_TLS_STATE_CONNECTING,
    EVPL_TLS_STATE_HANDSHAKING,
    EVPL_TLS_STATE_CONNECTED,
    EVPL_TLS_STATE_CLOSING,
};

struct evpl_tls {
    struct evpl_event         event;
    int                       fd;
    SSL                      *ssl;
    enum evpl_tls_state state;
    int                       is_server;
    int                       is_attached;
    int                       ktls_checked;
    struct evpl_tls_datagram *free_datagrams;
    struct evpl_iovec         recv1;
    struct evpl_iovec         recv2;
};

#define evpl_event_tls(eventp) container_of((eventp), struct evpl_tls, event)

struct evpl_tls_shared {
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
};

static int
evpl_tls_generate_self_signed_cert(SSL_CTX *ctx)
{
    EVP_PKEY     *pkey     = NULL;
    X509         *cert     = NULL;
    X509_NAME    *name     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int           rc       = 0;

    pkey = EVP_PKEY_new();
    evpl_tls_abort_if(!pkey, "Failed to create private key");

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    evpl_tls_abort_if(!pkey_ctx, "Failed to create RSA key context");

    rc = EVP_PKEY_keygen_init(pkey_ctx);
    evpl_tls_abort_if(rc <= 0, "Failed to initialize key generation");

    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048);
    evpl_tls_abort_if(rc <= 0, "Failed to set RSA key size");

    rc = EVP_PKEY_keygen(pkey_ctx, &pkey);
    evpl_tls_abort_if(rc <= 0, "Failed to generate RSA key");

    cert = X509_new();
    evpl_tls_abort_if(!cert, "Failed to create certificate");

    rc = X509_set_version(cert, 2);
    evpl_tls_abort_if(rc <= 0, "Failed to set certificate version");

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "localhost", -1, -1, 0);

    X509_set_issuer_name(cert, name);

    X509V3_CTX      ctx_v3;
    X509V3_set_ctx(&ctx_v3, cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    rc = X509_sign(cert, pkey, EVP_sha256());
    evpl_tls_abort_if(rc <= 0, "Failed to sign certificate");

    rc = SSL_CTX_use_certificate(ctx, cert);
    evpl_tls_abort_if(rc <= 0, "Failed to use certificate in SSL context");

    rc = SSL_CTX_use_PrivateKey(ctx, pkey);
    evpl_tls_abort_if(rc <= 0, "Failed to use private key in SSL context");

    rc = SSL_CTX_check_private_key(ctx);
    evpl_tls_abort_if(rc <= 0, "Private key does not match certificate");

    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (cert) {
        X509_free(cert);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return rc;
} /* evpl_tls_generate_self_signed_cert */

static SSL_CTX *
evpl_tls_create_ctx(int is_server)
{
    SSL_CTX                   *ctx;
    struct evpl_global_config *config = evpl_shared->config;
    int                        rc;

    ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    evpl_tls_abort_if(!ctx, "Failed to create SSL context");

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Enable kTLS if configured */
    if (config->tls_ktls_enabled) {
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    }

    /* Set cipher list if configured */
    if (config->tls_cipher_list) {
        rc = SSL_CTX_set_cipher_list(ctx, config->tls_cipher_list);
        evpl_tls_abort_if(rc <= 0, "Failed to set cipher list: %s", config->tls_cipher_list);
    } else if (config->tls_ktls_enabled) {
        /* Default cipher list for kTLS */
        rc = SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
        evpl_tls_abort_if(rc <= 0, "Failed to set cipher list: AES128-GCM-SHA256");
    }

    if (is_server) {
        SSL_CTX_set_ecdh_auto(ctx, 1);

        if (config->tls_cert_file && config->tls_key_file) {
            rc = SSL_CTX_use_certificate_file(ctx, config->tls_cert_file, SSL_FILETYPE_PEM);

            evpl_tls_abort_if(rc <= 0, "Failed to load certificate file: %s", config->tls_cert_file);

            rc = SSL_CTX_use_PrivateKey_file(ctx, config->tls_key_file, SSL_FILETYPE_PEM);

            evpl_tls_abort_if(rc <= 0, "Failed to load private key file: %s", config->tls_key_file);

            rc = SSL_CTX_check_private_key(ctx);

            evpl_tls_abort_if(rc <= 0, "Private key does not match certificate");

        } else {
            evpl_tls_info("No certificate files provided, generating self-signed certificate");
            rc = evpl_tls_generate_self_signed_cert(ctx);
            evpl_tls_abort_if(rc <= 0, "Failed to generate self-signed certificate");
        }
    }

    if (config->tls_ca_file) {
        rc = SSL_CTX_load_verify_locations(ctx, config->tls_ca_file, NULL);

        evpl_tls_abort_if(rc <= 0, "Failed to load CA file: %s", config->tls_ca_file);
    }

    if (config->tls_verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
} /* evpl_tls_create_ctx */

static void *
evpl_tls_framework_init(void)
{
    struct evpl_tls_shared *shared;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    shared = evpl_zalloc(sizeof(*shared));

    return shared;
} /* evpl_tls_framework_init */

static void
evpl_tls_framework_cleanup(void *private_data)
{
    struct evpl_tls_shared *shared = private_data;

    if (shared->client_ctx) {
        SSL_CTX_free(shared->client_ctx);
    }
    if (shared->server_ctx) {
        SSL_CTX_free(shared->server_ctx);
    }
    evpl_free(shared);
} /* evpl_tls_framework_cleanup */

static inline struct evpl_tls_datagram *
evpl_tls_datagram_alloc(
    struct evpl     *evpl,
    struct evpl_tls *t)
{
    struct evpl_tls_datagram *datagram;

    if (t->free_datagrams) {
        datagram = t->free_datagrams;
        LL_DELETE(t->free_datagrams, datagram);
    } else {
        datagram = evpl_zalloc(sizeof(*datagram));
        evpl_iovec_alloc_datagram(evpl, &datagram->iovec, evpl_shared->config->max_datagram_size);
    }

    return datagram;
} /* evpl_tls_datagram_alloc */

static inline void
evpl_tls_datagram_free(
    struct evpl              *evpl,
    struct evpl_tls          *t,
    struct evpl_tls_datagram *datagram)
{
    LL_PREPEND(t->free_datagrams, datagram);
} /* evpl_tls_datagram_free */

static int
evpl_tls_handle_ssl_error(
    struct evpl     *evpl,
    struct evpl_tls *t,
    int              ret)
{
    int err = SSL_get_error(t->ssl, ret);

    switch (err) {
        case SSL_ERROR_WANT_READ:
            evpl_event_mark_unreadable(evpl, &t->event);
            return 0;

        case SSL_ERROR_WANT_WRITE:
            evpl_event_mark_unwritable(evpl, &t->event);
            return 0;

        case SSL_ERROR_ZERO_RETURN:
            return -1;

        case SSL_ERROR_SYSCALL:
            if (ret != 0) {
                evpl_tls_error("SSL syscall error: %s", strerror(errno));
            }
            return -1;

        case SSL_ERROR_SSL:
            evpl_tls_error("SSL error: %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;

        default:
            evpl_tls_error("Unknown SSL error: %d", err);
            return -1;
    } /* switch */
} /* evpl_tls_handle_ssl_error */

static void
evpl_tls_handshake(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_tls  *t)
{
    struct evpl_notify notify;
    int                ret;

    if (t->is_server) {
        ret = SSL_accept(t->ssl);
    } else {
        ret = SSL_connect(t->ssl);
    }

    if (ret == 1) {
        t->state = EVPL_TLS_STATE_CONNECTED;
        // Initially interested in both read and write
        evpl_event_read_interest(evpl, &t->event);
        evpl_event_write_interest(evpl, &t->event);

        notify.notify_type   = EVPL_NOTIFY_CONNECTED;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);

    } else if (evpl_tls_handle_ssl_error(evpl, t, ret) < 0) {
        evpl_close(evpl, bind);
    }
} /* evpl_tls_handshake */



void
evpl_tls_read_ktls(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls   *s    = evpl_event_tls(event);
    struct evpl_bind  *bind = evpl_private2bind(s);
    struct evpl_iovec *iovec;
    struct evpl_notify notify;
    struct iovec       iov[2];
    ssize_t            res, total, remain;
    int                length, niov;

    if (unlikely(s->fd < 0)) {
        return;
    }

    if (s->recv1.length == 0) {
        if (s->recv2.length) {
            evpl_iovec_move(&s->recv1, &s->recv2);
            s->recv2.length = 0;
        } else {
            evpl_iovec_alloc_whole(evpl, &s->recv1);
        }
    }

    if (s->recv2.length == 0) {
        evpl_iovec_alloc_whole(evpl, &s->recv2);
    }

    iov[0].iov_base = s->recv1.data;
    iov[0].iov_len  = s->recv1.length;
    iov[1].iov_base = s->recv2.data;
    iov[1].iov_len  = s->recv2.length;

    total = iov[0].iov_len + iov[1].iov_len;

    res = readv(s->fd, iov, 2);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    if (s->recv1.length >= res) {
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1, res);
    } else {
        remain = res - s->recv1.length;
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1,
                               s->recv1.length);
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv2, remain);
    }

    if (bind->segment_callback) {

        iovec = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);

        while (1) {

            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                goto out;
            }

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv,
                                         length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);

        }

    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:

    if (res < total) {
        evpl_event_mark_unreadable(evpl, event);
    }

} /* evpl_tls_read_ktls */

void
evpl_tls_write_ktls(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls   *s    = evpl_event_tls(event);
    struct evpl_bind  *bind = evpl_private2bind(s);
    struct evpl_notify notify;
    struct iovec      *iov;
    int                maxiov = evpl_shared->config->max_num_iovec;
    int                niov, niov_sent, msg_sent = 0;
    ssize_t            res, total;

    if (unlikely(s->fd < 0)) {
        return;
    }

    iov = alloca(sizeof(struct iovec) * maxiov);

    niov = evpl_iovec_ring_iov(&total, iov, maxiov, &bind->iovec_send);

    if (!niov) {
        res = 0;
        goto out;
    }

    res = writev(s->fd, iov, niov);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    niov_sent = evpl_iovec_ring_consume(evpl, &bind->iovec_send, res);

    if (bind->segment_callback) {
        while (niov_sent) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (!dgram) {
                break;
            }

            if (dgram->niov > niov_sent) {
                dgram->niov -= niov_sent;
                break;
            }

            niov_sent -= dgram->niov;
            msg_sent++;
            evpl_dgram_ring_remove(&bind->dgram_send);
        }
    }

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }

    if (res && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = res;
        notify.sent.msgs     = msg_sent;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:

    if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_event_write_disinterest(evpl, event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }

} /* evpl_tls_write_ktls */

void
evpl_tls_attach_ssl(struct evpl_tls *t)
{
    SSL_set_fd(t->ssl, t->fd);
    t->is_attached = 1;
} /* evpl_tls_attach_ssl */

void
evpl_tls_read(
    struct evpl       *evpl,
    struct evpl_event *event);

void
evpl_tls_write(
    struct evpl       *evpl,
    struct evpl_event *event);

void
evpl_tls_event_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls  *t    = evpl_event_tls(event);
    struct evpl_bind *bind = evpl_private2bind(t);

    if (unlikely(t->fd < 0)) {
        return;
    }

    evpl_close(evpl, bind);
}     /* evpl_tls_event_error */

void
evpl_tls_check_ktls(
    struct evpl     *evpl,
    struct evpl_tls *t)
{
    int ktls_rx, ktls_tx;

    t->ktls_checked = 1;

    ktls_rx = BIO_get_ktls_recv(SSL_get_rbio(t->ssl)) == 1;
    ktls_tx = BIO_get_ktls_send(SSL_get_wbio(t->ssl)) == 1;

    evpl_event_update_callbacks(evpl, &t->event,
                                ktls_rx ? evpl_tls_read_ktls : evpl_tls_read,
                                ktls_tx ? evpl_tls_write_ktls : evpl_tls_write,
                                evpl_tls_event_error);
} /* evpl_tls_check_ktls */

void
evpl_tls_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls   *t    = evpl_event_tls(event);
    struct evpl_bind  *bind = evpl_private2bind(t);
    struct evpl_iovec *iovec;
    struct evpl_notify notify;
    ssize_t            res;
    int                length, niov;

    if (unlikely(t->fd < 0)) {
        return;
    }

    if (!t->is_attached) {
        evpl_tls_attach_ssl(t);
    }

    if (t->state == EVPL_TLS_STATE_HANDSHAKING) {
        evpl_tls_handshake(evpl, bind, t);
        return;
    }

    if (t->state != EVPL_TLS_STATE_CONNECTED) {
        return;
    }

    if (t->recv1.length == 0) {
        evpl_iovec_alloc_whole(evpl, &t->recv1);
    }

    res = SSL_read(t->ssl, evpl_iovec_data(&t->recv1), evpl_iovec_length(&t->recv1));

    if (res <= 0) {
        if (evpl_tls_handle_ssl_error(evpl, t, res) < 0) {
            evpl_close(evpl, bind);
        }
        return;
    }

    if (evpl_shared->config->tls_ktls_enabled && !t->ktls_checked) {
        evpl_tls_check_ktls(evpl, t);
    }

    evpl_iovec_ring_append(evpl, &bind->iovec_recv, &t->recv1, res);

    if (bind->segment_callback) {
        iovec = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);

        while (1) {
            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (length == 0 || evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                return;
            }

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv, length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }
    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_tls_read */

void
evpl_tls_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls   *t    = evpl_event_tls(event);
    struct evpl_bind  *bind = evpl_private2bind(t);
    struct evpl_notify notify;
    struct iovec       iov;
    int                niov, niov_sent, msg_sent = 0;
    ssize_t            res;


    if (unlikely(t->fd < 0)) {
        return;
    }

    if (!t->is_attached) {
        evpl_tls_attach_ssl(t);
    }


    if (t->state == EVPL_TLS_STATE_HANDSHAKING) {
        evpl_tls_handshake(evpl, bind, t);
        return;
    }

    if (t->state != EVPL_TLS_STATE_CONNECTED) {
        return;
    }

    niov = evpl_iovec_ring_iov(&res, &iov, 1, &bind->iovec_send);

    if (!niov) {
        evpl_event_write_disinterest(evpl, &t->event);
        return;
    }


    res = SSL_write(t->ssl, iov.iov_base, iov.iov_len);

    if (res <= 0) {
        if (evpl_tls_handle_ssl_error(evpl, t, res) < 0) {
            evpl_close(evpl, bind);
        }
        return;
    }

    if (evpl_shared->config->tls_ktls_enabled && !t->ktls_checked) {
        evpl_tls_check_ktls(evpl, t);
    }

    niov_sent = (res == iov.iov_len) ? 1 : 0;

    evpl_iovec_ring_consume(evpl, &bind->iovec_send, res);

    if (bind->segment_callback) {
        if (niov_sent) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (dgram) {

                if (dgram->niov) {
                    dgram->niov--;
                } else {
                    msg_sent++;
                    evpl_dgram_ring_remove(&bind->dgram_send);
                }
            }
        }
    }

    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = res;
        notify.sent.msgs     = msg_sent;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_event_write_disinterest(evpl, &t->event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }
} /* evpl_tls_write */

void
evpl_accept_tls(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_tls          *ls          = evpl_event_tls(event);
    struct evpl_bind         *listen_bind = evpl_private2bind(ls);
    struct evpl_address      *remote_addr;
    struct evpl_accepted_tls *accepted_tls;
    int                       fd;

    while (1) {
        remote_addr          = evpl_address_alloc();
        remote_addr->addrlen = sizeof(remote_addr->sa);

        fd = accept(ls->fd, remote_addr->addr, &remote_addr->addrlen);

        if (fd < 0) {
            evpl_event_mark_unreadable(evpl, event);
            evpl_free(remote_addr);
            return;
        }

        accepted_tls     = evpl_zalloc(sizeof(*accepted_tls));
        accepted_tls->fd = fd;

        listen_bind->accept_callback(evpl, listen_bind, remote_addr, accepted_tls, listen_bind->private_data);
    }
} /* evpl_accept_tls */

static inline void
evpl_tls_init(
    struct evpl     *evpl,
    struct evpl_tls *t,
    int              fd,
    int              is_server,
    int              is_listen)
{
    struct evpl_tls_shared *shared = evpl_framework_private(evpl, EVPL_FRAMEWORK_TLS);
    int                     flags, rc, yes = 1;
    SSL_CTX                *ssl_ctx;

    evpl_tls_abort_if(!shared, "TLS framework not initialized");

    t->fd        = fd;
    t->is_server = is_server;

    if (is_listen) {
        t->state = EVPL_TLS_STATE_CONNECTED;
    } else {
        t->state = EVPL_TLS_STATE_HANDSHAKING;
    }

    if (is_server) {
        if (!shared->server_ctx) {
            shared->server_ctx = evpl_tls_create_ctx(1);
        }
        ssl_ctx = shared->server_ctx;
    } else {
        if (!shared->client_ctx) {
            shared->client_ctx = evpl_tls_create_ctx(0);
        }
        ssl_ctx = shared->client_ctx;
    }

    t->ssl          = SSL_new(ssl_ctx);
    t->is_attached  = 0;
    t->ktls_checked = 0;

    evpl_tls_abort_if(!t->ssl, "Failed to create SSL object");

    flags = fcntl(t->fd, F_GETFL, 0);
    evpl_tls_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(errno));

    rc = fcntl(t->fd, F_SETFL, flags | O_NONBLOCK);
    evpl_tls_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(errno));

    if (is_listen) {
        rc = setsockopt(t->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        evpl_tls_abort_if(rc, "Failed to set socket options: %s", strerror(errno));

        evpl_add_event(evpl, &t->event, t->fd, evpl_accept_tls, NULL, NULL);

        evpl_event_read_interest(evpl, &t->event);

    } else {
        rc = setsockopt(t->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        evpl_tls_abort_if(rc, "Failed to set TCP_NODELAY on socket");

        evpl_add_event(evpl, &t->event, t->fd,
                       evpl_tls_read,
                       evpl_tls_write,
                       evpl_tls_event_error);

        evpl_event_read_interest(evpl, &t->event);
        evpl_event_write_interest(evpl, &t->event);
    }
} /* evpl_tls_init */

void
evpl_tls_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{

    struct evpl_tls *t = evpl_bind_private(bind);
    int              rc;

    t->fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);
    evpl_tls_abort_if(t->fd < 0, "Failed to create tcp socket: %s", strerror(errno));

    evpl_tls_init(evpl, t, t->fd, 0, 0);

    rc = connect(t->fd, bind->remote->addr, bind->remote->addrlen);
    evpl_tls_abort_if(rc < 0 && errno != EINPROGRESS, "Failed to connect tcp socket: %s", strerror(errno));

} /* evpl_tls_connect */

void
evpl_tls_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_tls          *t            = evpl_bind_private(bind);
    struct evpl_accepted_tls *accepted_tls = accepted;
    int                       fd           = accepted_tls->fd;
    struct sockaddr_storage   ss;
    socklen_t                 sslen = sizeof(ss);
    int                       rc;

    evpl_free(accepted_tls);

    rc = getsockname(fd, (struct sockaddr *) &ss, &sslen);

    evpl_tls_abort_if(rc < 0, "getsockname failed: %s", strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    evpl_tls_init(evpl, t, fd, 1, 0);

} /* evpl_tls_attach */

void
evpl_tls_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_tls *t = evpl_bind_private(listen_bind);
    int              rc;

    t->fd = socket(listen_bind->local->addr->sa_family, SOCK_STREAM, 0);
    evpl_tls_abort_if(t->fd < 0, "Failed to create tcp listen socket: %s", strerror(errno));

    rc = bind(t->fd, listen_bind->local->addr, listen_bind->local->addrlen);
    evpl_tls_abort_if(rc < 0, "Failed to bind listen socket: %s", strerror(errno));

    rc = listen(t->fd, evpl_shared->config->max_pending);
    evpl_tls_fatal_if(rc, "Failed to listen on listener fd");

    evpl_tls_init(evpl, t, t->fd, 1, 1);
} /* evpl_tls_listen */

void
evpl_tls_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tls *t = evpl_bind_private(bind);

    if (t->ssl && t->state == EVPL_TLS_STATE_CONNECTED) {
        SSL_shutdown(t->ssl);
    }

    evpl_event_read_disinterest(evpl, &t->event);
    evpl_event_write_disinterest(evpl, &t->event);

    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }
} /* evpl_tls_pending_close */

void
evpl_tls_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tls          *t = evpl_bind_private(bind);
    struct evpl_tls_datagram *datagram;

    if (t->ssl) {
        SSL_free(t->ssl);
        t->ssl = NULL;
    }

    if (t->recv1.length) {
        evpl_iovec_release(evpl, &t->recv1);
        t->recv1.length = 0;
    }

    if (t->recv2.length) {
        evpl_iovec_release(evpl, &t->recv2);
        t->recv2.length = 0;
    }

    while (t->free_datagrams) {
        datagram = t->free_datagrams;
        LL_DELETE(t->free_datagrams, datagram);
        evpl_iovec_release(evpl, &datagram->iovec);
        evpl_free(datagram);
    }
} /* evpl_tls_close */

void
evpl_tls_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_tls *t = evpl_bind_private(bind);

    evpl_event_write_interest(evpl, &t->event);
} /* evpl_tls_flush */

static void *
evpl_tls_framework_create(
    struct evpl *evpl,
    void        *shared)
{
    return shared;
} /* evpl_tls_framework_create */

static void
evpl_tls_framework_destroy(
    struct evpl *evpl,
    void        *state)
{
} /* evpl_tls_framework_destroy */

struct evpl_framework evpl_framework_tls = {
    .id      = EVPL_FRAMEWORK_TLS,
    .name    = "TLS",
    .init    = evpl_tls_framework_init,
    .cleanup = evpl_tls_framework_cleanup,
    .create  = evpl_tls_framework_create,
    .destroy = evpl_tls_framework_destroy,
};

struct evpl_protocol  evpl_socket_tls = {
    .id            = EVPL_STREAM_SOCKET_TLS,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_SOCKET_TLS",
    .framework     = &evpl_framework_tls,
    .connect       = evpl_tls_connect,
    .pending_close = evpl_tls_pending_close,
    .close         = evpl_tls_close,
    .listen        = evpl_tls_listen,
    .attach        = evpl_tls_attach,
    .flush         = evpl_tls_flush,
};