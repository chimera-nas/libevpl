// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <openssl/err.h>
#include "core/evpl.h"
#include "core/logging.h"
#include "core/tls/openssl.h"
#include "core/tls/engine.h"

struct evpl_tls_engine { SSL *ssl; };

struct evpl_tls_engine *
evpl_tls_engine_create(
    struct evpl *evpl,
    int          server)
{
    struct evpl_tls_engine *engine = evpl_zalloc(sizeof(*engine));
    BIO                    *input = BIO_new(BIO_s_mem()), *output = BIO_new(BIO_s_mem());

    evpl_core_abort_if(!input || !output, "TLS BIO allocation failed");
    engine->ssl = evpl_tls_session_create(evpl, server);
    BIO_set_mem_eof_return(input, -1);
    BIO_set_mem_eof_return(output, -1);
    SSL_set_bio(engine->ssl, input, output);
    if (server) {
        SSL_set_accept_state(engine->ssl);
    } else {
        SSL_set_connect_state(engine->ssl);
    }
    return engine;
} /* evpl_tls_engine_create */

void
evpl_tls_engine_free(struct evpl_tls_engine *engine)
{
    if (engine) {
        SSL_free(engine->ssl);
        evpl_free(engine);
    }
} /* evpl_tls_engine_free */

int
evpl_tls_engine_input(
    struct evpl_tls_engine *engine,
    const void             *data,
    unsigned int            length)
{
    return BIO_write(SSL_get_rbio(engine->ssl), data, (int) length);
} /* evpl_tls_engine_input */

int
evpl_tls_engine_output(
    struct evpl_tls_engine *engine,
    void                   *data,
    unsigned int            length)
{
    return BIO_read(SSL_get_wbio(engine->ssl), data, (int) length);
} /* evpl_tls_engine_output */

static int
evpl_tls_engine_result(
    struct evpl_tls_engine *engine,
    int                     result)
{
    int error;

    if (result > 0) {
        return 1;
    }
    error = SSL_get_error(engine->ssl, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : -1;
} /* evpl_tls_engine_result */

int
evpl_tls_engine_handshake(struct evpl_tls_engine *engine)
{
    ERR_clear_error();
    return evpl_tls_engine_result(engine, SSL_do_handshake(engine->ssl));
} /* evpl_tls_engine_handshake */

int
evpl_tls_engine_read(
    struct evpl_tls_engine *engine,
    void                   *data,
    size_t                  capacity,
    size_t                 *length)
{
    ERR_clear_error();
    return evpl_tls_engine_result(engine, SSL_read_ex(engine->ssl, data, capacity, length));
} /* evpl_tls_engine_read */

int
evpl_tls_engine_write(
    struct evpl_tls_engine *engine,
    const void             *data,
    size_t                  length,
    size_t                 *written)
{
    ERR_clear_error();
    return evpl_tls_engine_result(engine, SSL_write_ex(engine->ssl, data, length, written));
} /* evpl_tls_engine_write */

void
evpl_tls_engine_shutdown(struct evpl_tls_engine *engine)
{
    ERR_clear_error();
    SSL_shutdown(engine->ssl);
} /* evpl_tls_engine_shutdown */

int
evpl_tls_engine_alpn(
    struct evpl_tls_engine *engine,
    char                   *buf,
    int                     size)
{
    const unsigned char *value;
    unsigned int         length;

    SSL_get0_alpn_selected(engine->ssl, &value, &length);
    if (size > 0) {
        unsigned int copy = length < (unsigned int) size ? length : (unsigned int) size - 1;
        if (copy) {
            memcpy(buf, value, copy);
        }
        buf[copy] = 0;
    }
    return (int) length;
} /* evpl_tls_engine_alpn */
