// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/tls/schannel_internal.h"

#define EVPL_TLS_INPUT_LIMIT (1024 * 1024)

struct evpl_tls_engine {
    struct evpl_schannel_shared      *shared;
    CtxtHandle                        context;
    SecPkgContext_StreamSizes         sizes;
    SecPkgContext_ApplicationProtocol alpn;
    BYTE                             *input;
    unsigned int                      input_length;
    unsigned int                      input_capacity;
    BYTE                             *output;
    unsigned int                      output_length;
    BYTE                              plain[16384];
    unsigned int                      plain_length;
    int                               server;
    int                               ready;
    int                               renegotiating;
};

struct evpl_tls_engine *
evpl_tls_engine_create(
    struct evpl *evpl,
    int          server)
{
    struct evpl_tls_engine *engine = evpl_zalloc(sizeof(*engine));

    engine->shared = evpl_schannel_credentials(evpl, server);
    engine->server = server;
    SecInvalidateHandle(&engine->context);
    return engine;
} /* evpl_tls_engine_create */

void
evpl_tls_engine_free(struct evpl_tls_engine *engine)
{
    if (!engine) {
        return;
    }
    if (SecIsValidHandle(&engine->context)) {
        DeleteSecurityContext(&engine->context);
    }
    evpl_free(engine->input);
    evpl_free(engine->output);
    SecureZeroMemory(engine->plain, sizeof(engine->plain));
    evpl_free(engine);
} /* evpl_tls_engine_free */

int
evpl_tls_engine_input(
    struct evpl_tls_engine *engine,
    const void             *data,
    unsigned int            length)
{
    if (length > EVPL_TLS_INPUT_LIMIT - engine->input_length) {
        return -1;
    }
    if (engine->input_capacity < engine->input_length + length) {
        unsigned int capacity = engine->input_length + length + 16384;
        BYTE        *input    = evpl_malloc(capacity);
        if (engine->input_length) {
            memcpy(input, engine->input, engine->input_length);
        }
        evpl_free(engine->input);
        engine->input          = input;
        engine->input_capacity = capacity;
    }
    memcpy(engine->input + engine->input_length, data, length);
    engine->input_length += length;
    return (int) length;
} /* evpl_tls_engine_input */

static void
evpl_schannel_output(
    struct evpl_tls_engine *engine,
    const void             *data,
    unsigned int            length)
{
    BYTE *output;

    if (!length) {
        return;
    }
    output = evpl_malloc(engine->output_length + length);
    if (engine->output_length) {
        memcpy(output, engine->output, engine->output_length);
    }
    memcpy(output + engine->output_length, data, length);
    evpl_free(engine->output);
    engine->output         = output;
    engine->output_length += length;
} /* evpl_schannel_output */

int
evpl_tls_engine_output(
    struct evpl_tls_engine *engine,
    void                   *data,
    unsigned int            capacity)
{
    unsigned int length = engine->output_length < capacity ? engine->output_length : capacity;

    if (length) {
        memcpy(data, engine->output, length);
        engine->output_length -= length;
        memmove(engine->output, engine->output + length, engine->output_length);
    }
    return (int) length;
} /* evpl_tls_engine_output */

static void
evpl_schannel_extra(
    struct evpl_tls_engine *engine,
    SecBuffer              *buffers,
    unsigned int            count)
{
    unsigned int i;

    for (i = 0; i < count; i++) {
        if (buffers[i].BufferType == SECBUFFER_EXTRA) {
            unsigned int remaining = buffers[i].cbBuffer;
            evpl_core_assert(remaining <= engine->input_length);
            memmove(engine->input, engine->input + engine->input_length - remaining, remaining);
            engine->input_length = remaining;
            return;
        }
    }
    engine->input_length = 0;
} /* evpl_schannel_extra */

static SECURITY_STATUS
evpl_schannel_step(
    struct evpl_tls_engine *engine,
    int                     shutdown)
{
    SecBuffer       input[3] = { 0 }, output[2] = { 0 };
    SecBufferDesc   in  = { SECBUFFER_VERSION, 2, input };
    SecBufferDesc   out = { SECBUFFER_VERSION, 2, output };

    union {
        SEC_APPLICATION_PROTOCOLS protocols;
        BYTE                      bytes[sizeof(SEC_APPLICATION_PROTOCOLS) + 256];
    } alpn;
    ULONG           flags, attributes;
    SECURITY_STATUS status;
    int             initial = !SecIsValidHandle(&engine->context);
    int             i;

    input[0].BufferType = SECBUFFER_TOKEN;
    input[0].pvBuffer   = engine->input;
    input[0].cbBuffer   = engine->input_length;
    input[1].BufferType = SECBUFFER_EMPTY;
    if (initial && evpl_schannel_alpn_length) {
        SEC_APPLICATION_PROTOCOL_LIST *list = alpn.protocols.ProtocolLists;
        memset(&alpn, 0, sizeof(alpn));
        alpn.protocols.ProtocolListsSize = (ULONG) (offsetof(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) +
                                                    evpl_schannel_alpn_length);
        list->ProtoNegoExt     = SecApplicationProtocolNegotiationExt_ALPN;
        list->ProtocolListSize = (USHORT) evpl_schannel_alpn_length;
        memcpy(list->ProtocolList, evpl_schannel_alpn, evpl_schannel_alpn_length);
        input[2].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        input[2].pvBuffer   = &alpn;
        input[2].cbBuffer   = (ULONG) offsetof(SEC_APPLICATION_PROTOCOLS, ProtocolLists) + alpn.protocols.
            ProtocolListsSize;
        in.cBuffers = 3;
    }
    output[0].BufferType = SECBUFFER_TOKEN;
    output[1].BufferType = SECBUFFER_ALERT;
    if (engine->server) {
        flags = ASC_REQ_STREAM | ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT |
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_EXTENDED_ERROR;
        if (engine->shared->verify_peer) {
            flags |= ASC_REQ_MUTUAL_AUTH;
        }
        status = AcceptSecurityContext(&engine->shared->credentials[1], initial ? NULL : &engine->context,
                                       shutdown ? NULL : &in, flags, SECURITY_NATIVE_DREP, &engine->context, &out, &
                                       attributes, NULL);
    } else {
        flags = ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MANUAL_CRED_VALIDATION |
            ISC_REQ_USE_SUPPLIED_CREDS;
        if (initial) {
            /* ALPN is permitted on the initial call, without an input token. */
            in.pBuffers = &input[2];
            in.cBuffers = evpl_schannel_alpn_length ? 1 : 0;
        }
        status = InitializeSecurityContextW(&engine->shared->credentials[0], initial ? NULL : &engine->context,
                                            NULL, flags, 0, SECURITY_NATIVE_DREP, shutdown || !in.cBuffers ? NULL : &in,
                                            0, &engine->context, &out, &attributes, NULL);
    }
    if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
        SECURITY_STATUS complete = CompleteAuthToken(&engine->context, &out);
        status = complete != SEC_E_OK ? complete : status == SEC_I_COMPLETE_NEEDED ? SEC_E_OK : SEC_I_CONTINUE_NEEDED;
    }
    if (output[0].pvBuffer) {
        evpl_schannel_output(engine, output[0].pvBuffer, output[0].cbBuffer);
    }
    for (i = 0; i < 2; i++) {
        if (output[i].pvBuffer) {
            FreeContextBuffer(output[i].pvBuffer);
        }
    }
    if (!shutdown && status != SEC_E_INCOMPLETE_MESSAGE && !(initial && !engine->server)) {
        evpl_schannel_extra(engine, input, 2);
    }
    return status;
} /* evpl_schannel_step */

int
evpl_tls_engine_handshake(struct evpl_tls_engine *engine)
{
    SECURITY_STATUS status;

    if (engine->ready && !engine->renegotiating) {
        return 1;
    }
    do {
        if ((engine->server || SecIsValidHandle(&engine->context)) && !engine->input_length && engine->renegotiating !=
            2) {
            return 0;
        }
        if (engine->renegotiating == 2) {
            engine->renegotiating = 1;
        }
        status = evpl_schannel_step(engine, 0);
        if (status == SEC_E_OK) {
            if (!evpl_schannel_verify(engine->shared, &engine->context, engine->server) ||
                QueryContextAttributes(&engine->context, SECPKG_ATTR_STREAM_SIZES, &engine->sizes) != SEC_E_OK) {
                return -1;
            }
            memset(&engine->alpn, 0, sizeof(engine->alpn));
            QueryContextAttributes(&engine->context, SECPKG_ATTR_APPLICATION_PROTOCOL, &engine->alpn);
            engine->ready         = 1;
            engine->renegotiating = 0;
            return 1;
        }
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            return 0;
        }
        if (status != SEC_I_CONTINUE_NEEDED) {
            evpl_core_error("Schannel handshake failed (0x%lx)", (unsigned long) status);
            return -1;
        }
    } while (engine->input_length);
    return 0;
} /* evpl_tls_engine_handshake */

int
evpl_tls_engine_read(
    struct evpl_tls_engine *engine,
    void                   *data,
    size_t                  capacity,
    size_t                 *length)
{
    SecBuffer       buffers[4];
    SecBufferDesc   message = { SECBUFFER_VERSION, 4, buffers };
    SECURITY_STATUS status;
    unsigned int    i;

    *length = 0;
    while (!engine->plain_length) {
        if (engine->renegotiating) {
            int result = evpl_tls_engine_handshake(engine);
            if (result <= 0) {
                return result;
            }
        }
        if (!engine->input_length) {
            return 0;
        }
        memset(buffers, 0, sizeof(buffers));
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].pvBuffer   = engine->input;
        buffers[0].cbBuffer   = engine->input_length;
        status                = DecryptMessage(&engine->context, &message, 0, NULL);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            return 0;
        }
        if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE) {
            return -1;
        }
        for (i = 0; i < 4; i++) {
            if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer) {
                if (buffers[i].cbBuffer > sizeof(engine->plain) - engine->plain_length) {
                    return -1;
                }
                memcpy(engine->plain + engine->plain_length, buffers[i].pvBuffer, buffers[i].cbBuffer);
                engine->plain_length += buffers[i].cbBuffer;
            }
        }
        evpl_schannel_extra(engine, buffers, 4);
        if (status == SEC_I_RENEGOTIATE) {
            /* Schannel can consume a TLS 1.3 post-handshake message fully and
             * still require one context update with an empty token. Waiting
             * for another network read here would strand pending writes. */
            engine->renegotiating = 2;
        }
    }
    *length = engine->plain_length < capacity ? engine->plain_length : capacity;
    memcpy(data, engine->plain, *length);
    engine->plain_length -= (unsigned int) *length;
    memmove(engine->plain, engine->plain + *length, engine->plain_length);
    return 1;
} /* evpl_tls_engine_read */

int
evpl_tls_engine_write(
    struct evpl_tls_engine *engine,
    const void             *data,
    size_t                  length,
    size_t                 *written)
{
    SecBuffer       buffers[4] = { 0 };
    SecBufferDesc   message    = { SECBUFFER_VERSION, 4, buffers };
    BYTE           *record;
    SECURITY_STATUS status;
    unsigned int    i;

    *written = 0;
    if (engine->renegotiating) {
        return 0;
    }
    if (length > engine->sizes.cbMaximumMessage) {
        length = engine->sizes.cbMaximumMessage;
    }
    record                = evpl_malloc(engine->sizes.cbHeader + length + engine->sizes.cbTrailer);
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].pvBuffer   = record;
    buffers[0].cbBuffer   = engine->sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].pvBuffer   = record + engine->sizes.cbHeader;
    buffers[1].cbBuffer   = (ULONG) length;
    memcpy(buffers[1].pvBuffer, data, length);
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].pvBuffer   = record + engine->sizes.cbHeader + length;
    buffers[2].cbBuffer   = engine->sizes.cbTrailer;
    status                = EncryptMessage(&engine->context, 0, &message, 0);
    if (status == SEC_E_OK) {
        for (i = 0; i < 3; i++) {
            evpl_schannel_output(engine, buffers[i].pvBuffer, buffers[i].cbBuffer);
        }
        *written = length;
    }
    evpl_free(record);
    return status == SEC_E_OK ? 1 : -1;
} /* evpl_tls_engine_write */

void
evpl_tls_engine_shutdown(struct evpl_tls_engine *engine)
{
    DWORD         token   = SCHANNEL_SHUTDOWN;
    SecBuffer     buffer  = { sizeof(token), SECBUFFER_TOKEN, &token };
    SecBufferDesc message = { SECBUFFER_VERSION, 1, &buffer };

    if (ApplyControlToken(&engine->context, &message) == SEC_E_OK) {
        evpl_schannel_step(engine, 1);
    }
} /* evpl_tls_engine_shutdown */

int
evpl_tls_engine_alpn(
    struct evpl_tls_engine *engine,
    char                   *buf,
    int                     size)
{
    unsigned int length = engine->alpn.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success ? engine->alpn
        .ProtocolIdSize : 0;

    if (size > 0) {
        unsigned int copy = length < (unsigned int) size ? length : (unsigned int) size - 1;
        memcpy(buf, engine->alpn.ProtocolId, copy);
        buf[copy] = 0;
    }
    return (int) length;
} /* evpl_tls_engine_alpn */
