// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef _WIN32
#include "tests/test_options.h"
#else  /* ifdef _WIN32 */
#include <getopt.h>
#endif /* ifdef _WIN32 */

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "core/test_log.h"
#include "test_common.h"

#include "rdma_ddp_xdr.h"
#include "rpcrdma1_xdr.h"

/* Default protocol and port */
static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8002;

/* Test data sizes */
#define READ_SIZE         4096
#define WRITE_SIZE        4093
#define REDUCE_SIZE       8192 /* Large enough to trigger reply chunk */

/*
 * A reply chunk has to hold the whole RPC reply message -- the RPC header and
 * the other result fields as well as the payload -- so advertising exactly the
 * payload size leaves it a few dozen bytes short and the responder declines it
 * and answers inline instead.  The headroom is what makes these two calls
 * actually travel in a reply chunk.
 */
#define REPLY_CHUNK_SLACK 512

/* Test data buffer */
static char test_data[REDUCE_SIZE];

/* Test state */
struct test_state {
    struct RDMA_DDP_V1 *prog;
    int                 read_done;
    int                 write_done;
    int                 reduce_done;
    int                 test_complete;
    int                 test_passed;
};

/* read_into test: a caller-armed write-chunk destination buffer and a flag the
 * reply callback sets once it has verified the data landed directly in it. */
static struct evpl_iovec read_into_dest;
static int               read_into_done;

struct multiread_state {
    struct evpl_iovec dest;
    uint32_t          count[2];
    int               rdma;
    int               expect_error;
    int               expect_untouched;
    int               done;
};

static void
decode_error_reply(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct MultiReadResponse    *reply,
    int                          status,
    void                        *private_data)
{
    evpl_test_abort_if(reply || status != EVPL_RPC2_REPLY_DECODE_ERROR, "expected decoder error callback");
    *(int *) private_data = 1;
} /* decode_error_reply */

/* Failure after a successfully cloned item must restore the source's refcount
 * on both decoder paths, including missing payload padding and arena failure. */
static void
check_decode_ownership(
    struct evpl        *evpl,
    struct RDMA_DDP_V1 *prog)
{
    uint32_t                 words[] = { 3, 1, 3, 0x11223300, 3, 1, 3, 0x44556600, 7 };
    struct evpl_iovec        input, parts[2];
    struct MultiReadResponse reply;
    xdr_dbuf                 dbuf;

    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        words[i] = htonl(words[i]);
    }
    evpl_test_abort_if(evpl_iovec_alloc(evpl, sizeof(words), 1, 1, 0, &input) != 1, "decode input alloc");
    memcpy(input.data, words, sizeof(words));
    xdr_dbuf_init(&dbuf, 4096);
    for (int split = 0; split < 2; split++) {
        for (int length = 12; length < sizeof(words); length++) {
            evpl_iovec_clone_segment(&parts[0], &input, 0, split ? 7 : length);
            if (split) {
                evpl_iovec_clone_segment(&parts[1], &input, 7, length - 7);
            }
            unsigned int refs = evpl_iovec_get_ref(&input)->refcnt;
            xdr_dbuf_reset(&dbuf);
            int          rc = unmarshall_MultiReadResponse(&reply, parts, split + 1, NULL, &dbuf);
            evpl_test_abort_if(rc >= 0, "accepted truncated response (%d bytes, split %d)", length, split);
            evpl_test_abort_if(evpl_iovec_get_ref(&input)->refcnt != refs, "partial decoder retained clones");
            evpl_iovecs_release(evpl, parts, split + 1);
        }
        evpl_iovec_clone_segment(&parts[0], &input, 0, split ? 7 : sizeof(words));
        if (split) {
            evpl_iovec_clone_segment(&parts[1], &input, 7, sizeof(words) - 7);
        }
        unsigned int refs = evpl_iovec_get_ref(&input)->refcnt;
        for (int size = 0; size < 160; size += 8) {
            xdr_dbuf_reset(&dbuf);
            dbuf.size = size;
            int rc = unmarshall_MultiReadResponse(&reply, parts, split + 1, NULL, &dbuf);
            if (rc >= 0) {
                for (int i = 0; i < 2; i++) {
                    evpl_iovecs_release(evpl, reply.reads[i].data.iov, reply.reads[i].data.niov);
                }
            }
            evpl_test_abort_if(evpl_iovec_get_ref(&input)->refcnt != refs, "arena failure retained clones");
        }
        dbuf.size = 4096;
        evpl_iovecs_release(evpl, parts, split + 1);
    }
    xdr_dbuf_reset(&dbuf);
    unsigned int refs      = evpl_iovec_get_ref(&input)->refcnt;
    int          completed = 0;
    int          rc        = prog->rpc2.recv_reply_dispatch(evpl, NULL, &dbuf, 4, NULL, NULL,
                                                            &input, 1, sizeof(words) + 4, 0, decode_error_reply, &
                                                            completed);
    evpl_test_abort_if(rc || !completed || evpl_iovec_get_ref(&input)->refcnt != refs,
                       "trailing reply data retained clones or missed callback");
    xdr_dbuf_destroy(&dbuf);
    evpl_iovec_release(evpl, &input);
} /* check_decode_ownership */

struct raw_probe {
    int      connected;
    int      done;
    int      rdma_error;
    uint32_t rpc_status;
    uint32_t write_segments;
};

static void
raw_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct raw_probe *state = private_data;

    if (notify->notify_type == EVPL_NOTIFY_CONNECTED) {
        state->connected = 1;
    } else if (notify->notify_type == EVPL_NOTIFY_RECV_MSG) {
        struct rdma_msg reply;
        xdr_dbuf        dbuf;
        uint8_t         data[16384];
        int             length = 0;
        xdr_dbuf_init(&dbuf, 4096);
        int             offset = unmarshall_rdma_msg(&reply, notify->recv_msg.iovec, notify->recv_msg.niov, NULL, &dbuf)
        ;
        evpl_test_abort_if(offset < 0, "raw reply transport header invalid");
        state->rdma_error = reply.rdma_body.proc == RDMA_ERROR;
        if (state->rdma_error) {
            evpl_test_abort_if(reply.rdma_body.rdma_error.err != ERR_CHUNK, "expected ERR_CHUNK");
        } else {
            evpl_test_abort_if(reply.rdma_body.proc != RDMA_MSG, "expected inline reply");
            struct xdr_write_list *writes = reply.rdma_body.rdma_msg.rdma_writes;
            state->write_segments = writes ? writes->entry.num_target : UINT32_MAX;
            if (writes) {
                for (unsigned int i = 0; i < writes->entry.num_target; i++) {
                    evpl_test_abort_if(writes->entry.target[i].length, "zero-capacity Write offer was used");
                }
            }
            for (int i = 0; i < notify->recv_msg.niov; i++) {
                struct evpl_iovec *iov = &notify->recv_msg.iovec[i];
                evpl_test_abort_if(length + iov->length > sizeof(data), "oversized raw reply");
                memcpy(data + length, iov->data, iov->length);
                length += iov->length;
            }
            evpl_test_abort_if(length < offset + 24, "short raw RPC reply");
            uint32_t status;
            memcpy(&status, data + offset + 20, sizeof(status));
            state->rpc_status = ntohl(status);
        }
        evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
        xdr_dbuf_destroy(&dbuf);
        state->done = 1;
    }
} /* raw_callback */

/* A plain registered-memory peer can describe offers that the generated client
 * never emits. Valid keys distinguish admission failures from provider errors;
 * separate bad-key cases exercise read failure draining. */
static void
check_raw_chunks(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint,
    int                   rdma)
{
    struct raw_probe  state = { 0 };

    if (!rdma) {
        return;
    }
    struct evpl_bind *bind = evpl_connect(evpl, proto, NULL, endpoint, raw_callback, NULL, &state);
    evpl_test_abort_if(!bind, "raw connection failed");
    while (!state.connected) {
        evpl_continue(evpl);
    }
    struct evpl_iovec source;
    uint32_t          key;
    uint64_t          address;
    evpl_test_abort_if(evpl_iovec_alloc(evpl, WRITE_SIZE, 1, 1, 0, &source) != 1, "raw source alloc");
    memcpy(source.data, test_data, WRITE_SIZE);
    evpl_rdma_get_address(evpl, bind, &source, &key, &address);
    for (int scenario = 0; scenario < 23; scenario++) {
        uint32_t wire[32768], n = 0;
#define WORD(value) wire[n++] = htonl(value)
        WORD(0xabc000 + scenario); WORD(1); WORD(1); WORD(0);
        int      reads = scenario >= 4;
        int      valid = scenario == 13 || scenario == 19 || scenario == 22;
        int      count = scenario == 20 ? 4095 : scenario == 21 ? 5000 : scenario == 8 ? 17 : valid ? 16 : scenario == 7
            || scenario == 9 || scenario == 18 ? 2
        : 1;
        uint32_t segment_offset = 0;
        if (reads) {
            for (int j = 0; j < count; j++) {
                uint32_t position = scenario == 4 ? 36 : scenario == 5 ? 60 : scenario == 6 ? 55 :
                    scenario == 7 && j ? 52 : 56;
                uint32_t len = scenario == 16 ? 0 : scenario == 9 ? UINT32_MAX : scenario == 10 ? 0x40000000 :
                    valid ? (j == 0 ? 0 : j == 15 ? WRITE_SIZE - segment_offset : 257) : 1;
                uint64_t addr = scenario == 11 ? UINT64_MAX : address + segment_offset;
                WORD(1); WORD(position); WORD((valid || (scenario >= 4 && scenario <= 8) || scenario == 20 || (scenario
                                                                                                               == 18 &&
                                                                                                               !j)) ?
                                              key : 0xdeadbeef); WORD(len);
                WORD(addr >> 32); WORD(addr);
                segment_offset += len;
            }
        }
        WORD(0);
        if (!reads && scenario != 0) {
            WORD(1); WORD(scenario == 1 ? 0 : 2);
            if (scenario != 1) {
                for (int j = 0; j < 2; j++) {
                    WORD(0xdeadbeef); WORD(0); WORD(0); WORD(0);
                }
            }
            WORD(0);
        } else {
            WORD(0);
        }
        WORD(0);
        WORD(0xabc000 + scenario); WORD(0); WORD(2); WORD(0x20250001); WORD(1);
        WORD(scenario == 12 ? 999 : reads ? 2 : 4);
        WORD(0); WORD(0); WORD(0); WORD(0);
        if (reads) {
            WORD(0); WORD(0); WORD(WRITE_SIZE); WORD(WRITE_SIZE);
        } else {
            WORD(scenario == 3 ? 0 : 3); WORD(5); WORD(0);
        }
#undef WORD
        if (scenario == 14 || scenario == 15) {
            n = scenario == 14 ? 5 : 3;
        }
        struct evpl_iovec send;
        evpl_test_abort_if(evpl_iovec_alloc(evpl, n * 4, 1, 1, 0, &send) != 1, "raw send alloc");
        memcpy(send.data, wire, n * 4);
        state.done = 0;
        evpl_sendv(evpl, bind, &send, 1, n * 4, EVPL_SEND_FLAG_TAKE_REF);
        while (!state.done) {
            evpl_continue(evpl);
        }
        int               expected_error = scenario == 2 || (scenario >= 4 && scenario < 12) || scenario == 14 ||
            scenario == 15 || scenario == 17 || scenario == 18 || scenario == 20 || scenario == 21;
        evpl_test_abort_if(state.rdma_error != expected_error, "raw scenario %d: wrong RDMA status", scenario);
        if (!expected_error) {
            evpl_test_abort_if(state.rpc_status != (scenario == 12 ? 3 : scenario == 16 ? 4 : 0),
                               "raw scenario %d: RPC status %u", scenario,
                               state.rpc_status);
            if (!reads) {
                evpl_test_abort_if(state.write_segments != (scenario == 0 ? UINT32_MAX : scenario == 1 ? 0 : 2),
                                   "raw Write segment count changed");
            }
        }
    }
    evpl_iovec_release(evpl, &source);
    evpl_close(evpl, bind);
} /* check_raw_chunks */

/* Initialize test data with pattern */
static void
init_test_data(void)
{
    int i;

    for (i = 0; i < REDUCE_SIZE; i++) {
        test_data[i] = (char) (i & 0xFF);
    }
} /* init_test_data */

/* Verify test data pattern */
static int
verify_data(
    const char *data,
    int         offset,
    int         length)
{
    int i;

    for (i = 0; i < length; i++) {
        if (data[i] != (char) ((offset + i) & 0xFF)) {
            evpl_test_error("Data mismatch at offset %d: expected %02x, got %02x",
                            offset + i, (offset + i) & 0xFF, (unsigned char) data[i]);
            return -1;
        }
    }
    return 0;
} /* verify_data */

/* Server-side: Handle READ request */
void
server_recv_read(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct ReadRequest        *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state  *state = private_data;
    struct RDMA_DDP_V1 *prog  = state->prog;
    struct ReadResponse reply;
    xdr_iovec           iov;
    int                 rc;

    evpl_test_info("Server received READ request: offset=%llu, count=%u",
                   (unsigned long long) call->offset, call->count);

    /* Validate request */
    evpl_test_abort_if(call->offset != 0, "offset mismatch");
    evpl_test_abort_if(call->count != READ_SIZE, "count mismatch");

    /* Allocate iovec for response data */
    evpl_iovec_alloc(evpl, READ_SIZE, 1, 1, 0, &iov);
    memcpy(iov.data, test_data, READ_SIZE);
    iov.length = READ_SIZE;

    /* Prepare reply with test data */
    reply.count = READ_SIZE;
    reply.eof   = 1;
    xdr_set_ref(&reply, data, &iov, 1, READ_SIZE);

    /* Send reply */
    rc = prog->send_reply_READ(evpl, NULL, &reply, encoding);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send READ reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent READ reply: count=%u", reply.count);
} /* server_recv_read */

/* Server-side: Handle WRITE request */
void
server_recv_write(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct WriteRequest       *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state   *state = private_data;
    struct RDMA_DDP_V1  *prog  = state->prog;
    struct WriteResponse reply;
    int                  rc, i;

    evpl_test_info("Server received WRITE request: offset=%llu, count=%u, data_len=%u",
                   (unsigned long long) call->offset, call->count,
                   call->data.length);

    /* Validate request */
    evpl_test_abort_if(call->offset != 0, "offset mismatch");
    evpl_test_abort_if(call->count != WRITE_SIZE, "count mismatch");
    evpl_test_abort_if(call->data.length != WRITE_SIZE, "data length mismatch");
    evpl_test_abort_if(call->data.niov != 1, "niov mismatch");

    /* Verify the data */
    rc = verify_data(xdr_iovec_data(&call->data.iov[0]), 0, WRITE_SIZE);
    evpl_test_abort_if(rc != 0, "data verification failed");

    /*
     * Take ownership of data iovecs and release them.
     * In RDMA mode, this transfers ownership from read_chunk.
     * In TCP mode, the iovecs were already cloned for us.
     */
    evpl_rpc2_encoding_take_read_chunk(encoding, NULL, NULL);
    for (i = 0; i < call->data.niov; i++) {
        evpl_iovec_release(evpl, &call->data.iov[i]);
    }

    /* Prepare reply */
    reply.count     = WRITE_SIZE;
    reply.committed = 1;

    /* Send reply */
    rc = prog->send_reply_WRITE(evpl, NULL, &reply, encoding);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send WRITE reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent WRITE reply: count=%u", reply.count);
} /* server_recv_write */

/* Server-side: Handle REDUCE request */
void
server_recv_reduce(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct ReduceRequest      *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state    *state = private_data;
    struct RDMA_DDP_V1   *prog  = state->prog;
    struct ReduceResponse reply;
    int                   rc;

    evpl_test_info("Server received REDUCE request: response_size=%u",
                   call->response_size);

    /* Validate request */
    evpl_test_abort_if(call->response_size != REDUCE_SIZE, "response_size mismatch");

    /* Prepare large reply to trigger reply chunk - use regular opaque */
    reply.data.data = test_data;
    reply.data.len  = REDUCE_SIZE;

    /* Send reply */
    rc = prog->send_reply_REDUCE(evpl, NULL, &reply, encoding);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send REDUCE reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent REDUCE reply: data_len=%u", REDUCE_SIZE);
} /* server_recv_reduce */

struct corrupt_reply {
    struct evpl_rpc2_encoding *encoding;
    struct MultiReadRequest   *call;
};

/* Deliberately report a shorter Write chunk than the encoded first result.
* This reaches the client's chunk-length rejection after an RPC SUCCESS. */
static void
server_corrupt_chunk_length(
    const struct evpl_iovec           *iov,
    int                                niov,
    int                                total_length,
    uint32_t                           body_offset,
    const struct evpl_rpc2_rdma_chunk *write_chunk,
    void                              *private_data)
{
    struct corrupt_reply      *state    = private_data;
    struct evpl_rpc2_encoding *encoding = state->encoding;

    if (state->call->corrupt_length >= 2) {
        /* Reject the second result after claiming the first Write payload (or
         * cloning its inline reference), including caller-owned read-into. */
        uint32_t offset = body_offset + 16 + (write_chunk ? 0 : (state->call->first_count + 3) / 4 * 4);
        for (int i = 0; i < niov; i++) {
            if (offset < iov[i].length) {
                evpl_test_abort_if(offset + 4 > iov[i].length, "split test boolean");
                uint32_t bad = htonl(2);
                memcpy((char *) iov[i].data + offset, &bad, 4);
                return;
            }
            offset -= iov[i].length;
        }
        evpl_test_abort_if(1, "missing test boolean");
    }

    evpl_test_abort_if(encoding->write_chunk->length < 2,
                       "Malformed MULTIREAD needs a nonempty Write chunk");
    encoding->write_chunk->length--;
} /* server_corrupt_chunk_length */

/* One Write chunk must select only the first result, even when it is empty.
 * The odd lengths also check that inline roundup stays with the second item. */
static void
server_recv_multiread(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct MultiReadRequest   *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state       *state = private_data;
    struct MultiReadResponse reply = { 0 };
    struct evpl_iovec        iov[2];
    uint32_t                 count[2] = { call->first_count, call->second_count };
    int                      i, j, rc;

    if (call->corrupt_length >= 4 && conn->rdma) {
        struct evpl_iovec bad;
        uint32_t          header[] = { htonl(encoding->xid), htonl(call->corrupt_length == 5 ? 2 : 1), htonl(1) };
        evpl_test_abort_if(evpl_iovec_alloc(evpl, sizeof(header), 1, 1, 0, &bad) != 1, "bad header alloc");
        memcpy(bad.data, header, sizeof(header));
        evpl_sendv(evpl, conn->bind, &bad, 1, sizeof(header), EVPL_SEND_FLAG_TAKE_REF);
        /* Release the server request normally; the following complete reply
         * must be ignored once the malformed one has completed the client. */
        evpl_rpc2_send_reply_system_error(evpl, encoding);
        return;
    }
    for (i = 0; i < 2; i++) {
        evpl_test_abort_if(count[i] > REDUCE_SIZE, "MULTIREAD count too large");
        reply.reads[i].count = count[i];
        reply.reads[i].eof   = 1;
        if (count[i]) {
            rc = evpl_iovec_alloc(evpl, count[i], 1, 1, 0, &iov[i]);
            evpl_test_abort_if(rc != 1, "MULTIREAD buffer allocation failed");
            for (j = 0; j < count[i]; j++) {
                ((char *) iov[i].data)[j] = (char) ((j + 17 + 56 * i) & 0xFF);
            }
            xdr_set_ref(&reply.reads[i], data, &iov[i], 1, count[i]);
        }
    }
    struct corrupt_reply corruption = { .encoding = encoding, .call = call };
    if (call->corrupt_length >= 2 || (call->corrupt_length && conn->rdma)) {
        encoding->reply_capture_cb      = server_corrupt_chunk_length;
        encoding->reply_capture_private = &corruption;
    }
    reply.sentinel = 0x13579BDF;
    rc             = state->prog->send_reply_MULTIREAD(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc != 0, "Failed to send MULTIREAD reply: %d", rc);
} /* server_recv_multiread */

static void
client_recv_multiread(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct MultiReadResponse    *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct multiread_state *state = callback_private_data;
    struct ReadResponse    *read;
    uint32_t                offset;
    int                     i, j;

    if (state->expect_error) {
        evpl_test_abort_if(status != state->expect_error,
                           "MULTIREAD expected transport/decode error %d, got %d",
                           state->expect_error, status);
        if (state->dest.data && state->expect_untouched) {
            evpl_test_abort_if(((unsigned char *) state->dest.data)[0] != 0xCC,
                               "Short Write chunk was modified before ERR_CHUNK");
        }
        state->done = 1;
        return;
    }

    evpl_test_abort_if(status != 0 || !reply, "MULTIREAD reply error: %d", status);
    evpl_test_abort_if(reply->sentinel != 0x13579BDF, "MULTIREAD tail corrupt");

    for (i = 0; i < 2; i++) {
        read = &reply->reads[i];
        evpl_test_abort_if(read->count != state->count[i] || !read->eof ||
                           read->data.length != state->count[i],
                           "MULTIREAD result %d length or fields differ", i);
        evpl_test_abort_if(!state->count[i] && read->data.niov,
                           "Empty MULTIREAD result retains an iovec");
        offset = 0;
        for (j = 0; j < read->data.niov; j++) {
            struct evpl_iovec *iov = &read->data.iov[j];
            evpl_test_abort_if(iov->length > state->count[i] - offset,
                               "MULTIREAD result %d iovec exceeds payload", i);
            evpl_test_abort_if(verify_data(iov->data, offset + 17 + 56 * i,
                                           iov->length) != 0,
                               "MULTIREAD result %d data differs", i);
            offset += iov->length;
            if (state->rdma && i == 0) {
                evpl_test_abort_if(iov->data != state->dest.data,
                                   "First MULTIREAD did not use Write chunk");
            } else {
                evpl_test_abort_if(state->rdma && iov->data == state->dest.data,
                                   "Second MULTIREAD reused first Write chunk");
                evpl_iovec_release(evpl, iov);
            }
        }
        evpl_test_abort_if(offset != state->count[i], "MULTIREAD result incomplete");
    }
    if (state->rdma && !state->count[0]) {
        evpl_test_abort_if(((unsigned char *) state->dest.data)[0] != 0xCC,
                           "Empty first MULTIREAD let second result use Write chunk");
    }
    state->done = 1;
} /* client_recv_multiread */

static void
run_multiread(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    struct RDMA_DDP_V1    *prog,
    uint32_t               first_count,
    uint32_t               second_count,
    int                    reply_chunk,
    int                    short_chunk,
    int                    corrupt_length)
{
    struct MultiReadRequest call  = { first_count, second_count, corrupt_length };
    struct multiread_state  state = { 0 };
    int                     rc, capacity = short_chunk ? 16 : READ_SIZE;

    state.count[0]         = first_count;
    state.count[1]         = second_count;
    state.rdma             = conn->rdma;
    state.expect_untouched = short_chunk;
    state.expect_error     = !conn->rdma ? (corrupt_length >= 2 ? EVPL_RPC2_REPLY_DECODE_ERROR : 0) :
        (short_chunk ? EVPL_RPC2_REPLY_RDMA_ERROR :
         (corrupt_length ? EVPL_RPC2_REPLY_DECODE_ERROR : 0));

    /* Malformed replies use an internally owned destination: the decoder's
     * failure path, rather than this test, must release its reference. */
    if (state.rdma && (!corrupt_length || corrupt_length == 3)) {
        rc = evpl_iovec_alloc(evpl, capacity, 1, 1, 0, &state.dest);
        evpl_test_abort_if(rc != 1, "MULTIREAD destination allocation failed");
        memset(state.dest.data, 0xCC, capacity);
    }
    prog->send_call_MULTIREAD(&prog->rpc2, evpl, conn, NULL, &call, 0,
                              state.rdma ? capacity : 0,
                              state.dest.data ? &state.dest : NULL, state.dest.data ? 1 : 0,
                              reply_chunk ? REDUCE_SIZE + REPLY_CHUNK_SLACK : 0,
                              client_recv_multiread, &state);
    while (!state.done) {
        evpl_continue(evpl);
    }
    if (state.dest.data) {
        evpl_iovec_release(evpl, &state.dest);
    }
} /* run_multiread */

/* Client-side: Handle READ reply */
void
client_recv_reply_read(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct ReadResponse         *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct test_state *state = callback_private_data;
    int                rc, i;

    evpl_test_info("Client received READ reply: status=%d, count=%u, eof=%d, data_len=%u",
                   status, reply->count, reply->eof, reply->data.length);

    /* Validate reply */
    evpl_test_abort_if(status != 0, "status mismatch");
    evpl_test_abort_if(reply->count != READ_SIZE, "count mismatch");
    evpl_test_abort_if(reply->eof != 1, "eof mismatch");
    evpl_test_abort_if(reply->data.length != READ_SIZE, "data length mismatch");
    evpl_test_abort_if(reply->data.niov != 1, "niov mismatch");

    /* Verify the data */
    rc = verify_data(xdr_iovec_data(&reply->data.iov[0]), 0, READ_SIZE);
    evpl_test_abort_if(rc != 0, "data verification failed");

    /* Release the iovecs */
    for (i = 0; i < reply->data.niov; i++) {
        evpl_iovec_release(evpl, &reply->data.iov[i]);
    }

    state->read_done = 1;
    evpl_test_info("READ test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
} /* client_recv_reply_read */

/* Client-side: Handle WRITE reply */
void
client_recv_reply_write(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct WriteResponse        *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct test_state *state = callback_private_data;

    evpl_test_info("Client received WRITE reply: status=%d, count=%u, committed=%d",
                   status, reply->count, reply->committed);

    /* Validate reply */
    evpl_test_abort_if(status != 0, "status mismatch");
    evpl_test_abort_if(reply->count != WRITE_SIZE, "count mismatch");
    evpl_test_abort_if(reply->committed != 1, "committed mismatch");

    state->write_done = 1;
    evpl_test_info("WRITE test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
} /* client_recv_reply_write */

/* Client-side: Handle REDUCE reply */
void
client_recv_reply_reduce(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct ReduceResponse       *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct test_state *state = callback_private_data;
    int                rc;

    evpl_test_info("Client received REDUCE reply: status=%d, data_len=%u",
                   status, reply->data.len);

    /* Validate reply */
    evpl_test_abort_if(status != 0, "status mismatch");
    evpl_test_abort_if(reply->data.len != REDUCE_SIZE, "data length mismatch");

    /* Verify the data - regular opaque uses .data and .len */
    rc = verify_data(reply->data.data, 0, REDUCE_SIZE);
    evpl_test_abort_if(rc != 0, "data verification failed");

    /* No iovec release needed - regular opaque is managed by RPC2 */

    state->reduce_done = 1;
    evpl_test_info("REDUCE test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
} /* client_recv_reply_reduce */

/* Client-side: Handle READ reply for the read_into (armed write-chunk) test.
 * The data must have been RDMA-written straight into our armed destination
 * buffer -- so reply->data.iov[0] must reference that exact buffer (zero copy),
 * not an internally allocated one. */
void
client_recv_reply_read_into(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct ReadResponse         *reply,
    int                          status,
    void                        *callback_private_data)
{
    evpl_test_info("Client received READ_INTO reply: status=%d, count=%u, niov=%d",
                   status, reply->count, reply->data.niov);

    evpl_test_abort_if(status != 0, "read_into status mismatch");
    evpl_test_abort_if(reply->count != READ_SIZE, "read_into count mismatch");
    evpl_test_abort_if(reply->data.niov != 1, "read_into niov mismatch");

    /* Zero-copy: the reply data references our armed buffer, not a fresh one. */
    evpl_test_abort_if(xdr_iovec_data(&reply->data.iov[0]) != read_into_dest.data,
                       "read_into did not land in the caller's buffer");

    /* And the bytes actually arrived there. */
    evpl_test_abort_if(verify_data(read_into_dest.data, 0, READ_SIZE) != 0,
                       "read_into data verification failed");

    read_into_done = 1;
    evpl_test_info("READ_INTO test PASSED!");
} /* client_recv_reply_read_into */

static void
usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port]\n", prog_name);
    fprintf(stderr, "  -r protocol  Protocol to use (default: STREAM_SOCKET_TCP)\n");
    fprintf(stderr, "  -p port      Port to use (default: 8002)\n");
    exit(1);
} /* usage */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_rpc2_server  *server;
    struct evpl_rpc2_conn    *conn;
    struct evpl_rpc2_thread  *thread;
    struct evpl_endpoint     *endpoint;
    struct RDMA_DDP_V1        prog;
    struct ReadRequest        read_req;
    struct WriteRequest       write_req;
    struct ReduceRequest      reduce_req;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };
    xdr_iovec                 write_req_iov;
    int                       opt, rc;

    /* Initialize evpl first, before any evpl functions are called */
    test_evpl_config();

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "r:p:")) != -1) {
        switch (opt) {
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                usage(argv[0]);
        } /* switch */
    }

    /* Initialize test data */
    init_test_data();

    evpl = evpl_create(NULL);

    /* Initialize server program */
    RDMA_DDP_V1_init(&prog);
    prog.recv_call_READ      = server_recv_read;
    prog.recv_call_WRITE     = server_recv_write;
    prog.recv_call_REDUCE    = server_recv_reduce;
    prog.recv_call_MULTIREAD = server_recv_multiread;
    programs[0]              = &prog.rpc2;
    state.prog               = &prog;

    /* Create RPC2 server */
    server = evpl_rpc2_server_init(programs, 1);

    /* Create endpoint */
    endpoint = evpl_endpoint_create(test_address(proto, "127.0.0.1", argv[0]), port);

    /* Start listening */
    evpl_rpc2_server_start(server, proto, endpoint);

    evpl_test_info("Server listening on port %d with protocol %d", port, proto);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);

    /* Attach server to this thread */
    evpl_rpc2_server_attach(thread, server, &state);

    /* Connect to server */
    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);

    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    evpl_test_info("Client connected to server");

    /* Test 1: READ operation - uses reply chunk for DDP */
    evpl_test_info("Client sending READ request");
    read_req.offset = 0;
    read_req.count  = READ_SIZE;
    /* Enable DDP: ddp=1, no write chunk, reply chunk of READ_SIZE */
    prog.send_call_READ(&prog.rpc2, evpl, conn, NULL, &read_req, 1, 0, NULL, 0,
                        READ_SIZE + REPLY_CHUNK_SLACK,
                        client_recv_reply_read, &state);

    /* Test 2: WRITE operation - uses write chunk for DDP */
    evpl_test_info("Client sending WRITE request");
    write_req.offset = 0;
    write_req.count  = WRITE_SIZE;
    /* Allocate iovec for write data */
    evpl_iovec_alloc(evpl, WRITE_SIZE, 1, 1, 0, &write_req_iov);
    memcpy(write_req_iov.data, test_data, WRITE_SIZE);
    write_req_iov.length = WRITE_SIZE;
    xdr_set_ref(&write_req, data, &write_req_iov, 1, WRITE_SIZE);
    /* Enable DDP: ddp=1, no write chunk (write_chunk is for READ), no reply chunk */
    prog.send_call_WRITE(&prog.rpc2, evpl, conn, NULL, &write_req, 1, 0, NULL, 0, 0,
                         client_recv_reply_write, &state);

    /* Test 3: REDUCE operation - large reply to trigger reply chunk */
    evpl_test_info("Client sending REDUCE request");
    reduce_req.response_size = REDUCE_SIZE;
    /* Enable DDP: ddp=1, no write chunk, reply chunk of REDUCE_SIZE */
    prog.send_call_REDUCE(&prog.rpc2, evpl, conn, NULL, &reduce_req, 1, 0, NULL, 0,
                          REDUCE_SIZE + REPLY_CHUNK_SLACK,
                          client_recv_reply_reduce, &state);

    /* Wait for all replies */
    while (!state.test_complete) {
        evpl_continue(evpl);
    }

    /* Test 4 (RDMA only): READ_INTO -- pass a caller-owned buffer as the RDMA
     * write-chunk destination so the server RDMA-writes the reply data straight
     * into it (zero copy).  Over TCP there is no write chunk (data arrives
     * inline), so this path only applies to RDMA. */
    if (conn->rdma) {
        struct ReadRequest read_into_req;

        evpl_iovec_alloc(evpl, READ_SIZE, 1, 1, 0, &read_into_dest);
        memset(read_into_dest.data, 0, READ_SIZE);

        read_into_req.offset = 0;
        read_into_req.count  = READ_SIZE;

        /* ddp=0, max_rdma_write_chunk=READ_SIZE, write_chunk_iov=our buffer */
        prog.send_call_READ(&prog.rpc2, evpl, conn, NULL, &read_into_req, 0, READ_SIZE,
                            &read_into_dest, 1, 0,
                            client_recv_reply_read_into, &state);

        while (!read_into_done) {
            evpl_continue(evpl);
        }

        evpl_iovec_release(evpl, &read_into_dest);

        /* Regression guard: issue a normal READ right after the write-chunk
        * exchange.  The server's write-chunk reply involves a mid-receive ack
        * (OP_WRITE_REPLY) on each side; if that ack is mis-framed against the
        * following request the stream desyncs.  This must still succeed. */
        state.read_done = 0;
        read_req.offset = 0;
        read_req.count  = READ_SIZE;
        prog.send_call_READ(&prog.rpc2, evpl, conn, NULL, &read_req, 1, 0, NULL, 0,
                            READ_SIZE + REPLY_CHUNK_SLACK,
                            client_recv_reply_read, &state);
        while (!state.read_done) {
            evpl_continue(evpl);
        }
    }

    /* Two READ-like results with a single Write chunk.  Repeat over a Reply
     * chunk so actual returned Write lengths are honored for RDMA_NOMSG too. */
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 0);
    run_multiread(evpl, conn, &prog, 0, 67, 0, 0, 0);
    run_multiread(evpl, conn, &prog, 31, REDUCE_SIZE, 1, 0, 0);
    run_multiread(evpl, conn, &prog, 0, REDUCE_SIZE, 1, 0, 0);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 1, 0);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 1);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 2);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 3);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 4);
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 5);
    run_multiread(evpl, conn, &prog, 31, REDUCE_SIZE, 1, 0, 2);
    /* A transport-level refusal must leave the connection usable. */
    run_multiread(evpl, conn, &prog, 31, 67, 0, 0, 0);

    check_decode_ownership(evpl, &prog);
    check_raw_chunks(evpl, endpoint, conn->rdma);

    /* Cleanup */
    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, conn);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    /* Both TCP and RDMA modes now move iovecs (transferring ownership),
     * so caller does NOT need to release write_req_iov.
     */
    evpl_destroy(evpl);

    if (state.test_passed) {
        printf("Test PASSED\n");
        return 0;
    } else {
        printf("Test FAILED\n");
        return 1;
    }
} /* main */
