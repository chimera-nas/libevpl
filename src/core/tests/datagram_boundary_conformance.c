// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <time.h>
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "datagram_boundary_cases.h"

#define BUFFER_SIZE   32768
#define BURST         256
#define MAX_MESSAGES  (3 * BURST)
#define MAX_FRAGMENTS 65
#define OFFSET        7

struct message {
    struct evpl_iovec base;
    int               length, received;
};
struct replay {
    int                           warming, warm_received, warm_sent;
    struct evpl                  *sender, *receiver;
    struct evpl_bind             *send_bind, *recv_bind;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *destination;
    struct message                messages[MAX_MESSAGES];
    enum evpl_protocol_id protocol;
    int                           queued, received, sent, connected, disconnected, serial, cancel_at, cancelled;
    size_t                        queued_bytes, sent_bytes;
};
static struct replay r;

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

static void
pump(uint64_t deadline)
{
    evpl_test_abort_if(now_ms() > deadline, "datagram timeout: queued=%d received=%d sent=%d disconnected=%d",
                       r.queued, r.received, r.sent, r.disconnected);
    evpl_continue(r.sender);
    evpl_continue(r.receiver);
} /* pump */

static unsigned char
byte(
    int id,
    int offset)
{
    unsigned int token = ((unsigned int) r.serial << 16) | id;

    return offset < 4 ? (token >> (offset * 8)) & 255 : (id * 31 + r.serial * 19 + offset * 7);
} /* byte */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *arg)
{
    int receiving = evpl == r.receiver;

    if (r.warming && event->notify_type == EVPL_NOTIFY_SENT) {
        evpl_test_abort_if(receiving || event->notify_status || event->sent.bytes != 1 || event->sent.msgs != 1 ||
                           r.warm_sent++, "invalid readiness send completion");
        return;
    }
    if (r.warming && event->notify_type == EVPL_NOTIFY_RECV_MSG) {
        evpl_test_abort_if(!receiving || event->recv_msg.length != 1 || event->recv_msg.niov != 1 ||
                           *(unsigned char *) event->recv_msg.iovec[0].data != 0x5a || r.warm_received++,
                           "invalid readiness message");
        evpl_iovecs_release(evpl, event->recv_msg.iovec, event->recv_msg.niov);
        return;
    }
    if (event->notify_type == EVPL_NOTIFY_CONNECTED) {
        evpl_test_abort_if(event->notify_status, "connect failed");
        r.connected++;
    } else if (event->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        if (receiving) {
            evpl_test_abort_if(!r.recv_bind, "duplicate receiver disconnect");
            r.recv_bind = NULL;
        } else {
            evpl_test_abort_if(!r.send_bind, "duplicate sender disconnect");
            r.send_bind = NULL;
        }
        r.disconnected++;
    } else if (event->notify_type == EVPL_NOTIFY_SENT) {
        evpl_test_abort_if(receiving || !r.send_bind || event->notify_status,
                           "unexpected send completion");
        r.sent       += event->sent.msgs;
        r.sent_bytes += event->sent.bytes;
        evpl_test_abort_if(r.sent > r.queued || r.sent_bytes > r.queued_bytes, "duplicate send completion");
    } else if (event->notify_type == EVPL_NOTIFY_RECV_MSG) {
        unsigned char data[BUFFER_SIZE];
        unsigned int  length = 0;
        evpl_test_abort_if(!receiving || !r.recv_bind, "receive on wrong/retired endpoint");
        for (unsigned int i = 0; i < event->recv_msg.niov; i++) {
            struct evpl_iovec *v = &event->recv_msg.iovec[i];
            evpl_test_abort_if(length + v->length > sizeof(data), "datagrams merged or oversized");
            memcpy(data + length, v->data, v->length);
            length += v->length;
        }
        evpl_test_abort_if(length < 4 || length != event->recv_msg.length, "invalid message boundary");
        unsigned int    token = data[0] | (data[1] << 8) | (data[2] << 16) | ((unsigned int) data[3] << 24);
        unsigned int    id    = token & 65535;
        evpl_test_abort_if((token >> 16) != r.serial || id >= r.queued, "foreign message");
        struct message *m = &r.messages[id];
        evpl_test_abort_if(m->received++ || length != m->length, "duplicate or truncated message %u", id);
        for (unsigned int j = 0; j < length; j++) {
            evpl_test_abort_if(data[j] != byte(id, j), "corrupt message %u byte %u", id, j);
        }
        evpl_iovecs_release(evpl, event->recv_msg.iovec, event->recv_msg.niov);
        r.received++;
        if (r.cancel_at && r.received == r.cancel_at) {
            r.cancel_at = 0;
            r.cancelled++;
            evpl_close(r.sender, r.send_bind);
            evpl_close(r.receiver, r.recv_bind);
        }
    } else {
        evpl_test_abort("unexpected notification %u", event->notify_type);
    }
} /* notify */

static void
accepted(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **private_data,
    void                    *arg)
{
    evpl_test_abort_if(r.recv_bind, "duplicate accept");
    r.recv_bind   = bind;
    *callback     = notify;
    *segment      = NULL;
    *private_data = NULL;
} /* accepted */

static void
check_buffers(void)
{
    for (int id = 0; id < r.queued; id++) {
        struct message *m = &r.messages[id];
        evpl_test_abort_if(evpl_iovec_get_ref(&m->base)->refcnt != 1, "message %d retained/leaked a reference", id);
        for (int i = 0; i < BUFFER_SIZE; i++) {
            unsigned char expected = i >= OFFSET && i < OFFSET + m->length ? byte(id, i - OFFSET) : 0xcc;
            evpl_test_abort_if(((unsigned char *) m->base.data)[i] != expected, "send buffer or guard changed");
        }
    }
} /* check_buffers */

static void
await_closed(void)
{
    uint64_t deadline = now_ms() + 15000;

    while (r.disconnected != 2) {
        pump(deadline);
    }
    for (int i = 0; i < 8; i++) {
        pump(deadline);
    }
    check_buffers();
} /* await_closed */

static void
cleanup(void)
{
    if (!r.sender) {
        return;
    }
    r.cancel_at = 0;
    if (r.send_bind) {
        evpl_close(r.sender, r.send_bind);
    }
    if (r.recv_bind) {
        evpl_close(r.receiver, r.recv_bind);
    }
    await_closed();
    for (int i = 0; i < r.queued; i++) {
        evpl_iovec_release(r.sender, &r.messages[i].base);
    }
    if (r.binding) {
        evpl_listener_detach(r.receiver, r.binding);
        test_mbt_listener_destroy(r.receiver, r.listener);
    }
    evpl_endpoint_close(r.destination);
    evpl_destroy(r.sender);
    evpl_destroy(r.receiver);
    int                   serial   = r.serial;
    enum evpl_protocol_id protocol = r.protocol;
    memset(&r, 0, sizeof(r));
    r.serial   = serial;
    r.protocol = protocol;
} /* cleanup */

static struct evpl *
loop(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_wait_ms(config, 0);
    return evpl_create(config);
} /* loop */

static void
connect_pair(void)
{
    static int            port = 27000;

    cleanup();
    r.serial++;
    r.sender   = loop();
    r.receiver = loop();
    const char           *address = getenv("EVPL_TEST_LISTEN_ADDRESS");
    struct evpl_endpoint *local   = evpl_endpoint_create(address ? address : "127.0.0.1", port);
    r.destination = evpl_endpoint_create("127.0.0.1", port++);
    if (r.protocol == EVPL_DATAGRAM_LIBFABRIC_RDM) {
        r.recv_bind = evpl_bind(r.receiver, r.protocol, local, notify, NULL);
        struct evpl_endpoint *source = evpl_endpoint_create("127.0.0.1", port++);
        r.send_bind = evpl_bind(r.sender, r.protocol, source, notify, NULL);
        evpl_endpoint_close(source);
    } else {
        r.listener = evpl_listener_create();
        evpl_test_abort_if(test_mbt_listen(r.receiver, r.listener, r.protocol, local), "listen failed");
        r.binding   = evpl_listener_attach(r.receiver, r.listener, accepted, NULL);
        r.send_bind = evpl_connect(r.sender, r.protocol, NULL, r.destination, notify, NULL, NULL);
        uint64_t deadline = now_ms() + 15000;
        while (r.connected != 2) {
            pump(deadline);
        }
    }
    evpl_endpoint_close(local);
    evpl_test_abort_if(!r.send_bind || !r.recv_bind, "endpoint setup failed");
    evpl_bind_request_send_notifications(r.sender, r.send_bind);
    if (r.protocol == EVPL_DATAGRAM_LIBFABRIC_RDM) {
        /* Connect denotes a ready pair. RxM establishes its underlying TCP
         * connection lazily, so complete one adapter readiness message before
         * exploring application-transfer cancellation. */
        unsigned char probe = 0x5a;
        r.warming = 1;
        evpl_sendtoep(r.sender, r.send_bind, r.destination, &probe, 1);
        uint64_t      deadline = now_ms() + 15000;
        while (!r.warm_received || !r.warm_sent) {
            pump(deadline);
        }
        r.warming = 0;
    }

} /* connect_pair */

static void
queue_batch(const struct datagram_step *s)
{
    evpl_test_abort_if(s->fragments < 1 || s->fragments > MAX_FRAGMENTS || r.queued + BURST > MAX_MESSAGES,
                       "invalid model burst");
    for (int n = 0; n < BURST; n++) {
        int               id = r.queued++;
        struct message   *m  = &r.messages[id];
        struct evpl_iovec vectors[MAX_FRAGMENTS];
        int               fragment_bytes = s->fragments == MAX_FRAGMENTS ? 499 : 17;
        m->length = s->fragments * fragment_bytes + id % 13 + 1;
        evpl_test_abort_if(evpl_iovec_alloc(r.sender, BUFFER_SIZE, 1, 1, 0, &m->base) != 1,
                           "message allocation failed");
        memset(m->base.data, 0xcc, BUFFER_SIZE);
        for (int j = 0; j < m->length; j++) {
            ((unsigned char *) m->base.data)[OFFSET + j] = byte(id, j);
        }
        int               offset = 0;
        for (int j = 0; j < s->fragments; j++) {
            int length = j + 1 == s->fragments ? m->length - offset : fragment_bytes;
            evpl_iovec_clone_segment(&vectors[j], &m->base, OFFSET + offset, length);
            offset += length;
        }
        r.queued_bytes += m->length;
        unsigned int      flags = s->take ? EVPL_SEND_FLAG_TAKE_REF : 0;
        if (r.protocol == EVPL_DATAGRAM_LIBFABRIC_RDM) {
            evpl_sendtoepv(r.sender, r.send_bind, r.destination, vectors, s->fragments, m->length, flags);
        } else {
            evpl_sendv(r.sender, r.send_bind, vectors, s->fragments, m->length, flags);
        }
        if (!s->take) {
            evpl_iovecs_release(r.sender, vectors, s->fragments);
        }
    }
    /* Move the allocator's retained current-buffer reference past the final
    * whole-size application buffer, so the ledger has exactly one owner. */
    struct evpl_iovec remainder;
    evpl_test_abort_if(evpl_iovec_alloc(r.sender, 1, 1, 1, 0, &remainder) != 1, "allocator advance failed");
    evpl_iovec_release(r.sender, &remainder);
} /* queue_batch */

int
main(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    test_evpl_set_core_mech(config);
    evpl_global_config_set_buffer_size(config, BUFFER_SIZE);
    evpl_global_config_set_slab_size(config, 64 * 1024 * 1024);
    evpl_global_config_set_libfabric_tx_size(config, 128);
    evpl_global_config_set_libfabric_rq_size(config, 4);
    evpl_global_config_set_libfabric_rq_batch(config, 2);
    evpl_global_config_set_libfabric_datagram_size_override(config, BUFFER_SIZE - 64);
    evpl_init(config);
    r.protocol = test_mbt_stream_protocol();
    evpl_test_abort_if(r.protocol != EVPL_DATAGRAM_LIBFABRIC_MSG && r.protocol != EVPL_DATAGRAM_LIBFABRIC_RDM,
                       "unsupported datagram adapter");
    for (size_t i = 0; i < sizeof(datagram_steps) / sizeof(datagram_steps[0]); i++) {
        const struct datagram_step *s = &datagram_steps[i];
        fprintf(stderr, "datagram step %zu op %d\n", i, s->op);
        uint64_t                    deadline = now_ms() + 15000;
        switch (s->op) {
            case datagram_Reset: cleanup(); break;
            case datagram_Connect: connect_pair(); break;
            case datagram_Queue: queue_batch(s); break;
            case datagram_Hold: {
                int received = r.received;
                evpl_continue(r.sender);
                evpl_test_abort_if(r.received != received, "paused receiver dispatched callbacks");
                break;
            }
            case datagram_Drain:
                while (r.received != r.queued || r.sent != r.queued) {
                    pump(deadline);
                }
                evpl_test_abort_if(r.sent_bytes != r.queued_bytes, "send byte count differs");
                check_buffers();
                break;
            case datagram_CancelPrefix:
                r.cancel_at = s->prefix;
                while (!r.cancelled) {
                    pump(deadline);
                }
                evpl_test_abort_if(r.sent == r.queued, "cancellation did not leave an outstanding suffix");
                await_closed();
                break;
            case datagram_PeerClose:
                evpl_close(r.receiver, r.recv_bind);
                evpl_continue(r.receiver);
                for (int n = 0; n < 8 && r.send_bind; n++) {
                    evpl_continue(r.sender);
                }
                if (r.send_bind) {
                    evpl_close(r.sender, r.send_bind);
                }
                await_closed();
                break;
            case datagram_Close:
                evpl_close(r.sender, r.send_bind);
                evpl_close(r.receiver, r.recv_bind);
                await_closed();
                break;
            default: abort();
        } /* switch */
        if (s->op != datagram_Reset) {
            evpl_test_abort_if(r.queued != s->queued * BURST || !!r.send_bind != s->live,
                               "datagram implementation differs from model at step %zu", i);
        }
    }
    cleanup();
    return 0;
} /* main */
