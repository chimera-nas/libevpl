// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include "evpl/evpl_platform.h"

#include <errno.h>
#include <string.h>
#include <utlist.h>

#include "core/bind.h"
#include "core/macros.h"
#include "core/logging.h"
#include "core/endpoint.h"
#include "core/evpl_shared.h"
#include "core/evpl.h"

static evpl_mutex_t EvplListenerLock = EVPL_MUTEX_INITIALIZER;

void
evpl_listener_binding_release(struct evpl_listener_binding *binding)
{
    if (atomic_fetch_sub_explicit(&binding->refs, 1, memory_order_acq_rel) == 1) {
        evpl_free(binding);
    }
} /* evpl_listener_binding_release */

/* XLIO needs to attach its detached socket to a poll group before closing.
 * Its ordinary bind lifecycle performs that operation and drains callbacks. */
static void
evpl_listener_discard_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    (void) evpl; (void) bind; (void) private_data;
    if (notify->notify_type == EVPL_NOTIFY_RECV_MSG) {
        for (int i = 0; i < notify->recv_msg.niov; i++) {
            evpl_iovec_release(evpl, &notify->recv_msg.iovec[i]);
        }
    }
} /* evpl_listener_discard_notify */

void
evpl_listener_discard(
    struct evpl          *evpl,
    struct evpl_protocol *protocol,
    struct evpl_address  *remote,
    void                 *accepted)
{
    if (protocol->discard_accepted) {
        protocol->discard_accepted(evpl, accepted);
        evpl_address_release(remote);
    } else {
        struct evpl_bind *bind = evpl_bind_prepare(evpl, protocol, NULL, remote);
        bind->notify_callback = evpl_listener_discard_notify;
        protocol->attach(evpl, bind, accepted);
        evpl_close(evpl, bind);
    }
} /* evpl_listener_discard */

static void
evpl_listener_accept(
    struct evpl         *evpl,
    struct evpl_bind    *listen_bind,
    struct evpl_address *remote_address,
    void                *accepted,
    void                *private_data)
{
    struct evpl_listener         *listener = private_data;
    struct evpl_listener_binding *binding;
    struct evpl_connect_request  *request;

    evpl_mutex_lock(&EvplListenerLock);

    if (listener->num_attached == 0) {
        evpl_mutex_unlock(&EvplListenerLock);
        evpl_listener_discard(evpl, listen_bind->protocol, remote_address, accepted);
        return;
    }

    binding = listener->attached[listener->rotor];

    listener->rotor++;

    if (listener->rotor >= listener->num_attached) {
        listener->rotor = 0;
    }

    request = evpl_zalloc(sizeof(struct evpl_connect_request));

    /* Note: local_address is left NULL here. The protocol attach function
    * will set it to the actual interface address using getsockname() or
    * equivalent. This is important when the server binds to 0.0.0.0/:: */
    request->local_address  = NULL;
    request->remote_address = remote_address;
    request->protocol       = listen_bind->protocol;
    request->binding        = binding;
    atomic_fetch_add_explicit(&binding->refs, 1, memory_order_relaxed);
    request->accepted = accepted;

    evpl_mutex_lock(&binding->evpl->lock);
    DL_APPEND(binding->evpl->connect_requests, request);
    evpl_mutex_unlock(&binding->evpl->lock);

    evpl_ring_doorbell(&binding->evpl->run_doorbell);

    evpl_mutex_unlock(&EvplListenerLock);
} /* evpl_listener_accept */

static void
evpl_listen_complete(struct evpl_listen_request *request)
{
    if (request->callback) {
        request->callback(request->status, request->private_data);
        evpl_free(request);
    } else {
        evpl_mutex_lock(&request->lock);
        request->complete = 1;
        evpl_cond_signal(&request->cond);
        evpl_mutex_unlock(&request->lock);
    }
} /* evpl_listen_complete */

static void
evpl_listener_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_listener       *listener = container_of(doorbell, struct evpl_listener, doorbell);
    struct evpl_listen_request *request;
    struct evpl_bind           *bind;
    int                         closing;

    for (;;) {
        evpl_mutex_lock(&EvplListenerLock);
        request = listener->requests;
        closing = listener->closing;
        if (request) {
            DL_DELETE(listener->requests, request);
        }
        evpl_mutex_unlock(&EvplListenerLock);
        if (!request) {
            break;
        }
        if (closing) {
            evpl_address_release(request->address);
            request->status = ECANCELED;
            evpl_listen_complete(request);
            continue;
        }
        bind = evpl_bind_prepare(evpl, evpl_shared->protocol[request->protocol_id],
                                 request->address, NULL);
        bind->accept_callback = evpl_listener_accept;
        bind->private_data    = listener;
        request->status       = bind->protocol->listen(evpl, bind);
        if (request->status) {
            evpl_bind_abort(evpl, bind);
        } else {
            if (listener->num_binds == listener->max_binds) {
                listener->max_binds *= 2;
                listener->binds      = evpl_realloc(listener->binds,
                                                    listener->max_binds * sizeof(*listener->binds));
            }
            listener->binds[listener->num_binds++] = bind;
        }
        /* Never invoke application callbacks under the global listener lock. */
        evpl_listen_complete(request);
    }
} /* evpl_listener_callback */

static void
evpl_listener_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_listener *listener = private_data;

    evpl_listener_callback(evpl, &listener->doorbell);
    evpl_remove_doorbell(evpl, &listener->doorbell);
} /* evpl_listener_shutdown */

static void *
evpl_listener_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_listener *listener = private_data;

    /* The doorbell wakeup was opened by evpl_listener_create before the
     * thread existed, so rings issued before this registration are retained
     * and dispatched on the first loop pass. */
#ifdef HAVE_SPDK
    evpl_add_doorbell_opened(evpl, &listener->doorbell, evpl_listener_callback);
#else  /* ifdef HAVE_SPDK */
    evpl_add_doorbell(evpl, &listener->doorbell, evpl_listener_callback);
#endif /* ifdef HAVE_SPDK */

    return listener;

} /* evpl_listener_init */

SYMBOL_EXPORT struct evpl_listener *
evpl_listener_create_config(struct evpl_thread_config *config)
{
    struct evpl_listener *listener;

    __evpl_init();

    listener = evpl_zalloc(sizeof(*listener));

    /* Open the doorbell before the worker exists so evpl_listen can ring it
     * immediately; the worker registers it on its own evpl in
     * evpl_listener_init and picks up any retained rings.  No readiness wait
     * is needed, which also keeps this callable in SPDK guest mode where the
     * worker may share a reactor with the caller. */
#ifdef HAVE_SPDK
    evpl_doorbell_open(&listener->doorbell);
#endif /* ifdef HAVE_SPDK */


    listener->max_binds = 64;
    listener->binds     = evpl_calloc(listener->max_binds, sizeof(struct evpl_bind *));

    listener->max_attached = 64;
    listener->attached     = evpl_calloc(listener->max_attached, sizeof(struct evpl_listener_binding *));

#ifdef HAVE_SPDK
    listener->thread = evpl_thread_create_async(config, evpl_listener_init,
#else  /* ifdef HAVE_SPDK */
    listener->thread = evpl_thread_create(config, evpl_listener_init,
#endif /* ifdef HAVE_SPDK */
                                                evpl_listener_shutdown, listener);
    return listener;
} /* evpl_listener_create_config */

SYMBOL_EXPORT struct evpl_listener *
evpl_listener_create(void)
{
    return evpl_listener_create_config(NULL);
} /* evpl_listener_create */

static void
evpl_listener_stop(struct evpl_listener *listener)
{
    evpl_mutex_lock(&EvplListenerLock);
    listener->closing = 1;
    for (int i = 0; i < listener->num_attached; i++) {
        listener->attached[i]->listener = NULL;
    }
    listener->num_attached = 0;
    evpl_mutex_unlock(&EvplListenerLock);
} /* evpl_listener_stop */

static void
evpl_listener_finished(void *arg)
{
    struct evpl_listener *listener     = arg;
    evpl_completion_t     callback     = listener->completion;
    void                 *private_data = listener->completion_private;

    evpl_free(listener->binds);
    evpl_free(listener->attached);
    evpl_free(listener);
    if (callback) {
        callback(private_data);
    }
} /* evpl_listener_finished */

SYMBOL_EXPORT void
evpl_listener_destroy_async(
    struct evpl_listener *listener,
    evpl_completion_t     callback,
    void                 *private_data)
{
    listener->completion         = callback;
    listener->completion_private = private_data;
    evpl_listener_stop(listener);
    evpl_thread_destroy_async(listener->thread, evpl_listener_finished, listener);
} /* evpl_listener_destroy_async */

SYMBOL_EXPORT void
evpl_listener_destroy(struct evpl_listener *listener)
{
    if (evpl_current_spdk_thread()) {
        evpl_listener_destroy_async(listener, NULL, NULL);
        return;
    }
    evpl_listener_stop(listener);
    evpl_thread_destroy(listener->thread);
    evpl_listener_finished(listener);
} /* evpl_listener_destroy */

SYMBOL_EXPORT struct evpl_listener_binding *
evpl_listener_attach(
    struct evpl           *evpl,
    struct evpl_listener  *listener,
    evpl_attach_callback_t attach_callback,
    void                  *private_data)
{
    struct evpl_listener_binding *binding, **new_attached;

    binding = evpl_zalloc(sizeof(struct evpl_listener_binding));

    binding->evpl            = evpl;
    binding->listener        = listener;
    binding->attach_callback = attach_callback;
    binding->private_data    = private_data;
    binding->enabled         = 1;
    atomic_init(&binding->refs, 1);

    DL_APPEND(evpl->listener_bindings, binding);

    evpl_mutex_lock(&EvplListenerLock);

    if (listener->num_attached >= listener->max_attached) {

        listener->max_attached *= 2;

        new_attached = evpl_zalloc(sizeof(struct evpl_listener_binding * ) * listener->max_attached);

        memcpy(new_attached, listener->attached, listener->num_attached * sizeof(struct evpl_listener_binding *));

        evpl_free(listener->attached);

        listener->attached = new_attached;
    }

    listener->attached[listener->num_attached++] = binding;

    evpl_mutex_unlock(&EvplListenerLock);

    return binding;
} /* evpl_listener_attach */

SYMBOL_EXPORT void
evpl_listener_detach(
    struct evpl                  *evpl,
    struct evpl_listener_binding *binding)
{
    struct evpl_listener *listener;

    evpl_core_abort_if(!binding,
                       "evpl_listener_detach called with NULL binding");

    evpl_mutex_lock(&EvplListenerLock);

    listener = binding->listener;

    if (listener) {

        for (int i = 0; i < listener->num_attached; i++) {
            if (listener->attached[i] == binding) {

                if (i + 1 < listener->num_attached) {
                    memmove(&listener->attached[i], &listener->attached[i + 1],
                            (listener->num_attached - i - 1) * sizeof(struct evpl_listener_binding *));
                }

                listener->num_attached--;

                if (listener->rotor >= listener->num_attached) {
                    listener->rotor = 0;
                }
                break;
            }
        }

    }

    evpl_mutex_unlock(&EvplListenerLock);

    DL_DELETE(evpl->listener_bindings, binding);

    binding->enabled = 0;
    evpl_listener_binding_release(binding);

} /* evpl_listener_detach */

static int
evpl_listen_submit(
    struct evpl_listener       *listener,
    enum evpl_protocol_id       protocol_id,
    struct evpl_endpoint       *endpoint,
    struct evpl_listen_request *request)
{
    struct evpl_protocol *protocol;

    if ((unsigned int) protocol_id >= EVPL_NUM_PROTO) {
        return ENOTSUP;
    }
    protocol = evpl_shared->protocol[protocol_id];
    if (!protocol || !protocol->listen) {
        return ENOTSUP;
    }
    if (!endpoint || evpl_endpoint_check_protocol(endpoint, protocol) < 0) {
        return EINVAL;
    }
    request->address = evpl_endpoint_resolve(endpoint);
    if (!request->address) {
        return EADDRNOTAVAIL;
    }
    request->protocol_id = protocol_id;
    evpl_mutex_lock(&EvplListenerLock);
    if (listener->closing) {
        evpl_mutex_unlock(&EvplListenerLock);
        evpl_address_release(request->address);
        return ECANCELED;
    }
    DL_APPEND(listener->requests, request);
    evpl_ring_doorbell(&listener->doorbell);
    evpl_mutex_unlock(&EvplListenerLock);
    return 0;
} /* evpl_listen_submit */

SYMBOL_EXPORT void
evpl_listen_async(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol_id,
    struct evpl_endpoint *endpoint,
    void (*callback)(int status, void *private_data),
          void *private_data)
{
    struct evpl_listen_request *request = evpl_zalloc(sizeof(*request));
    int                         status;

    evpl_core_abort_if(!callback, "evpl_listen_async requires a callback");
    request->callback = callback;
    request->private_data = private_data;
    status = evpl_listen_submit(listener, protocol_id, endpoint, request);
    if (status) {
        request->status = status;
        evpl_listen_complete(request);
    }
} /* evpl_listen_async */

SYMBOL_EXPORT int
evpl_listen(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol_id,
    struct evpl_endpoint *endpoint)
{
    struct evpl_listen_request *request;
    int                         status;

    /* The synchronous convenience is only for callers outside reactors. */
    if (evpl_current_spdk_thread()) {
        return EWOULDBLOCK;
    }
    request = evpl_zalloc(sizeof(*request));
    evpl_mutex_init(&request->lock, NULL);
    evpl_cond_init(&request->cond, NULL);
    status = evpl_listen_submit(listener, protocol_id, endpoint, request);
    if (!status) {
        evpl_mutex_lock(&request->lock);
        while (!request->complete) {
            evpl_cond_wait(&request->cond, &request->lock);
        }
        status = request->status;
        evpl_mutex_unlock(&request->lock);
    }
    evpl_cond_destroy(&request->cond);
    evpl_mutex_destroy(&request->lock);
    evpl_free(request);
    return status ? -1 : 0;
} /* evpl_listen */
