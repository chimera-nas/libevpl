#include <pthread.h>
#include <unistd.h>

#include "uthash/utlist.h"

#include "core/bind.h"
#include "core/macros.h"
#include "core/evpl_shared.h"
#include "core/evpl.h"

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
    uint64_t                      one = 1;
    int                           rc;

    pthread_mutex_lock(&listener->lock);

    binding = &listener->attached[listener->rotor];

    listener->rotor++;

    if (listener->rotor >= listener->num_attached) {
        listener->rotor = 0;
    }

    request = evpl_zalloc(sizeof(struct evpl_connect_request));

    request->local_address   = listen_bind->local;
    request->remote_address  = remote_address;
    request->protocol        = listen_bind->protocol;
    request->attach_callback = binding->attach_callback;
    request->accepted        = accepted;
    request->private_data    = binding->private_data;

    evpl_address_incref(request->local_address);

    pthread_mutex_lock(&binding->evpl->lock);
    DL_APPEND(binding->evpl->connect_requests, request);
    pthread_mutex_unlock(&binding->evpl->lock);

    rc = write(binding->evpl->eventfd, &one, sizeof(one));

    evpl_core_abort_if(rc != sizeof(one),
                       "evpl_listener_accept: write failed");

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_accept */

static void
evpl_listener_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_listener       *listener = container_of(doorbell, struct evpl_listener, doorbell);
    struct evpl_listen_request *request;
    struct evpl_bind           *bind, **new_binds;

    pthread_mutex_lock(&listener->lock);

    while (listener->requests) {
        request = listener->requests;
        DL_DELETE(listener->requests, request);

        bind = evpl_bind_prepare(evpl,
                                 evpl_shared->protocol[request->protocol_id],
                                 request->address,
                                 NULL);

        evpl_core_abort_if(!bind->protocol->listen,
                           "evpl_listen called with non-connection oriented protocol");

        bind->accept_callback = evpl_listener_accept;
        bind->private_data    = listener;

        bind->protocol->listen(evpl, bind);

        if (listener->num_binds >= listener->max_binds) {
            listener->max_binds *= 2;

            new_binds = evpl_calloc(listener->max_binds, sizeof(struct evpl_bind *));

            memcpy(new_binds, listener->binds, listener->num_binds * sizeof(struct evpl_bind *));

            evpl_free(listener->binds);

            listener->binds = new_binds;
        }

        listener->binds[listener->num_binds++] = bind;

        pthread_mutex_lock(&request->lock);
        request->complete = 1;
        pthread_cond_signal(&request->cond);
        pthread_mutex_unlock(&request->lock);
    }

    pthread_mutex_unlock(&listener->lock);

} /* evpl_listener_callback */

static void *
evpl_listener_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_listener *listener = private_data;

    evpl_add_doorbell(evpl, &listener->doorbell, evpl_listener_callback);

    __sync_synchronize();

    listener->running = 1;

    return listener;

} /* evpl_listener_init */

SYMBOL_EXPORT struct evpl_listener *
evpl_listener_create(void)
{
    struct evpl_listener *listener;

    __evpl_init();

    listener = evpl_zalloc(sizeof(*listener));

    pthread_mutex_init(&listener->lock, NULL);

    listener->thread = evpl_thread_create(NULL, evpl_listener_init, NULL, listener);

    listener->max_binds = 64;
    listener->binds     = evpl_calloc(listener->max_binds, sizeof(struct evpl_bind *));

    listener->max_attached = 64;
    listener->attached     = evpl_calloc(listener->max_attached, sizeof(struct evpl_listener_binding));

    while (!listener->running) {
        __sync_synchronize();
    }

    return listener;
} /* evpl_listener_create */

SYMBOL_EXPORT void
evpl_listener_destroy(struct evpl_listener *listener)
{

    evpl_core_abort_if(listener->num_attached,
                       "evpl_listener_destroy called with attached evpl contexts");

    pthread_mutex_destroy(&listener->lock);
    evpl_free(listener->binds);
    evpl_free(listener->attached);
    evpl_free(listener);
} /* evpl_listener_destroy */

SYMBOL_EXPORT void
evpl_listener_attach(
    struct evpl           *evpl,
    struct evpl_listener  *listener,
    evpl_attach_callback_t attach_callback,
    void                  *private_data)
{
    struct evpl_listener_binding *binding, *new_attached;

    pthread_mutex_lock(&listener->lock);

    if (listener->num_attached >= listener->max_attached) {
        listener->max_attached *= 2;

        new_attached = evpl_zalloc(sizeof(struct evpl_listener_binding) * listener->max_attached);

        memcpy(new_attached, listener->attached, listener->num_attached * sizeof(struct evpl_listener_binding));

        evpl_free(listener->attached);

        listener->attached = new_attached;
    }

    binding = &listener->attached[listener->num_attached++];

    binding->evpl            = evpl;
    binding->attach_callback = attach_callback;
    binding->private_data    = private_data;

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_attach */

SYMBOL_EXPORT void
evpl_listener_detach(
    struct evpl          *evpl,
    struct evpl_listener *listener)
{
    pthread_mutex_lock(&listener->lock);

    for (int i = 0; i < listener->num_attached; i++) {
        if (listener->attached[i].evpl == evpl) {
            if (i + 1 < listener->num_attached) {
                listener->attached[i] = listener->attached[listener->num_attached - 1];
            }
            listener->num_attached--;
            break;
        }
    }

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_detach */

SYMBOL_EXPORT void
evpl_listen(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol_id,
    struct evpl_endpoint *endpoint)
{
    struct evpl_listen_request *request;

    request = evpl_zalloc(sizeof(*request));

    pthread_mutex_init(&request->lock, NULL);
    pthread_cond_init(&request->cond, NULL);

    request->protocol_id = protocol_id;
    request->address     = evpl_endpoint_resolve(endpoint);

    pthread_mutex_lock(&listener->lock);
    DL_APPEND(listener->requests, request);
    pthread_mutex_unlock(&listener->lock);

    evpl_ring_doorbell(&listener->doorbell);

    pthread_mutex_lock(&request->lock);

    while (!request->complete) {
        pthread_cond_wait(&request->cond, &request->lock);
    }

    pthread_mutex_unlock(&request->lock);

    evpl_free(request);

} /* evpl_listen */