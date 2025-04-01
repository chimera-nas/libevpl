#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "uthash/utlist.h"

#include "core/macros.h"
#include "core/endpoint.h"
#include "core/evpl_shared.h"
#include "core/evpl.h"

SYMBOL_EXPORT struct evpl_endpoint *
evpl_endpoint_create(
    const char *address,
    int         port)
{
    struct evpl_endpoint *ep;

    __evpl_init();

    ep = evpl_zalloc(sizeof(*ep));

    ep->port = port;
    strncpy(ep->address, address, sizeof(ep->address) - 1);

    pthread_rwlock_init(&ep->lock, NULL);

    pthread_mutex_lock(&evpl_shared->lock);
    DL_APPEND(evpl_shared->endpoints, ep);
    pthread_mutex_unlock(&evpl_shared->lock);

    return ep;
} /* evpl_endpoint_create */

SYMBOL_EXPORT void
evpl_endpoint_close(struct evpl_endpoint *endpoint)
{
    pthread_rwlock_wrlock(&endpoint->lock);

    pthread_mutex_lock(&evpl_shared->lock);
    DL_DELETE(evpl_shared->endpoints, endpoint);
    pthread_mutex_unlock(&evpl_shared->lock);

    if (endpoint->resolved_addr) {
        evpl_address_release(endpoint->resolved_addr);
    }

    pthread_rwlock_unlock(&endpoint->lock);

    evpl_free(endpoint);
} /* evpl_endpoint_close */

struct evpl_address *
evpl_endpoint_resolve(struct evpl_endpoint *endpoint)
{
    char                 port_str[8];
    struct addrinfo      hints, *ai, *p, **pp;
    struct evpl_address *addr;
    struct timespec      now;
    uint64_t             age_ms;
    int                  rc, i, n;

    clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_rwlock_rdlock(&endpoint->lock);

    if (likely(endpoint->resolved_addr)) {
        age_ms = (now.tv_sec - endpoint->last_resolved.tv_sec) * 1000 +
            (now.tv_nsec - endpoint->last_resolved.tv_nsec) / 1000000;

        if (likely(age_ms <= evpl_shared->config->resolve_timeout_ms)) {
            addr = endpoint->resolved_addr;
            evpl_address_incref(addr);
            pthread_rwlock_unlock(&endpoint->lock);
            return addr;
        }
    }

    pthread_rwlock_unlock(&endpoint->lock);
    pthread_rwlock_wrlock(&endpoint->lock);

    if (endpoint->resolved_addr) {
        evpl_address_release(endpoint->resolved_addr);
    }

    snprintf(port_str, sizeof(port_str), "%d", endpoint->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = 0; // SOCK_DGRAM;
    hints.ai_flags    = 0;

    rc = getaddrinfo(endpoint->address, port_str, &hints, &ai);

    if (unlikely(rc < 0)) {
        pthread_rwlock_unlock(&endpoint->lock);
        return NULL;
    }

    n = 0;

    for (p = ai; p != NULL; p = p->ai_next) {
        n++;
    }

    if (n) {
        pp = alloca(n * sizeof(struct addrinfo *));

        for (p = ai, i = 0; p != NULL; p = p->ai_next, i++) {
            pp[i] = p;
        }

        p = pp[rand() % n];

        addr = evpl_address_init(p->ai_addr, p->ai_addrlen);

        endpoint->resolved_addr = addr;
        endpoint->last_resolved = now;

        evpl_address_incref(addr);

    } else {
        addr = NULL;
    }

    pthread_rwlock_unlock(&endpoint->lock);

    freeaddrinfo(ai);

    return addr;
} /* evpl_endpoint_resolve */

const char *
evpl_endpoint_address(const struct evpl_endpoint *ep)
{
    return ep->address;
}    /* evpl_endpoint_address */

int
evpl_endpoint_port(const struct evpl_endpoint *ep)
{
    return ep->port;
} /* evpl_endpoint_port */