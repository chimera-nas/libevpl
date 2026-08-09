// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utlist.h>

#include "core/macros.h"
#include "core/logging.h"
#include "core/endpoint.h"
#include "core/evpl_shared.h"
#include "core/evpl.h"

#define EVPL_UNIX_PATH_MAX     sizeof(((struct sockaddr_un *) 0)->sun_path)

/* Scheme introducing an in-process name.  No hostname or IP literal can
* contain ':' or '/', so this is unambiguous against an inet address. */
#define EVPL_INPROC_PREFIX     "inproc://"
#define EVPL_INPROC_PREFIX_LEN (sizeof(EVPL_INPROC_PREFIX) - 1)

static void
evpl_endpoint_register(struct evpl_endpoint *ep)
{
    pthread_rwlock_init(&ep->lock, NULL);

    pthread_mutex_lock(&evpl_shared->lock);
    DL_APPEND(evpl_shared->endpoints, ep);
    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_endpoint_register */

/* Validate a local socket name and build an endpoint for it, or return NULL.
 * Shared by evpl_endpoint_create_local() and the local branch of
 * evpl_endpoint_create(). */
static struct evpl_endpoint *
evpl_endpoint_alloc_local(const char *path)
{
    struct evpl_endpoint *ep;
    size_t                len;

    if (unlikely(!path)) {
        evpl_core_error("local endpoint: NULL path");
        return NULL;
    }

    len = strlen(path);

    if (unlikely(path[0] != '/' && path[0] != '@')) {
        evpl_core_error(
            "local endpoint: '%s' is neither an absolute path "
            "nor an abstract name ('@name')", path);
        return NULL;
    }

    if (unlikely(len < 2)) {
        evpl_core_error("local endpoint: '%s' is empty", path);
        return NULL;
    }

    /* A pathname socket needs a trailing NUL inside sun_path; an abstract
     * name spends a byte on the leading NUL instead.  Either way the budget
     * is sizeof(sun_path).  Reject rather than truncate: a silently shortened
     * path is a different socket. */
    if (unlikely(len + (path[0] == '@' ? 0 : 1) > EVPL_UNIX_PATH_MAX)) {
        evpl_core_error(
            "local endpoint: '%s' is %zu bytes, max is %zu",
            path, len, EVPL_UNIX_PATH_MAX - (path[0] == '@' ? 0 : 1));
        return NULL;
    }

#ifndef __linux__
    if (unlikely(path[0] == '@')) {
        evpl_core_error(
            "local endpoint: abstract sockets ('%s') are "
            "Linux-only", path);
        return NULL;
    }
#endif /* ifndef __linux__ */

    ep = evpl_zalloc(sizeof(*ep));

    ep->kind = EVPL_ENDPOINT_LOCAL;
    ep->port = 0;
    memcpy(ep->address, path, len + 1);

    evpl_endpoint_register(ep);

    return ep;
} /* evpl_endpoint_alloc_local */

SYMBOL_EXPORT struct evpl_endpoint *
evpl_endpoint_create_local(const char *path)
{
    __evpl_init();

    return evpl_endpoint_alloc_local(path);
} /* evpl_endpoint_create_local */

/* Validate an in-process name and build an endpoint for it, or return NULL.
 * name is the bare name, without the "inproc://" scheme.  Shared by
 * evpl_endpoint_create_inproc() and the inproc branch of
 * evpl_endpoint_create(). */
static struct evpl_endpoint *
evpl_endpoint_alloc_inproc(const char *name)
{
    struct evpl_endpoint *ep;
    size_t                len;

    if (unlikely(!name)) {
        evpl_core_error("inproc endpoint: NULL name");
        return NULL;
    }

    len = strlen(name);

    if (unlikely(len == 0)) {
        evpl_core_error("inproc endpoint: empty name");
        return NULL;
    }

    /* The name is stored NUL terminated inside a fixed field, so the budget is
     * one less than the field.  Reject rather than truncate: a shortened name
     * is a different endpoint. */
    if (unlikely(len + 1 > EVPL_INPROC_NAME_MAX)) {
        evpl_core_error("inproc endpoint: '%s' is %zu bytes, max is %zu",
                        name, len, EVPL_INPROC_NAME_MAX - 1);
        return NULL;
    }

    ep = evpl_zalloc(sizeof(*ep));

    ep->kind = EVPL_ENDPOINT_INPROC;
    ep->port = 0;

    /* Stored with the scheme so evpl_endpoint_address() round-trips through
     * evpl_endpoint_create(). */
    snprintf(ep->address, sizeof(ep->address), EVPL_INPROC_PREFIX "%s", name);

    evpl_endpoint_register(ep);

    return ep;
} /* evpl_endpoint_alloc_inproc */

SYMBOL_EXPORT struct evpl_endpoint *
evpl_endpoint_create_inproc(const char *name)
{
    __evpl_init();

    return evpl_endpoint_alloc_inproc(name);
} /* evpl_endpoint_create_inproc */

SYMBOL_EXPORT struct evpl_endpoint *
evpl_endpoint_create(
    const char *address,
    int         port)
{
    struct evpl_endpoint *ep;

    __evpl_init();

    /* Neither a hostname nor an IP literal can begin with '/' or '@', so a
     * leading one of those unambiguously names a local socket.  Detecting it
     * here is what lets a caller that takes an address from configuration
     * support unix sockets without a separate code path.  The port is not
     * meaningful for a local endpoint and is ignored. */
    if (unlikely(address[0] == '/' || address[0] == '@')) {
        return evpl_endpoint_alloc_local(address);
    }

    /* Likewise for "inproc://": ':' and '/' cannot appear in a hostname. */
    if (unlikely(strncmp(address, EVPL_INPROC_PREFIX,
                         EVPL_INPROC_PREFIX_LEN) == 0)) {
        return evpl_endpoint_alloc_inproc(address + EVPL_INPROC_PREFIX_LEN);
    }

    ep = evpl_zalloc(sizeof(*ep));

    ep->kind = EVPL_ENDPOINT_INET;
    ep->port = port;
    strncpy(ep->address, address, sizeof(ep->address) - 1);

    evpl_endpoint_register(ep);

    return ep;
} /* evpl_endpoint_create */

SYMBOL_EXPORT int
evpl_endpoint_is_local(const struct evpl_endpoint *ep)
{
    return ep->kind == EVPL_ENDPOINT_LOCAL;
} /* evpl_endpoint_is_local */

SYMBOL_EXPORT int
evpl_endpoint_is_inproc(const struct evpl_endpoint *ep)
{
    return ep->kind == EVPL_ENDPOINT_INPROC;
} /* evpl_endpoint_is_inproc */

/* The bare name, without the "inproc://" scheme the endpoint stores it with. */
static inline const char *
evpl_endpoint_inproc_name(const struct evpl_endpoint *ep)
{
    return ep->address + EVPL_INPROC_PREFIX_LEN;
} /* evpl_endpoint_inproc_name */

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

/*
 * Build the AF_UNIX sockaddr for a local endpoint.  Called with the endpoint
 * write lock held.  Returns a +1 referenced address, or NULL.
 */
static struct evpl_address *
evpl_endpoint_resolve_local(struct evpl_endpoint *endpoint)
{
    struct sockaddr_un sun;
    socklen_t          addrlen;
    const char        *path = endpoint->address;
    size_t             len  = strlen(path);

    memset(&sun, 0, sizeof(sun));

    sun.sun_family = AF_UNIX;

    if (path[0] == '@') {
        /* Linux abstract namespace: sun_path[0] is a NUL and the name is
         * exactly the following len-1 bytes.  There is deliberately NO
         * trailing NUL -- the kernel takes the name to be the whole of
         * (addrlen - offsetof), so a trailing NUL would become part of the
         * name and yield a different, unreachable socket.  For the same
         * reason neither SUN_LEN() (which strlen()s an empty sun_path and
         * returns the autobind length) nor sizeof(sun) may be used here. */
        if (unlikely(len < 2 || len > EVPL_UNIX_PATH_MAX)) {
            evpl_core_error("abstract socket name '%s' is invalid", path);
            return NULL;
        }

        memcpy(&sun.sun_path[1], path + 1, len - 1);

        addrlen = offsetof(struct sockaddr_un, sun_path) + len;
    } else {
        /* Pathname socket: sun_path holds the path plus a trailing NUL, and
         * addrlen counts that NUL. */
        if (unlikely(len == 0 || len + 1 > EVPL_UNIX_PATH_MAX)) {
            evpl_core_error("unix socket path '%s' is %zu bytes, max is %zu",
                            path, len, EVPL_UNIX_PATH_MAX - 1);
            return NULL;
        }

        memcpy(sun.sun_path, path, len); /* trailing NUL from the memset */

        addrlen = offsetof(struct sockaddr_un, sun_path) + len + 1;
    }

    return evpl_address_init((struct sockaddr *) &sun, addrlen);
} /* evpl_endpoint_resolve_local */

/*
 * Build the EVPL_AF_INPROC sockaddr for an in-process endpoint.  Called with
 * the endpoint write lock held.  Returns a +1 referenced address, or NULL.
 *
 * This is the listener form: id is left 0.  A connection's addresses are
 * derived from it by the inproc backend, which stamps in the serial.
 */
static struct evpl_address *
evpl_endpoint_resolve_inproc(struct evpl_endpoint *endpoint)
{
    struct evpl_sockaddr_inproc sinp;
    const char                 *name = evpl_endpoint_inproc_name(endpoint);

    memset(&sinp, 0, sizeof(sinp));

    sinp.family = EVPL_AF_INPROC;
    sinp.id     = 0;

    /* Length was checked at create time, so this cannot truncate; the memset
     * supplies the terminator. */
    memcpy(sinp.name, name, strlen(name));

    return evpl_address_init((struct sockaddr *) &sinp, sizeof(sinp));
} /* evpl_endpoint_resolve_inproc */

/*
 * Resolve a hostname/IP endpoint via getaddrinfo.  Called with the endpoint
 * write lock held.  Returns a +1 referenced address, or NULL.
 */
static struct evpl_address *
evpl_endpoint_resolve_inet(struct evpl_endpoint *endpoint)
{
    char                 port_str[8];
    struct addrinfo      hints, *ai, *p, **pp;
    struct evpl_address *addr;
    int                  rc, i, n;

    snprintf(port_str, sizeof(port_str), "%d", endpoint->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = 0; // SOCK_DGRAM;
    hints.ai_flags    = 0;

    /* getaddrinfo reports failure with a nonzero EAI_* code and leaves *res
     * untouched, so it must be tested against 0 rather than for a negative
     * value: the EAI_* constants are negative in glibc but positive on BSD,
     * where a "< 0" test would walk an uninitialized addrinfo. */
    rc = getaddrinfo(endpoint->address, port_str, &hints, &ai);

    if (unlikely(rc != 0)) {
        evpl_core_error("failed to resolve '%s:%d': %s",
                        endpoint->address, endpoint->port, gai_strerror(rc));
        return NULL;
    }

    n = 0;

    for (p = ai; p != NULL; p = p->ai_next) {
        n++;
    }

    if (unlikely(n == 0)) {
        freeaddrinfo(ai);
        return NULL;
    }

    pp = alloca(n * sizeof(struct addrinfo *));

    for (p = ai, i = 0; p != NULL; p = p->ai_next, i++) {
        pp[i] = p;
    }

    p = pp[rand() % n];

    addr = evpl_address_init(p->ai_addr, p->ai_addrlen);

    freeaddrinfo(ai);

    return addr;
} /* evpl_endpoint_resolve_inet */

static inline uint64_t
evpl_endpoint_age_ms(
    const struct evpl_endpoint *endpoint,
    const struct timespec      *now)
{
    return (now->tv_sec - endpoint->last_resolved.tv_sec) * 1000 +
           (now->tv_nsec - endpoint->last_resolved.tv_nsec) / 1000000;
} /* evpl_endpoint_age_ms */

/*
 * A local or in-process endpoint's sockaddr is a pure function of its
 * immutable name, so it is resolved once and never expires;
 * resolve_timeout_ms exists to pick up DNS changes and has no analogue for a
 * path or a registry key.
 */
static inline int
evpl_endpoint_cache_valid(
    const struct evpl_endpoint *endpoint,
    const struct timespec      *now)
{
    if (!endpoint->resolved_addr) {
        return 0;
    }

    if (endpoint->kind != EVPL_ENDPOINT_INET) {
        return 1;
    }

    return evpl_endpoint_age_ms(endpoint, now) <=
           evpl_shared->config->resolve_timeout_ms;
} /* evpl_endpoint_cache_valid */

struct evpl_address *
evpl_endpoint_resolve(struct evpl_endpoint *endpoint)
{
    struct evpl_address *addr, *old;
    struct timespec      now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_rwlock_rdlock(&endpoint->lock);

    if (likely(evpl_endpoint_cache_valid(endpoint, &now))) {
        addr = endpoint->resolved_addr;
        evpl_address_incref(addr);
        pthread_rwlock_unlock(&endpoint->lock);
        return addr;
    }

    pthread_rwlock_unlock(&endpoint->lock);
    pthread_rwlock_wrlock(&endpoint->lock);

    /* Recheck under the write lock: another thread may have resolved while
     * the lock was dropped, and getaddrinfo is expensive enough to be worth
     * not doing n times over. */
    if (evpl_endpoint_cache_valid(endpoint, &now)) {
        addr = endpoint->resolved_addr;
        evpl_address_incref(addr);
        pthread_rwlock_unlock(&endpoint->lock);
        return addr;
    }

    switch (endpoint->kind) {
        case EVPL_ENDPOINT_LOCAL:
            addr = evpl_endpoint_resolve_local(endpoint);
            break;
        case EVPL_ENDPOINT_INPROC:
            addr = evpl_endpoint_resolve_inproc(endpoint);
            break;
        default:
            addr = evpl_endpoint_resolve_inet(endpoint);
            break;
    } /* switch */

    if (unlikely(!addr)) {
        /* Leave any previously cached address in place.  Releasing it up
         * front (as this function used to) both destroyed a working address
         * on a transient DNS failure and left endpoint->resolved_addr
         * dangling, which the next call would release a second time. */
        pthread_rwlock_unlock(&endpoint->lock);
        return NULL;
    }

    old = endpoint->resolved_addr;

    endpoint->resolved_addr = addr;
    endpoint->last_resolved = now;

    evpl_address_incref(addr); /* one ref for the cache, one for the caller */

    pthread_rwlock_unlock(&endpoint->lock);

    /* Released outside the lock: framework release_address callbacks run
     * here and should not be serialized behind the endpoint rwlock. */
    if (old) {
        evpl_address_release(old);
    }

    return addr;
} /* evpl_endpoint_resolve */

SYMBOL_EXPORT const char *
evpl_endpoint_address(const struct evpl_endpoint *ep)
{
    return ep->address;
}    /* evpl_endpoint_address */

SYMBOL_EXPORT int
evpl_endpoint_port(const struct evpl_endpoint *ep)
{
    return ep->port;
} /* evpl_endpoint_port */