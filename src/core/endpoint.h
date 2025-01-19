#pragma once

#include <stdio.h>
#include <sys/socket.h>
#include "core/evpl.h"

struct addrinfo;

struct evpl_address {
    struct sockaddr        *addr;
    socklen_t               addrlen;
    struct evpl_address    *next;
    int                     refcnt;
    void                   *framework_private[EVPL_NUM_FRAMEWORK];
    struct sockaddr_storage sa;
};

struct evpl_endpoint {
    char                  address[256];
    int                   port;
    int                   refcnt;
    struct evpl_address  *addr;
    struct evpl_endpoint *prev;
    struct evpl_endpoint *next;
};

int
evpl_endpoint_resolve(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint);

struct evpl_address *
evpl_address_alloc(
    struct evpl *evpl);

struct evpl_address *
evpl_address_init(
    struct evpl     *evpl,
    struct sockaddr *addr,
    socklen_t        addrlen);

void
evpl_address_release(
    struct evpl         *evpl,
    struct evpl_address *address);

static inline void *
evpl_address_private(
    struct evpl_address  *address,
    enum evpl_protocol_id protocol)
{
    return address->framework_private[protocol];
} // evpl_address_private

static inline void
evpl_address_set_private(
    struct evpl_address  *address,
    enum evpl_protocol_id protocol,
    void                 *private_data)
{
    address->framework_private[protocol] = private_data;
} // evpl_address_set_private

static void
evpl_address_get_address(
    struct evpl_address *address,
    char                *str,
    int                  len)
{
    struct sockaddr     *sa = address->addr;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;
    char                 addr_str[INET6_ADDRSTRLEN];

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        snprintf(str, len, "%s:%d", addr_str, ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
        snprintf(str, len, "[%s]:%d", addr_str, ntohs(sin6->sin6_port));
    }
} /* evpl_bind_get_local_address */

