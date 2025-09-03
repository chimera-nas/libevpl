// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#include "core/evpl_shared.h"

struct evpl_address {
    struct sockaddr        *addr;
    socklen_t               addrlen;
    struct evpl_address    *next;
    atomic_int              refcnt;
    void                   *framework_private[EVPL_NUM_FRAMEWORK];
    struct sockaddr_storage sa;
};


struct evpl_address *
evpl_address_alloc(
    void);

struct evpl_address *
evpl_address_init(
    struct sockaddr *addr,
    socklen_t        addrlen);

static inline void
evpl_address_incref(struct evpl_address *address)
{
    atomic_fetch_add(&address->refcnt, 1);
} /* evpl_address_incref */

void
evpl_address_release(
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
