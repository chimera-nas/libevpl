// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/un.h>
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

static inline void
evpl_address_get_address(
    struct evpl_address *address,
    char                *str,
    int                  len)
{
    struct sockaddr     *sa;
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;
    struct sockaddr_un  *sun;
    char                 addr_str[INET6_ADDRSTRLEN];
    int                  pathlen;

    if (address == NULL) {
        snprintf(str, len, "(NULL)");
        return;
    }

    sa = address->addr;

    switch (sa->sa_family) {
        case AF_INET:
            sin = (struct sockaddr_in *) sa;
            inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
            snprintf(str, len, "%s:%d", addr_str, ntohs(sin->sin_port));
            break;

        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
            snprintf(str, len, "[%s]:%d", addr_str, ntohs(sin6->sin6_port));
            break;

        case AF_UNIX:
            sun     = (struct sockaddr_un *) sa;
            pathlen = (int) address->addrlen -
                (int) offsetof(struct sockaddr_un, sun_path);

            if (pathlen <= 0) {
                /* An unbound peer.  Unix clients are typically not bound to
                 * any name, so accept() and getsockname() hand back an
                 * addrlen of exactly sizeof(sa_family_t) with an empty
                 * sun_path.  This is the ordinary case for the remote end of
                 * an accepted connection, not an error. */
                snprintf(str, len, "unix:*");
            } else if (sun->sun_path[0] == '\0') {
                /* Abstract namespace.  The name is the remaining pathlen - 1
                 * bytes and is not NUL terminated, so it needs an explicit
                 * precision. */
                snprintf(str, len, "unix:@%.*s", pathlen - 1,
                         sun->sun_path + 1);
            } else {
                /* Pathname socket.  Bound by strnlen rather than trusting an
                 * addrlen that came from the kernel via a peer. */
                snprintf(str, len, "unix:%.*s",
                         (int) strnlen(sun->sun_path, (size_t) pathlen),
                         sun->sun_path);
            }
            break;

        default:
            /* Never leave the caller's buffer uninitialized -- it is very
             * likely about to be printed. */
            snprintf(str, len, "(family %d)", sa->sa_family);
            break;
    } /* switch */
} /* evpl_bind_get_local_address */
