// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stdatomic.h>

#include "core/evpl_shared.h"

/*
 * Private address family for the in-process transport.
 *
 * An inproc peer is a thread, not anything the kernel knows about, so there is
 * no real family to borrow.  This value is above AF_MAX so it can never be
 * confused with one, and an EVPL_AF_INPROC sockaddr is never passed to a
 * syscall -- it exists only to let struct evpl_address carry an inproc name
 * through the same plumbing as every other peer address.
 *
 * It has to fit sa_family_t, which is where the original 0x4950 ('IP') came
 * unstuck: that is fine in Linux's 16-bit sa_family_t, but Darwin's is 8 bits,
 * so the value truncated to 80 and switching on it did not even compile.  0xF0
 * clears AF_MAX on both (mid-40s on Linux, low-40s on Darwin) with room to
 * spare, and fits a byte.
 */
#define EVPL_AF_INPROC       0xF0

/* Longest inproc name including its NUL.  Matched to sun_path so the two
 * name-addressed transports have the same budget, and small enough that the
 * rendered form still fits EVPL_ADDRESS_STRLEN. */
#define EVPL_INPROC_NAME_MAX 108

/*
 * Laid out to alias struct sockaddr's leading fields, since that is how the
 * family is read back -- evpl_address hands this to code that casts to struct
 * sockaddr and switches on sa_family.  The BSDs put a length byte first and
 * the family second, so the header differs by platform and this has to follow
 * it; on Linux the family is simply first.
 */
struct evpl_sockaddr_inproc {
#ifdef __APPLE__
    uint8_t     len;
    uint8_t     family;
    uint16_t    pad;
#else  /* ifdef __APPLE__ */
    sa_family_t family;
    uint16_t    pad;
#endif  /* ifdef __APPLE__ */
    /* Distinguishes the two ends and successive connections to one name: 0 for
     * a listener, a nonzero serial for a connection.  The analogue of an
     * ephemeral port -- without it two concurrent connections to the same name
     * would be indistinguishable in a log. */
    uint32_t    id;
    char        name[EVPL_INPROC_NAME_MAX];
};

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
    struct sockaddr             *sa;
    struct sockaddr_in          *sin;
    struct sockaddr_in6         *sin6;
    struct sockaddr_un          *sun;
    struct evpl_sockaddr_inproc *sinp;
    char                         addr_str[INET6_ADDRSTRLEN];
    int                          pathlen;

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

        case EVPL_AF_INPROC:
            sinp = (struct evpl_sockaddr_inproc *) sa;

            /* Bounded by strnlen rather than trusting the name to be
             * terminated, for the same reason as the pathname case above. */
            if (sinp->id) {
                snprintf(str, len, "inproc:%.*s#%u",
                         (int) strnlen(sinp->name, sizeof(sinp->name)),
                         sinp->name, sinp->id);
            } else {
                /* A listener, which has no connection serial. */
                snprintf(str, len, "inproc:%.*s",
                         (int) strnlen(sinp->name, sizeof(sinp->name)),
                         sinp->name);
            }
            break;

        default:
            /* Never leave the caller's buffer uninitialized -- it is very
             * likely about to be printed. */
            snprintf(str, len, "(family %d)", sa->sa_family);
            break;
    } /* switch */
} /* evpl_bind_get_local_address */
