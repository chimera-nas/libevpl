// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/address.h"

struct evpl_address *
evpl_address_alloc(void)
{
    struct evpl_address *address;

    address = evpl_zalloc(sizeof(*address));

    address->addr = (struct sockaddr *) &address->sa;
    atomic_init(&address->refcnt, 1);
    address->next = NULL;

    return address;
} /* evpl_address_alloc */

struct evpl_address *
evpl_address_init(
    struct sockaddr *addr,
    socklen_t        addrlen)
{
    struct evpl_address *ea = evpl_address_alloc();

    ea->addrlen = addrlen;
    memcpy(ea->addr, addr, addrlen);

    return ea;

} /* evpl_address_init */

void
evpl_address_release(struct evpl_address *address)
{
    int i;

    if (atomic_fetch_sub(&address->refcnt, 1) > 1) {
        return;
    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {

        if (!address->framework_private[i]) {
            continue;
        }

        evpl_shared->framework[i]->release_address(
            address->framework_private[i],
            evpl_shared->framework_private[i]);
    }

    evpl_free(address);
} /* evpl_address_release */