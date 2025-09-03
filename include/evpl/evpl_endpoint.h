// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_endpoint.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_endpoint;
struct evpl_address;

struct evpl_endpoint *
evpl_endpoint_create(
    const char *address,
    int         port);

void evpl_endpoint_close(
    struct evpl_endpoint *endpoint);

const char *
evpl_endpoint_address(
    const struct evpl_endpoint *ep);

int evpl_endpoint_port(
    const struct evpl_endpoint *ep);