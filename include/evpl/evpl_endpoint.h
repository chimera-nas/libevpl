// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_endpoint.h directly, include evpl/evpl.h instead"
#endif

struct evpl_endpoint;
struct evpl_address;

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl *evpl,
    const char *address,
    int port);

void evpl_endpoint_close(
    struct evpl *evpl,
    struct evpl_endpoint *endpoint);

const char *
evpl_endpoint_address(
    const struct evpl_endpoint *ep);

int evpl_endpoint_port(
    const struct evpl_endpoint *ep);