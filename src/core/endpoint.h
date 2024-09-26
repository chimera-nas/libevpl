#pragma once

struct addrinfo;

struct evpl_endpoint {
    char                  address[256];
    int                   port;
    int                   refcnt;
    struct addrinfo      *ai;
};

int
evpl_endpoint_resolve(
    struct evpl           *evpl,
    struct evpl_endpoint  *endpoint);
