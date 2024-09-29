#pragma once

struct addrinfo;

struct evpl_endpoint {
    char                  address[256];
    int                   port;
    int                   refcnt;
    int                   resolved;
    struct addrinfo      *ai;
    struct evpl_endpoint *prev;
    struct evpl_endpoint *next;
};

int
evpl_endpoint_resolve(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint);
