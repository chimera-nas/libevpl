#pragma once

#define _GNU_SOURCE

#include <sys/epoll.h>
#include <sys/socket.h>

#include "core/evpl.h"
#include "core/internal.h"
#include "core/protocol.h"
#include "core/event.h"

#define evpl_xlio_debug(...) evpl_debug("xlio", __VA_ARGS__)
#define evpl_xlio_info(...)  evpl_info("xlio", __VA_ARGS__)
#define evpl_xlio_error(...) evpl_error("xlio", __VA_ARGS__)
#define evpl_xlio_fatal(...) evpl_fatal("xlio", __VA_ARGS__)
#define evpl_xlio_abort(...) evpl_abort("xlio", __VA_ARGS__)

#define evpl_xlio_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "xlio", __VA_ARGS__)

#define evpl_xlio_abort_if(cond, ...) \
        evpl_abort_if(cond, "xlio", __VA_ARGS__)

typedef int (*socket_fptr_t) (int __domain, int __type, int __protocol);
typedef int (*fcntl_fptr_t)(int __fd, int __cmd, ...);
typedef int (*bind_fptr_t)(int __fd, const struct sockaddr *__addr, socklen_t __addrlen);
typedef int (*close_fptr_t)(int __fd);
typedef ssize_t (*sendmmsg_fptr_t)(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen,
                                   int __flags);
typedef int (*epoll_create_fptr_t)(int __size);
typedef int (*epoll_ctl_fptr_t)(int __epfd, int __op, int __fd, struct epoll_event *__event);
typedef int (*epoll_wait_fptr_t)(int __epfd, struct epoll_event *__events, int __maxevents,
                                 int __timeout);

struct evpl_xlio_shared {
    void           *hdl;

    socket_fptr_t   socket;
    fcntl_fptr_t    fcntl;
    bind_fptr_t     bind;
    close_fptr_t    close;
    sendmmsg_fptr_t sendmmsg;
    epoll_create_fptr_t epoll_create;
    epoll_ctl_fptr_t    epoll_ctl;
    epoll_wait_fptr_t   epoll_wait;
};

struct evpl_xlio_socket {
    struct evpl_event            event;
    int                          fd;
    int                          connected;
    const struct evpl_config    *config;
};

#define evpl_event_xlio_socket(eventp) container_of((eventp), struct evpl_xlio_socket, \
                                               event)

static inline void
evpl_xlio_socket_init(
    struct evpl        *evpl,
    struct evpl_xlio_socket *s,
    int                 fd,
    int                 connected)
{
    s->fd        = fd;
    s->connected = connected;
    s->config    = evpl_config(evpl);
} /* evpl_socket_init */