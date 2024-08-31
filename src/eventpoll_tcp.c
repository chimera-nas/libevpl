#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "eventpoll_internal.h"
#include "eventpoll_event.h"
#include "eventpoll_tcp.h"

void
eventpoll_accept_tcp(
    struct eventpoll_event *event)
{
    struct eventpoll_socket *ls = eventpoll_event_backend(event);
    struct eventpoll_socket *s;
    struct eventpoll_conn *conn;
    struct sockaddr_storage client_addr;
    struct sockaddr *client_addrp;
    socklen_t client_len = sizeof(client_addr);
    char ip_str[INET6_ADDRSTRLEN];
    int fd, port;
    void *addr;

    client_addrp =  (struct sockaddr *)&client_addr;

    fd = accept(ls->fd, client_addrp, &client_len);

    if (fd < 0) {
        eventpoll_event_mark_unreadable(event);
        return;
    }


    if (client_addrp->sa_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_addrp;
        addr = &(ipv4->sin_addr);
        port = ntohs(ipv4->sin_port);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_addrp;
        addr = &(ipv6->sin6_addr);
        port = ntohs(ipv6->sin6_port);
    }

    inet_ntop(client_addrp->sa_family, addr, ip_str, sizeof(ip_str));

    conn = eventpoll_alloc_conn(EVENTPOLL_PROTO_TCP, ip_str, port);

    s = eventpoll_conn_backend(conn);

    s->fd = fd;
    s->connected = 1;

    event->user_connect_callback(conn, event->user_private_data);
}

int
eventpoll_listen_tcp(
    struct eventpoll_config *config,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port)
{
    char port_str[8];
    struct addrinfo hints, *res, *p;
    int rc, fd;
    const int yes = 1;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(address, port_str, &hints, &res);

    if (rc) {
        eventpoll_debug("getaddrinfo returned %d", rc);
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            return errno;
        }


        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        eventpoll_debug("Failed to bind to any addr");
        return 1;
    }

    rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    rc = listen(fd, config->max_pending);

    eventpoll_fatal_if(rc, "Failed to listen on listener fd");
    
    s->fd = fd;

    event->fd = fd;
    event->backend_read_callback = eventpoll_accept_tcp;

    return 0;

}

void
eventpoll_read_tcp(
    struct eventpoll_event *event)
{
    eventpoll_debug("tcp socket readable");
}

void
eventpoll_write_tcp(
    struct eventpoll_event *event)
{
    struct eventpoll_socket *s = eventpoll_event_backend(event);
    int err, rc;
    socklen_t len;

    eventpoll_debug("tcp socket writable");

    if (!s->connected) {
        len = sizeof(err);
        rc = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        eventpoll_fatal_if(rc,"Failed to get SO_ERROR from socket");

        if (err == 0) {
            /* Casting event to conn is safe */
            event->user_connect_callback((struct eventpoll_conn *)event,
                                         event->user_private_data);
        } else {
            event->user_error_callback(err, event->user_private_data);
        }

        s->connected = 1;
    }
}

void
eventpoll_error_tcp(
    struct eventpoll_event *event)
{
    eventpoll_debug("tcp socket error");
}

int
eventpoll_connect_tcp(
    struct eventpoll_config *config,
    struct eventpoll_socket *s,
    struct eventpoll_event *event,
    const char *address,
    int port)
{
    char port_str[8];
    struct addrinfo hints, *res, *p;
    int rc, fd, flags;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(address, port_str, &hints, &res);

    if (rc) {
        eventpoll_debug("failed to resolve address for connect");
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        flags = fcntl(fd, F_GETFL, 0);

        if (flags == -1) {
            close(fd);
            continue;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            continue;
        }


        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                eventpoll_debug("connect errno: %s", strerror(errno));
                close(fd);
                continue;
            }
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        eventpoll_debug("failed to connect to any address");
        return 1;
    }

    s->fd = fd;
    s->connected = 0;

    event->fd = fd;
    event->backend_read_callback = eventpoll_read_tcp;
    event->backend_write_callback = eventpoll_write_tcp;
    event->backend_error_callback = eventpoll_error_tcp;

    return 0;
}

void
eventpoll_close_tcp(
    struct eventpoll_socket *s)
{
    close(s->fd);
}
