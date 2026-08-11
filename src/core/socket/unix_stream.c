// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/address.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/socket/common.h"
#include "core/socket/tcp.h"
#include "core/socket/unix_stream.h"

/*
 * AF_UNIX stream sockets.
 *
 * Once a connected fd exists the data path is byte for byte the TCP one, so
 * evpl_socket_tcp_read/write/error and evpl_accept_tcp are reused verbatim and
 * only connect/listen/attach/pending_close are specialized:
 *
 *   - no TCP_NODELAY: IPPROTO_TCP options return ENOPROTOOPT on AF_UNIX, and
 *     the TCP versions wrap that setsockopt in an abort
 *   - no SO_REUSEADDR: accepted but meaningless.  An AF_UNIX name is a
 *     filesystem entry rather than a port, so it does nothing about EADDRINUSE
 *   - a pathname listener owns a filesystem object, which has to be created
 *     around a possible stale predecessor and removed at teardown
 */

#define EVPL_UNIX_PATH_MAX sizeof(((struct sockaddr_un *) 0)->sun_path)

struct evpl_socket_unix {
    /* Must be first.  evpl_bind_private(), evpl_event_socket() and every
     * helper in socket/common.h assume the bind's private area begins with a
     * struct evpl_socket. */
    struct evpl_socket socket;

    /* Path this bind created and is therefore responsible for removing at
     * teardown.  Empty for clients, for accepted connections, and for
     * abstract-namespace listeners, which have no filesystem object.
     *
     * Deliberately kept here rather than inferred from bind->accept_callback:
     * evpl_bind_prepare() recycles binds from a freelist and does not reset
     * accept_callback, but it does memset the whole private area, so this is
     * guaranteed clean for every new bind. */
    char               unlink_path[EVPL_UNIX_PATH_MAX];
};

/*
 * Decide what to do about an existing entry at path, called only after bind()
 * has already failed with EADDRINUSE.
 *
 * SO_REUSEADDR does nothing here: bind() fails as long as the name exists,
 * whether or not anyone is listening behind it.  The only way to tell a live
 * server from the corpse of a crashed one is to try to connect -- a live
 * listener accepts immediately, or returns EAGAIN with a full backlog, while a
 * stale file returns ECONNREFUSED.
 *
 * Returns 1 if the entry proved stale and was unlinked, so bind may be
 * retried; 0 if a live server owns it or it is not ours to remove.
 */
static int
evpl_socket_unix_clear_stale(
    const struct sockaddr *addr,
    socklen_t              addrlen,
    const char            *path)
{
    struct stat st;
    int         fd, rc, flags;

    /* Never unlink something that is not a socket: a typo in an endpoint path
     * must not delete a user's file. */
    if (lstat(path, &st) < 0 || !S_ISSOCK(st.st_mode)) {
        return 0;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        return 0;
    }

    /* Non-blocking, for the reason the connect() result check below spells
     * out.  Set with fcntl() rather than by passing SOCK_NONBLOCK to socket(),
     * which is a Linux extension the BSDs do not have. */
    flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return 0;
    }

    /* Probe with the address the resolver already built, rather than
     * rebuilding one from the path: it carries the exact addrlen, so the
     * probe is guaranteed to name the same socket bind() just tried. */
    rc = connect(fd, addr, addrlen);

    /* The probe socket is non-blocking, so a live listener yields 0 -- AF_UNIX
     * completes connect synchronously -- or EAGAIN when the backlog is full.
     * Only ECONNREFUSED proves there is no listener behind the file. */
    if (rc == 0 || errno != ECONNREFUSED) {
        close(fd);
        return 0;
    }

    close(fd);

    return unlink(path) == 0;
} /* evpl_socket_unix_clear_stale */

static int
evpl_socket_unix_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_socket_unix *su = evpl_bind_private(listen_bind);
    struct evpl_socket      *s  = &su->socket;
    struct sockaddr_un      *sun;
    size_t                   pathlen;
    int                      rc;

    sun = (struct sockaddr_un *) listen_bind->local->addr;

    /* The core rejects an endpoint/protocol mismatch before it reaches a
     * backend, so this really is a should-never-happen. */
    evpl_socket_abort_if(sun->sun_family != AF_UNIX,
                         "STREAM_SOCKET_UNIX requires a local endpoint, see "
                         "evpl_endpoint_create_local()");

    s->fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (s->fd < 0) {
        evpl_socket_error("Failed to create unix listen socket: %s",
                          strerror(errno));
        return -1;
    }

    rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);

    /* A crashed predecessor leaves its name in the filesystem and bind() then
     * fails with EADDRINUSE forever.  Probe lazily and retry only once the
     * entry has proved stale: the clean case touches nothing, and a running
     * server can never be silently displaced. */
    if (rc < 0 && errno == EADDRINUSE && sun->sun_path[0] != '\0' &&
        evpl_socket_unix_clear_stale(listen_bind->local->addr,
                                     listen_bind->local->addrlen,
                                     sun->sun_path)) {
        rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);
    }

    if (rc < 0) {
        evpl_socket_error("Failed to bind unix listen socket '%s': %s",
                          sun->sun_path[0] ? sun->sun_path : "(abstract)",
                          strerror(errno));
        goto fail;
    }

    /* Remember the name so teardown can remove it.  Only a pathname socket
     * has anything to remove; an abstract name vanishes with the last
     * reference to the socket.  Recorded as soon as bind() succeeds, so that
     * a later failure below unlinks the entry we just created rather than
     * leaving it behind to block the next start. */
    if (sun->sun_path[0] != '\0') {
        pathlen = strnlen(sun->sun_path, sizeof(su->unlink_path) - 1);

        memcpy(su->unlink_path, sun->sun_path, pathlen);

        su->unlink_path[pathlen] = '\0';
    }

    rc = fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL, 0) | O_NONBLOCK);

    if (rc < 0) {
        evpl_socket_error("Failed to set socket flags: %s", strerror(errno));
        goto fail;
    }

    rc = listen(s->fd, evpl_shared->config->max_pending);

    if (rc < 0) {
        evpl_socket_error("Failed to listen on listener fd: %s",
                          strerror(errno));
        goto fail;
    }

    evpl_add_event(evpl, &s->event, s->fd,
                   evpl_accept_tcp, NULL, NULL);

    evpl_event_read_interest(evpl, &s->event);

    return 0;

 fail:

    if (su->unlink_path[0]) {
        unlink(su->unlink_path);
        su->unlink_path[0] = '\0';
    }

    close(s->fd);

    s->fd = -1;

    return -1;
} /* evpl_socket_unix_listen */

static void
evpl_socket_unix_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket_unix *su = evpl_bind_private(bind);
    struct evpl_socket      *s  = &su->socket;
    struct sockaddr_un      *sun;
    struct sockaddr_storage  ss;
    socklen_t                sslen = sizeof(ss);
    int                      rc;

    sun = (struct sockaddr_un *) bind->remote->addr;

    evpl_socket_abort_if(sun->sun_family != AF_UNIX,
                         "STREAM_SOCKET_UNIX requires a local endpoint, see "
                         "evpl_endpoint_create_local()");

    s->fd = socket(AF_UNIX, SOCK_STREAM, 0);

    evpl_socket_abort_if(s->fd < 0, "Failed to create unix socket: %s",
                         strerror(errno));

    /* Deliberately connects while the fd is still blocking, matching the TCP
     * backend, which also calls evpl_socket_init() only afterwards.  AF_UNIX
     * has no EINPROGRESS handshake to wait on, so a non-blocking connect
     * against a full backlog would return EAGAIN with nothing for epoll to
     * report -- blocking here is strictly better. */
    rc = connect(s->fd, bind->remote->addr, bind->remote->addrlen);

    evpl_socket_abort_if(rc < 0 && errno != EINPROGRESS && errno != EAGAIN,
                         "Failed to connect unix socket '%s': %s",
                         sun->sun_path, strerror(errno));

    /* The client is unbound, so getsockname reports the unnamed form: an
     * addrlen of offsetof(struct sockaddr_un, sun_path) and no path.  Recorded
     * anyway so bind->local is non-NULL and consistent with every other
     * protocol; evpl_address_alloc zeroes sa, so the short copy is safe. */
    rc = getsockname(s->fd, (struct sockaddr *) &ss, &sslen);

    evpl_socket_abort_if(rc < 0, "Failed to getsockname on socket: %s",
                         strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    evpl_socket_init(evpl, s, s->fd, 0);

    evpl_add_event(evpl, &s->event, s->fd,
                   evpl_socket_tcp_read,
                   evpl_socket_tcp_write,
                   evpl_socket_tcp_error);

    evpl_event_read_interest(evpl, &s->event);
    evpl_event_write_interest(evpl, &s->event);

} /* evpl_socket_unix_connect */

static void
evpl_socket_unix_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_socket_unix     *su              = evpl_bind_private(bind);
    struct evpl_socket          *s               = &su->socket;
    struct evpl_accepted_socket *accepted_socket = accepted;
    struct evpl_notify           notify;
    struct sockaddr_storage      ss;
    socklen_t                    sslen = sizeof(ss);
    int                          fd    = accepted_socket->fd;
    int                          rc;

    evpl_free(accepted_socket);

    evpl_socket_init(evpl, s, fd, 1);

    /* An accepted AF_UNIX socket inherits the listener's name, so this yields
     * the listening path.  su->unlink_path is deliberately left empty: the
     * listen bind owns the filesystem entry, not this connection. */
    rc = getsockname(fd, (struct sockaddr *) &ss, &sslen);

    evpl_socket_abort_if(rc < 0, "getsockname failed: %s", strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    evpl_add_event(evpl, &s->event, fd,
                   evpl_socket_tcp_read,
                   evpl_socket_tcp_write,
                   evpl_socket_tcp_error);

    evpl_event_read_interest(evpl, &s->event);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

} /* evpl_socket_unix_attach */

static void
evpl_socket_unix_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket_unix *su = evpl_bind_private(bind);
    struct evpl_socket      *s  = &su->socket;

    /* Remove the name before closing the fd, so a client racing the shutdown
     * gets ENOENT rather than briefly connecting to a socket that is about to
     * vanish.  unlink_path is set only by listen(), and only for pathname
     * sockets, so clients and accepted connections never delete anything. */
    if (su->unlink_path[0]) {
        unlink(su->unlink_path);
        su->unlink_path[0] = '\0';
    }

    evpl_event_read_disinterest(evpl, &s->event);
    evpl_event_write_disinterest(evpl, &s->event);

    close(s->fd);

    s->fd = -1;
} /* evpl_socket_unix_pending_close */

struct evpl_protocol evpl_socket_unix_stream = {
    .id            = EVPL_STREAM_SOCKET_UNIX,
    .connected     = 1,
    .stream        = 1,
    .endpoint_kind = EVPL_ENDPOINT_LOCAL,
    .name          = "STREAM_SOCKET_UNIX",
    .connect       = evpl_socket_unix_connect,
    .pending_close = evpl_socket_unix_pending_close,
    .close         = evpl_socket_close,
    .listen        = evpl_socket_unix_listen,
    .attach        = evpl_socket_unix_attach,
    .flush         = evpl_socket_flush,
};
