// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

struct evpl_protocol;
struct evpl_framework;
struct evpl_bind;

extern struct evpl_framework evpl_framework_tls;
extern struct evpl_protocol  evpl_socket_tls;

/*
 * Configure the ALPN protocol list (in client preference / server selection
 * order, e.g. {"h2", "http/1.1"}) advertised on TLS connections.  Process-wide
 * and intended to be set before the first TLS connection is established; the
 * HTTP layer calls this to enable "h2" negotiation over TLS.  Passing count==0
 * disables ALPN.
 */
void
evpl_tls_set_alpn_protocols(
    const char *const *protocols,
    int                count);

/*
 * Return the ALPN protocol negotiated on a TLS bind into buf (NUL-terminated).
 * Returns the protocol length, 0 if none was negotiated (or the bind is not a
 * TLS connection that has completed its handshake).
 */
int
evpl_tls_get_alpn(
    struct evpl_bind *bind,
    char             *buf,
    int               len);