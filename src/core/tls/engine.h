// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include <stddef.h>
struct evpl;
struct evpl_tls_engine;
/* The stream transport owns all network I/O. Engine calls never retain caller
 * buffers. Handshake/read/write return 1 for progress, 0 for more input, -1
 * for a terminal error or peer closure. Output is drained after every drive. */
struct evpl_tls_engine * evpl_tls_engine_create(
    struct evpl *,
    int server);
void evpl_tls_engine_free(
    struct evpl_tls_engine *);
int evpl_tls_engine_input(
    struct evpl_tls_engine *,
    const void *,
    unsigned int);
int evpl_tls_engine_output(
    struct evpl_tls_engine *,
    void *,
    unsigned int);
int evpl_tls_engine_handshake(
    struct evpl_tls_engine *);
int evpl_tls_engine_read(
    struct evpl_tls_engine *,
    void *,
    size_t,
    size_t *);
int evpl_tls_engine_write(
    struct evpl_tls_engine *,
    const void *,
    size_t,
    size_t *);
void evpl_tls_engine_shutdown(
    struct evpl_tls_engine *);
int evpl_tls_engine_alpn(
    struct evpl_tls_engine *,
    char *,
    int);
