// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Same evpl-client <-> evpl-server harness as http1_client, but over TLS with
 * HTTP/2 negotiated via ALPN ("h2").
 */

#define TEST_PROTOCOL EVPL_STREAM_SOCKET_TLS
#define TEST_VERSION  EVPL_HTTP_VERSION_HTTP2

#include "http1_client.c"
