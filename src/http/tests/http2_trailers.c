// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The http_trailers exchanges over HTTP/2 (h2c prior-knowledge), where the
 * trailer section is a trailing HEADERS frame -- including on the
 * Content-Length exchange that HTTP/1.x must drop it from.
 */

#define TEST_VERSION EVPL_HTTP_VERSION_HTTP2
#define TEST_PORT    8086

#include "http_trailers.c"
