// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Same evpl-client <-> evpl-server harness as http1_client, but selecting
 * HTTP/2 (h2c prior-knowledge over plain TCP).  Proves the unified client/server
 * code drives HTTP/2 with no API changes.
 */

#define TEST_VERSION EVPL_HTTP_VERSION_HTTP2

#include "http1_client.c"
