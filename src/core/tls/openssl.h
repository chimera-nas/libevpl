// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include <openssl/ssl.h>
struct evpl;
SSL * evpl_tls_session_create(
    struct evpl *evpl,
    int          is_server);
