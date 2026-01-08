// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

struct evpl;
struct evpl_bind;
struct evpl_protocol;

extern struct evpl_protocol evpl_socket_tcp;

void evpl_socket_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind);
