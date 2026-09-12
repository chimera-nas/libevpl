// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/os.h"

struct evpl;
struct evpl_core;
struct evpl_iocp_request {
    OVERLAPPED overlapped; /* stable through the terminal completion */
    void       (*callback)(
        struct evpl *,
        struct evpl_iocp_request *,
        DWORD bytes,
        DWORD error);
};
struct evpl_iocp_result {
    struct evpl_iocp_request *request;
    DWORD                     bytes;
    DWORD                     error;
};
struct evpl_core_iocp {
    HANDLE                  port;
    unsigned int            count;
    struct evpl_iocp_result results[64];
};
extern const struct evpl_core_ops evpl_core_iocp_ops;
int evpl_iocp_post(
    struct evpl *,
    struct evpl_iocp_request *);
int                               evpl_iocp_associate(struct evpl *, HANDLE);
