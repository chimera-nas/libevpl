// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include "core/internal.h"

#define evpl_rpc2_debug(...) evpl_debug("rpc2", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rpc2_info(...)  evpl_info("rpc2", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rpc2_error(...) evpl_error("rpc2", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rpc2_fatal(...) evpl_fatal("rpc2", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_rpc2_abort(...) evpl_abort("rpc2", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_rpc2_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "rpc2", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_rpc2_abort_if(cond, ...) \
        evpl_abort_if(cond, "rpc2", __FILE__, __LINE__, __VA_ARGS__)
