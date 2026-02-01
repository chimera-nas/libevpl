// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

extern struct evpl_framework      evpl_framework_io_uring;
#ifndef EVPL_IO_URING_LEGACY
extern struct evpl_protocol       evpl_io_uring_tcp;
#endif
extern struct evpl_block_protocol evpl_block_protocol_io_uring;