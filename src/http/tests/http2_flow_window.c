// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The http2_flow transfers with a 256KB flow-control window configured
 * through evpl_global_config_set_http2_window_size: the same completion and
 * high-water assertions hold against the larger bound, proving the setting
 * reaches both the per-stream and connection windows.
 */

#define TEST_WINDOW (256 * 1024)
#define TEST_PORT   8089

#include "http2_flow.c"
