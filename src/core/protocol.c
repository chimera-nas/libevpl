// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl_shared.h"

void
evpl_framework_init(
    struct evpl_shared    *evpl_shared,
    unsigned int           id,
    struct evpl_framework *framework)
{
    evpl_shared->framework[id] = framework;

} /* evpl_framework_init */

void
evpl_protocol_init(
    struct evpl_shared   *evpl_shared,
    unsigned int          id,
    struct evpl_protocol *protocol)
{
    evpl_shared->protocol[id] = protocol;
} /* evpl_protocol_init */

void
evpl_block_protocol_init(
    struct evpl_shared         *evpl_shared,
    unsigned int                id,
    struct evpl_block_protocol *protocol)
{
    evpl_shared->block_protocol[id] = protocol;
} /* evpl_block_protocol_init */

int
evpl_protocol_is_stream(enum evpl_protocol_id id)
{
    return evpl_shared->protocol[id]->stream;
} /* evpl_protocol_is_stream */