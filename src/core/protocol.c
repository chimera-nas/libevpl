// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/macros.h"
#include "core/evpl_shared.h"
#include "core/evpl.h"

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

/* Protocols may be absent because their backend was compiled out or disabled
 * by config, so the table slot can legitimately be NULL.  Callers reach these
 * predicates with ids that came from config strings, so validate rather than
 * dereference blindly. */
static inline struct evpl_protocol *
evpl_protocol_get(enum evpl_protocol_id id)
{
    __evpl_init();

    if (unlikely(id >= EVPL_NUM_PROTO)) {
        return NULL;
    }

    return evpl_shared->protocol[id];
} /* evpl_protocol_get */

SYMBOL_EXPORT int
evpl_protocol_available(enum evpl_protocol_id id)
{
    return evpl_protocol_get(id) != NULL;
} /* evpl_protocol_available */

SYMBOL_EXPORT int
evpl_protocol_is_stream(enum evpl_protocol_id id)
{
    struct evpl_protocol *protocol = evpl_protocol_get(id);

    return protocol ? (int) protocol->stream : 0;
} /* evpl_protocol_is_stream */

SYMBOL_EXPORT int
evpl_protocol_is_local(enum evpl_protocol_id id)
{
    struct evpl_protocol *protocol = evpl_protocol_get(id);

    return protocol && protocol->endpoint_kind == EVPL_ENDPOINT_LOCAL;
} /* evpl_protocol_is_local */

SYMBOL_EXPORT int
evpl_protocol_is_inproc(enum evpl_protocol_id id)
{
    struct evpl_protocol *protocol = evpl_protocol_get(id);

    return protocol && protocol->endpoint_kind == EVPL_ENDPOINT_INPROC;
} /* evpl_protocol_is_inproc */