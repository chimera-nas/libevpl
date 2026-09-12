// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include "logging.h"
#include "macros.h"

#ifdef _WIN32
#include <stdint.h>
#include <string.h>
struct evpl_allocation { void *base; size_t size; size_t alignment; };
static void *
evpl_allocate(
    size_t size,
    size_t alignment)
{
    struct evpl_allocation *header;
    void                   *base;
    uintptr_t               address;

    if (alignment < 16) {
        alignment = 16;
    }
    evpl_core_abort_if(alignment & (alignment - 1), "invalid allocation alignment");
    base = malloc(size + alignment - 1 + sizeof(*header));
    evpl_core_abort_if(!base, "allocation failed");
    address      = ((uintptr_t) base + sizeof(*header) + alignment - 1) & ~(uintptr_t) (alignment - 1);
    header       = (struct evpl_allocation *) address - 1;
    header->base = base; header->size = size; header->alignment = alignment;
    return (void *) address;
} /* evpl_allocate */
SYMBOL_EXPORT void * evpl_malloc(unsigned int n) { return evpl_allocate(n, 16); }
SYMBOL_EXPORT void * evpl_zalloc(unsigned int n) { void *p = evpl_malloc(n); memset(p, 0, n); return p; }
SYMBOL_EXPORT void *
evpl_calloc(
    unsigned int n,
    unsigned int size)
{
    size_t bytes = (size_t) n * size;
    void  *p     = evpl_allocate(bytes, 16); memset(p, 0, bytes); return p;
} /* evpl_calloc */
SYMBOL_EXPORT void * evpl_valloc(
    unsigned int n,
    unsigned int alignment) { return evpl_allocate(n, alignment); }
SYMBOL_EXPORT void
evpl_free(void *p)
{
    if (p) {
        free(((struct evpl_allocation *) p - 1)->base);
    }
} /* evpl_free */
SYMBOL_EXPORT void *
evpl_realloc(
    void        *p,
    unsigned int n)
{
    struct evpl_allocation *header;
    void                   *result;

    if (!p) {
        return evpl_malloc(n);
    }
    if (!n) {
        evpl_free(p); return NULL;
    }
    header = (struct evpl_allocation *) p - 1;
    result = evpl_allocate(n, header->alignment);
    memcpy(result, p, header->size < n ? header->size : n);
    evpl_free(p);
    return result;
} /* evpl_realloc */
#else  /* ifdef _WIN32 */
SYMBOL_EXPORT void *
evpl_malloc(unsigned int size)
{
    void *p = malloc(size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_malloc */

SYMBOL_EXPORT void *
evpl_zalloc(unsigned int size)
{
    void *p = calloc(1, size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_zalloc */

SYMBOL_EXPORT void *
evpl_calloc(
    unsigned int n,
    unsigned int size)
{
    void *p = calloc(n, size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u chunks of %u bytes\n", n, size);
    }

    return p;
} /* evpl_calloc */

SYMBOL_EXPORT void *
evpl_realloc(
    void        *p,
    unsigned int size)
{
    void *np = realloc(p, size);

    if (!np && size) {
        evpl_core_fatal("Failed to reallocate %u bytes\n", size);
    }

    return np;
} /* evpl_realloc */

SYMBOL_EXPORT void *
evpl_valloc(
    unsigned int size,
    unsigned int alignment)
{
    void  *p;
    size_t padded_size = (size + alignment - 1) & ~(alignment - 1);

    p = aligned_alloc(alignment, padded_size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_valloc */

SYMBOL_EXPORT void
evpl_free(void *p)
{
    free(p);
} /* evpl_free */

#endif /* ifdef _WIN32 */
