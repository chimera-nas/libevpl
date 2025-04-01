
#include <stdlib.h>
#include "logging.h"
#include "macros.h"

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
