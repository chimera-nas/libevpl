#pragma once

#include <stddef.h>

#define SYMBOL_EXPORT __attribute__((visibility("default")))

#ifndef unlikely
#define unlikely(x)                     __builtin_expect(!!(x), 0)
#endif // ifndef unlikely

#ifndef likely
#define likely(x)                       __builtin_expect(!!(x), 1)
#endif // ifndef likely

#define container_of(ptr, type, member) ({            \
        typeof(((type *) 0)->member) * __mptr = (ptr); \
        (type *) ((char *) __mptr - offsetof(type, member)); })

#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif // ifndef FORCE_INLINE