// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include <stddef.h>
#include "evpl/evpl_export.h"
#define SYMBOL_EXPORT EVPL_EXPORT
#ifndef unlikely
#ifdef _MSC_VER
#define unlikely(x)                     (!!(x))
#define likely(x)                       (!!(x))
#else // ifdef _MSC_VER
#define unlikely(x)                     __builtin_expect(!!(x), 0)
#define likely(x)                       __builtin_expect(!!(x), 1)
#endif // ifdef _MSC_VER
#endif // ifndef unlikely
#ifndef container_of
#define container_of(ptr, type, member) ((type *) ((char *) (ptr) - offsetof(type, member)))
#endif // ifndef container_of
#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#define NEVER_INLINE __declspec(noinline)
#else // ifdef _MSC_VER
#define FORCE_INLINE __attribute__((always_inline)) inline
#define NEVER_INLINE __attribute__((noinline))
#endif // ifdef _MSC_VER
