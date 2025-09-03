// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once


#define EVPL_LOG_NONE  0
#define EVPL_LOG_DEBUG 1
#define EVPL_LOG_INFO  2
#define EVPL_LOG_ERROR 3
#define EVPL_LOG_FATAL 4

void evpl_debug(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_info(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_error(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);

__attribute__((noreturn))
void evpl_fatal(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);

__attribute__((noreturn))
void evpl_abort(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);

#define evpl_fatal_if(cond, ...) \
        if (cond)                    \
        {                            \
            evpl_fatal(__VA_ARGS__); \
        }

#define evpl_abort_if(cond, ...) \
        if (cond)                    \
        {                            \
            evpl_abort(__VA_ARGS__); \
        }


#if defined(EVPL_ASSERT)
#define evpl_assert(module, file, line, cond) \
        if (!(cond)) { \
            evpl_abort(module, file, line, "assertion failed: " #cond); \
        }
#else // if defined(EVPL_ASSERT)
#define evpl_assert(module, file, line, cond)
#endif // if defined(EVPL_ASSERT)

#define evpl_core_debug(...)   evpl_debug("core", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_core_info(...)    evpl_info("core", __FILE__, __LINE__, \
                                         __VA_ARGS__)
#define evpl_core_error(...)   evpl_error("core", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_core_fatal(...)   evpl_fatal("core", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_core_abort(...)   evpl_abort("core", __FILE__, __LINE__, \
                                          __VA_ARGS__)

#define evpl_core_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "core", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_core_abort_if(cond, ...) \
        evpl_abort_if(cond, "core", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_core_assert(cond) evpl_assert("core", __FILE__, __LINE__, cond)