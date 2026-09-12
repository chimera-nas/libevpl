// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once

#ifdef _WIN32
#define EVPL_EXPORT   __declspec(dllexport)
#define EVPL_IMPORT   __declspec(dllimport)
#define EVPL_NORETURN __declspec(noreturn)
#define EVPL_ALIGN(n)     __declspec(align(n))
#define EVPL_PRINTF(a, b)
#else // ifdef _WIN32
#define EVPL_EXPORT   __attribute__((visibility("default")))
#define EVPL_IMPORT   EVPL_EXPORT
#define EVPL_NORETURN __attribute__((noreturn))
#define EVPL_ALIGN(n)     __attribute__((aligned(n)))
#define EVPL_PRINTF(a, b) __attribute__((format(printf, a, b)))
#endif // ifdef _WIN32

#ifdef EVPL_BUILD
#define EVPL_API      EVPL_EXPORT
#else // ifdef EVPL_BUILD
#define EVPL_API      EVPL_IMPORT
#endif // ifdef EVPL_BUILD
#ifdef EVPL_HTTP_BUILD
#define EVPL_HTTP_API EVPL_EXPORT
#else // ifdef EVPL_HTTP_BUILD
#define EVPL_HTTP_API EVPL_IMPORT
#endif // ifdef EVPL_HTTP_BUILD
#ifdef EVPL_RPC2_BUILD
#define EVPL_RPC2_API EVPL_EXPORT
#else // ifdef EVPL_RPC2_BUILD
#define EVPL_RPC2_API EVPL_IMPORT
#endif // ifdef EVPL_RPC2_BUILD
#ifdef EVPL_OTEL_BUILD
#define EVPL_OTEL_API EVPL_EXPORT
#else // ifdef EVPL_OTEL_BUILD
#define EVPL_OTEL_API EVPL_IMPORT
#endif // ifdef EVPL_OTEL_BUILD
