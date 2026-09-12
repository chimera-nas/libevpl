// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "evpl/evpl_platform.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#include <afunix.h>
#include <io.h>
#include <malloc.h>
#include <intrin.h>
typedef intptr_t ssize_t;
typedef int socklen_t;
typedef ADDRESS_FAMILY sa_family_t;
struct iovec { void *iov_base; size_t iov_len; };
#define alloca          _alloca
#define evpl_bswap32    _byteswap_ulong
#define strcasecmp      _stricmp
#define strncasecmp     _strnicmp
#define strdup          _strdup
#define CLOCK_MONOTONIC 1
#define CLOCK_REALTIME  2
static inline int
evpl_clock_gettime(
    int              clock,
    struct timespec *ts)
{
    if (clock == CLOCK_MONOTONIC) {
        LARGE_INTEGER now, frequency;
        QueryPerformanceCounter(&now);
        QueryPerformanceFrequency(&frequency);
        ts->tv_sec  = (time_t) (now.QuadPart / frequency.QuadPart);
        ts->tv_nsec = (long) ((now.QuadPart % frequency.QuadPart) * 1000000000ULL / frequency.QuadPart);
    } else {
        FILETIME       ft;
        ULARGE_INTEGER value;
        GetSystemTimePreciseAsFileTime(&ft);
        value.LowPart   = ft.dwLowDateTime; value.HighPart = ft.dwHighDateTime;
        value.QuadPart -= 116444736000000000ULL;
        ts->tv_sec      = (time_t) (value.QuadPart / 10000000ULL);
        ts->tv_nsec     = (long) ((value.QuadPart % 10000000ULL) * 100);
    }
    return 0;
} // evpl_clock_gettime
static inline void evpl_sleep_us(uint64_t us) { Sleep((DWORD) ((us + 999) / 1000)); }
static inline void evpl_sleep(unsigned int seconds) { Sleep(seconds * 1000); }
static inline unsigned int evpl_process_id(void) { return GetCurrentProcessId(); }
static inline unsigned int evpl_page_size(void) { SYSTEM_INFO s; GetSystemInfo(&s); return s.dwPageSize; }
static inline struct tm * evpl_gmtime(
    const time_t *t,
    struct tm    *tm) { return gmtime_s(tm, t) ? NULL : tm; }
static inline struct tm * evpl_localtime(
    const time_t *t,
    struct tm    *tm) { return localtime_s(tm, t) ? NULL : tm; }
#else // ifdef _WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <alloca.h>
#include <strings.h>
#define evpl_bswap32       __builtin_bswap32
#define evpl_clock_gettime clock_gettime
#define evpl_sleep_us      usleep
#define evpl_sleep         sleep
#define evpl_process_id    getpid
#define evpl_gmtime        gmtime_r
#define evpl_localtime     localtime_r
static inline unsigned int evpl_page_size(void) { return (unsigned int) sysconf(_SC_PAGESIZE); }
#endif // ifdef _WIN32
