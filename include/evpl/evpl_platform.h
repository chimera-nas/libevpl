// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // ifndef WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif // ifndef NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <errno.h>

typedef SRWLOCK evpl_mutex_t;
typedef CONDITION_VARIABLE evpl_cond_t;
typedef INIT_ONCE evpl_once_t;
typedef HANDLE evpl_native_thread_t;
typedef DWORD evpl_thread_id_t;
typedef size_t evpl_native_thread_attr_t;
/* Endpoint resolution is infrequent; serialize readers and writers on Windows
* so its single unlock operation has no thread-local lock-mode bookkeeping. */
typedef SRWLOCK evpl_rwlock_t;
#define EVPL_MUTEX_INITIALIZER SRWLOCK_INIT
#define EVPL_ONCE_INIT         INIT_ONCE_STATIC_INIT

static inline int evpl_mutex_init(
    evpl_mutex_t *m,
    const void   *attr) { (void) attr; InitializeSRWLock(m); return 0; }
static inline int evpl_mutex_destroy(evpl_mutex_t *m) { (void) m; return 0; }
static inline int evpl_mutex_lock(evpl_mutex_t *m) { AcquireSRWLockExclusive(m); return 0; }
static inline int evpl_mutex_unlock(evpl_mutex_t *m) { ReleaseSRWLockExclusive(m); return 0; }
static inline int evpl_cond_init(
    evpl_cond_t *c,
    const void  *attr) { (void) attr; InitializeConditionVariable(c); return 0; }
static inline int evpl_cond_destroy(evpl_cond_t *c) { (void) c; return 0; }
static inline int evpl_cond_wait(
    evpl_cond_t  *c,
    evpl_mutex_t *m) { return SleepConditionVariableSRW(c, m, INFINITE, 0) ? 0 : (int) GetLastError(); }
static inline int evpl_cond_signal(evpl_cond_t *c) { WakeConditionVariable(c); return 0; }
static inline int evpl_cond_broadcast(evpl_cond_t *c) { WakeAllConditionVariable(c); return 0; }
static inline int evpl_rwlock_init(
    evpl_rwlock_t *m,
    const void    *attr) { return evpl_mutex_init(m, attr); }
static inline int evpl_rwlock_rdlock(evpl_rwlock_t *m) { return evpl_mutex_lock(m); }
static inline int evpl_rwlock_wrlock(evpl_rwlock_t *m) { return evpl_mutex_lock(m); }
static inline int evpl_rwlock_unlock(evpl_rwlock_t *m) { return evpl_mutex_unlock(m); }
static inline evpl_thread_id_t evpl_current_thread(void) { return GetCurrentThreadId(); }
static inline int evpl_thread_equal(
    evpl_thread_id_t a,
    evpl_thread_id_t b) { return a == b; }

static BOOL CALLBACK
evpl_once_callback(
    PINIT_ONCE once,
    PVOID      parameter,
    PVOID     *context)
{
    void(**fn)(void) = parameter;
    (void) once; (void) context;
    (*fn)();
    return TRUE;
} // evpl_once_callback
static inline int
evpl_once(
    evpl_once_t *once,
    void       (*fn)(
        void))
{
    return InitOnceExecuteOnce(once, evpl_once_callback, &fn, NULL) ? 0 : (int) GetLastError();
} // evpl_once

struct evpl_native_thread_start { void              *(*fn)(
                                      void *); void *arg; };
static unsigned __stdcall
evpl_native_thread_entry(void *arg)
{
    struct evpl_native_thread_start start = *(struct evpl_native_thread_start *) arg;

    free(arg);
    start.fn(start.arg);
    return 0;
} // evpl_native_thread_entry
static inline int evpl_native_thread_attr_init(evpl_native_thread_attr_t *a) { *a = 0; return 0; }
static inline int evpl_native_thread_attr_destroy(evpl_native_thread_attr_t *a) { (void) a; return 0; }
static inline int evpl_native_thread_attr_setstacksize(
    evpl_native_thread_attr_t *a,
    size_t                     n) { *a = n; return 0; }
static inline int
evpl_native_thread_create(
    evpl_native_thread_t            *t,
    const evpl_native_thread_attr_t *a,
    void *                         (*fn)(
        void *),
    void                            *arg)
{
    struct evpl_native_thread_start *start = malloc(sizeof(*start));

    if (!start) {
        return ENOMEM;
    }
    start->fn = fn; start->arg = arg;
    *t        = (HANDLE) _beginthreadex(NULL, a ? (unsigned) *a : 0, evpl_native_thread_entry, start, 0, NULL);
    if (!*t) {
        int error = errno; free(start); return error;
    }
    return 0;
} // evpl_native_thread_create
static inline int
evpl_native_thread_join(
    evpl_native_thread_t t,
    void               **result)
{
    if (WaitForSingleObject(t, INFINITE) != WAIT_OBJECT_0) {
        return (int) GetLastError();
    }
    if (result) {
        *result = NULL;
    }
    CloseHandle(t);
    return 0;
} // evpl_native_thread_join
#else // ifdef _WIN32
#include <pthread.h>
typedef pthread_mutex_t evpl_mutex_t;
typedef pthread_cond_t evpl_cond_t;
typedef pthread_once_t evpl_once_t;
typedef pthread_t evpl_native_thread_t;
typedef pthread_t evpl_thread_id_t;
typedef pthread_attr_t evpl_native_thread_attr_t;
typedef pthread_rwlock_t evpl_rwlock_t;
#define EVPL_MUTEX_INITIALIZER               PTHREAD_MUTEX_INITIALIZER
#define EVPL_ONCE_INIT                       PTHREAD_ONCE_INIT
#define evpl_mutex_init                      pthread_mutex_init
#define evpl_mutex_destroy                   pthread_mutex_destroy
#define evpl_mutex_lock                      pthread_mutex_lock
#define evpl_mutex_unlock                    pthread_mutex_unlock
#define evpl_cond_init                       pthread_cond_init
#define evpl_cond_destroy                    pthread_cond_destroy
#define evpl_cond_wait                       pthread_cond_wait
#define evpl_cond_signal                     pthread_cond_signal
#define evpl_cond_broadcast                  pthread_cond_broadcast
#define evpl_once                            pthread_once
#define evpl_rwlock_init                     pthread_rwlock_init
#define evpl_rwlock_rdlock                   pthread_rwlock_rdlock
#define evpl_rwlock_wrlock                   pthread_rwlock_wrlock
#define evpl_rwlock_unlock                   pthread_rwlock_unlock
#define evpl_native_thread_attr_init         pthread_attr_init
#define evpl_native_thread_attr_destroy      pthread_attr_destroy
#define evpl_native_thread_attr_setstacksize pthread_attr_setstacksize
#define evpl_native_thread_create            pthread_create
#define evpl_native_thread_join              pthread_join
#define evpl_current_thread                  pthread_self
#define evpl_thread_equal                    pthread_equal
#endif // ifdef _WIN32
