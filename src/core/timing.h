// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define NS_PER_S (1000000000UL)


static inline int64_t
evpl_ts_interval(
    const struct timespec *end,
    const struct timespec *start)
{
    return NS_PER_S * (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->
                                                       tv_nsec);
} // evpl_ts_interval

static inline int
evpl_ts_compare(
    const struct timespec *a,
    const struct timespec *b)
{
    if (a->tv_sec == b->tv_sec) {
        if (a->tv_nsec < b->tv_nsec) {
            return -1;
        } else if (a->tv_nsec > b->tv_nsec) {
            return 1;
        }
        return 0;
    } else if (a->tv_sec < b->tv_sec) {
        return -1;
    } else {
        return 1;
    }
} // evpl_ts_compare