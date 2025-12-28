// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "evpl/evpl.h"

typedef struct evpl_iovec xdr_iovec;

#define xdr_iovec_data(iov)          ((iov)->data)
#define xdr_iovec_len(iov)           ((iov)->length)

#define xdr_iovec_set_data(iov, ptr) ((iov)->data = (ptr))
#define xdr_iovec_set_len(iov, len)  ((iov)->length = (len))

/*
 * XDR iovec private field operations.
 * These only operate on the ref field; data/length are set separately.
 *
 * copy: Takes a new reference (refcount +1). Both source and dest have valid
 *       references.
 *
 * move: Takes the reference without changing refcount. source becomes invalid.
 */
#define xdr_iovec_copy_private(out, in) \
        evpl_iovec_clone(out, in)

#ifdef EVPL_IOVEC_TRACE
#define xdr_iovec_move_private(out, in) \
        evpl_iovec_move(out, in)
#else // ifdef EVPL_IOVEC_TRACE
#define xdr_iovec_move_private(out, in) \
        do { \
            (out)->ref = (in)->ref; \
        } while (0)
#endif // ifdef EVPL_IOVEC_TRACE
