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
 * XDR iovec operations.
 *
 * copy: Clones the iovec, taking a new reference (refcount +1). Both source
 *       and dest have valid references.
 *
 * move: Moves ownership of the iovec without changing refcount. Source becomes
 *       invalid after the move.
 */
#define xdr_iovec_copy_private(out, in) \
        evpl_iovec_clone(out, in)

#define xdr_iovec_move_private(out, in) \
        evpl_iovec_move(out, in)
