// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include "evpl/evpl.h"

typedef struct evpl_iovec xdr_iovec;

#define xdr_iovec_data(iov)          ((iov)->data)
#define xdr_iovec_len(iov)           ((iov)->length)

#define xdr_iovec_set_data(iov, ptr) ((iov)->data = (ptr))
#define xdr_iovec_set_len(iov, len)  ((iov)->length = (len))

#define xdr_iovec_copy_private(out, in) \
        {                                   \
            (out)->private = (in)->private; \
            evpl_iovec_addref(in); \
        }

#define xdr_iovec_move_private(out, in) \
        {                                   \
            (out)->private = (in)->private; \
        }

#define xdr_iovec_set_private_null(out) \
        {                                   \
            (out)->private = NULL;          \
        }
