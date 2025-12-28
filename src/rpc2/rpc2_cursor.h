// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "evpl/evpl.h"
#include "rpc2/xdr_iovec.h"

#include "rpc2_xdr.h"
#include "rpcrdma1_xdr.h"

struct evpl_rpc2_iovec_cursor {
    struct evpl_iovec *iov;
    int                offset;
    int                niov;
};


static inline void
evpl_rpc2_iovec_cursor_init(
    struct evpl_rpc2_iovec_cursor *cursor,
    struct evpl_iovec             *iov,
    int                            niov)
{
    cursor->iov    = iov;
    cursor->niov   = niov;
    cursor->offset = 0;
} /* evpl_rpc2_iovec_cursor_init */

static int
evpl_rpc2_iovec_cursor_move(
    struct evpl_rpc2_iovec_cursor *cursor,
    xdr_dbuf                      *dbuf,
    struct evpl_iovec            **iov,
    int                            length)
{
    int                chunk, left = length, niov = 0;
    struct evpl_iovec *cur_iov;
    int                cur_niov, cur_offset;

    cur_iov    = cursor->iov;
    cur_niov   = cursor->niov;
    cur_offset = cursor->offset;

    while (left && cur_niov) {
        chunk = cur_iov->length - cur_offset;

        if (left < chunk) {
            chunk = left;
        }

        left -= chunk;
        niov++;
        cur_niov--;
        cur_iov++;
        cur_offset = 0;
    }

    if (unlikely(left)) {
        evpl_rpc2_abort("evpl_rpc2_iovec_cursor_move: left = %d after niov %d", left, niov);
        return -1;
    }

    *iov = xdr_dbuf_alloc_space(sizeof(*iov) * niov, dbuf);

    if (unlikely(iov == NULL)) {
        return -1;
    }

    left = length;

    cur_niov = 0;

    while (left && cursor->niov) {
        chunk = cursor->iov->length - cursor->offset;

        if (left < chunk) {
            chunk = left;
        }

        (*iov)[cur_niov].data   = cursor->iov->data + cursor->offset;
        (*iov)[cur_niov].length = chunk;

        cursor->offset += chunk;

        if (cursor->offset == cursor->iov->length) {
            evpl_iovec_move(&(*iov)[cur_niov], cursor->iov);

            cursor->iov++;
            cursor->niov--;
            cursor->offset = 0;
        } else {
            evpl_iovec_clone_segment(&(*iov)[cur_niov], cursor->iov, cursor->offset, chunk);
        }

        cur_niov++;
        left -= chunk;
    }

    return niov;
} /* evpl_rpc2_iovec_cursor_move */
