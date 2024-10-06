#pragma once

#include "core/evpl.h"

typedef struct evpl_bvec xdr_iovec;

#define xdr_iovec_data(iov)             ((iov)->data)
#define xdr_iovec_len(iov)              ((iov)->length)

#define xdr_iovec_set_data(iov, ptr)    ((iov)->data = (ptr))
#define xdr_iovec_set_len(iov, len)     ((iov)->length = (len))

#define xdr_iovec_copy_private(out, in) { \
            (out)->buffer = (in)->buffer; \
}
