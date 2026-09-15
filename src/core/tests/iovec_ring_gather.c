// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/iovec_ring.h"

int
main(void)
{
    struct evpl           *evpl = evpl_create(NULL);
    struct evpl_iovec_ring ring;
    struct evpl_iovec      source, slice;

    struct { struct evpl_iovec iov[2]; uint64_t canary; } out;
    int                    i, n, offset = 0;

    evpl_iovec_ring_alloc(&ring, 8, 64);
    if (evpl_iovec_alloc(evpl, 300, 0, 1, 0, &source) != 1) {
        return 1;
    }
    for (i = 0; i < 300; i++) {
        ((unsigned char *) source.data)[i] = (unsigned char) i;
        evpl_iovec_clone_segment(&slice, &source, i, 1);
        evpl_iovec_ring_add(&ring, &slice);
    }
    evpl_iovec_release(evpl, &source);
    out.canary = UINT64_C(0x123456789abcdef0);
    n          = evpl_iovec_ring_copyv_bounded(evpl, out.iov, 2, &ring, 299);
    if (n < 1 || n > 2 || out.canary != UINT64_C(0x123456789abcdef0) || ring.length != 1) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        for (unsigned int j = 0; j < out.iov[i].length; j++) {
            if (((unsigned char *) out.iov[i].data)[j] != (unsigned char) offset++) {
                return 1;
            }
        }
        evpl_iovec_release(evpl, &out.iov[i]);
    }
    if (offset != 299) {
        return 1;
    }
    /* The final byte follows the zero-copy path, exercising partial drain. */
    n = evpl_iovec_ring_copyv_bounded(evpl, out.iov, 2, &ring, 1);
    if (n != 1 || *(unsigned char *) out.iov[0].data != (unsigned char) 299 || ring.length) {
        return 1;
    }
    evpl_iovec_release(evpl, &out.iov[0]);
    evpl_iovec_ring_free(&ring);
    evpl_destroy(evpl);
    return 0;
} /* main */
