// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Growing an iovec ring has to carry the waist over into the new index space
 * along with head and tail.  The waist is only moved by the RDMA CM protocol,
 * which needs a device to exercise, so the ring is driven here directly.
 */

#include <stdio.h>

#include "core/iovec_ring.h"

#define RING_SIZE 8
#define IOVEC_LEN 64

int
main(
    int   argc,
    char *argv[])
{
    struct evpl           *evpl;
    struct evpl_iovec_ring ring;
    struct evpl_iovec      iovec;
    struct evpl_iovec     *waist;
    void                  *old_entry;
    int                    i, old_size;

    evpl_init(NULL);

    evpl = evpl_create(NULL);

    evpl_iovec_ring_alloc(&ring, RING_SIZE, IOVEC_LEN);

    for (i = 0; i < RING_SIZE - 1; i++) {
        evpl_iovec_alloc(evpl, IOVEC_LEN, IOVEC_LEN, 1, 0, &iovec);
        evpl_iovec_ring_add(&ring, &iovec);
    }

    /* Drain most of the ring and refill it, which leaves tail near the top of
     * the array and head wrapped around below it. */
    for (i = 0; i < RING_SIZE - 2; i++) {
        evpl_iovec_release_internal(evpl, evpl_iovec_ring_tail(&ring));
        evpl_iovec_ring_remove(&ring);
    }

    for (i = 0; i < RING_SIZE - 2; i++) {
        evpl_iovec_alloc(evpl, IOVEC_LEN, IOVEC_LEN, 1, 0, &iovec);
        evpl_iovec_ring_add(&ring, &iovec);
    }

    /* A waist that has wrapped as well, so it sits below tail. */
    ring.waist = 1;

    if (!evpl_iovec_ring_is_full(&ring) || ring.waist >= ring.tail) {
        fprintf(stderr, "setup did not produce a full ring with a wrapped "
                "waist (head %d waist %d tail %d)\n",
                ring.head, ring.waist, ring.tail);
        return 1;
    }

    old_size  = ring.size;
    old_entry = ring.iovec[ring.waist].data;

    /* The ring is full, so this add grows it. */
    evpl_iovec_alloc(evpl, IOVEC_LEN, IOVEC_LEN, 1, 0, &iovec);
    evpl_iovec_ring_add(&ring, &iovec);

    if (ring.size != old_size << 1) {
        fprintf(stderr, "ring did not grow (size %d)\n", ring.size);
        return 1;
    }

    if (ring.waist < 0 || ring.waist >= ring.size) {
        fprintf(stderr, "waist %d is outside a ring of %d after resize\n",
                ring.waist, ring.size);
        return 1;
    }

    waist = evpl_iovec_ring_waist(&ring);

    if (!waist) {
        fprintf(stderr, "waist caught up with head across the resize\n");
        return 1;
    }

    if (waist->data != old_entry) {
        fprintf(stderr, "waist names a different entry after resize\n");
        return 1;
    }

    evpl_iovec_ring_clear(evpl, &ring);
    evpl_iovec_ring_free(&ring);

    evpl_destroy(evpl);

    return 0;
} /* main */
