#pragma once

struct evpl_dgram {
    int                  nbvec;
    struct evpl_address *addr;
};

struct evpl_dgram_ring {
    struct evpl_dgram *dgram;
    int                size;
    int                mask;
    int                alignment;
    int                head;
    int                tail;
};


static inline void
evpl_dgram_ring_alloc(
    struct evpl_dgram_ring *ring,
    int                     size,
    int                     alignment)
{
    ring->dgram = evpl_valloc(size * sizeof(struct evpl_dgram), alignment);

    ring->size      = size;
    ring->mask      = size - 1;
    ring->alignment = alignment;
    ring->head      = 0;
    ring->tail      = 0;

} // evpl_dgram_ring_alloc

static inline void
evpl_dgram_ring_resize(struct evpl_dgram_ring *ring)
{
    int                new_size  = ring->size << 1;
    struct evpl_dgram *new_dgram = evpl_valloc(
        new_size * sizeof(struct evpl_dgram), ring->alignment);

    if (ring->head > ring->tail) {
        memcpy(new_dgram, &ring->dgram[ring->tail], (ring->head - ring->tail) *
               sizeof(struct evpl_dgram));
    } else {
        memcpy(new_dgram, &ring->dgram[ring->tail], (ring->size - ring->tail) *
               sizeof(struct evpl_dgram));
        memcpy(&new_dgram[ring->size - ring->tail], ring->dgram, ring->head *
               sizeof(struct evpl_dgram));
    }

    ring->head = ring->size - 1;
    ring->tail = 0;

    evpl_free(ring->dgram);

    ring->dgram = new_dgram;
    ring->size  = new_size;
    ring->mask  = new_size - 1;
} // evpl_dgram_ring_resize

static inline void
evpl_dgram_ring_free(struct evpl_dgram_ring *ring)
{
    evpl_free(ring->dgram);
} // evpl_dgram_ring_free

static inline int
evpl_dgram_ring_is_empty(const struct evpl_dgram_ring *ring)
{
    return ring->head == ring->tail;
} // evpl_dgram_ring_is_empty

static inline int
evpl_dgram_ring_is_full(const struct evpl_dgram_ring *ring)
{
    return ((ring->head + 1) & ring->mask) == ring->tail;
} // evpl_dgram_ring_is_full

static inline struct evpl_dgram *
evpl_dgram_ring_head(struct evpl_dgram_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->dgram[ring->head];
    }
} // evpl_dgram_ring_head

static inline struct evpl_dgram *
evpl_dgram_ring_tail(struct evpl_dgram_ring *ring)
{
    if (ring->head == ring->tail) {
        return NULL;
    } else {
        return &ring->dgram[ring->tail];
    }
} // evpl_dgram_ring_tail

static inline struct evpl_dgram *
evpl_dgram_ring_next(
    struct evpl_dgram_ring *ring,
    struct evpl_dgram      *cur)
{
    int index = ((cur - ring->dgram) + 1) & ring->mask;

    if (index == ring->head) {
        return NULL;
    }

    return &ring->dgram[index];
} // evpl_dgram_ring_next

static inline struct evpl_dgram *
evpl_dgram_ring_add(struct evpl_dgram_ring *ring)
{
    struct evpl_dgram *res;

    if (evpl_dgram_ring_is_full(ring)) {
        evpl_dgram_ring_resize(ring);
    }

    res = &ring->dgram[ring->head];

    ring->head = (ring->head + 1) & ring->mask;

    return res;
} // evpl_dgram_ring_add

static inline void
evpl_dgram_ring_remove(struct evpl_dgram_ring *ring)
{
    ring->tail = (ring->tail + 1) & ring->mask;
} // evpl_dgram_ring_remove

static inline void
evpl_dgram_ring_clear(
    struct evpl            *evpl,
    struct evpl_dgram_ring *ring)
{
    ring->head = 0;
    ring->tail = 0;
} // evpl_dgram_ring_clear
