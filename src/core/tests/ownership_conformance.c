// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "evpl/evpl.h"
#include "rpc2/xdr_iovec.h"
#include "evpl/evpl_rpc2_program.h"
#include "tests/test_mbt.h"
#include "ownership_cases.h"

/* The holder exercises the public encoding ownership contract independently
 * of network transport. Its descriptor storage dies at Destroy; transferred
 * buffer references must outlive that storage. Real RPC callbacks separately
 * test retaining decoded data beyond request teardown. */
struct holder {
    struct evpl_rpc2_encoding   encoding;
    struct evpl_rpc2_rdma_chunk chunk;
    struct evpl_iovec           iov;
};

static struct evpl_iovec *
owned(struct evpl_iovec *iov)
{
    evpl_test_abort_if(!iov || !iov->data || !iov->ref, "model expected an owned view");
    return iov;
} /* owned */

static void
check_view(
    struct evpl_iovec *iov,
    unsigned int       offset,
    unsigned int       length,
    unsigned int       refs,
    unsigned int       allocator_refs)
{
    struct evpl_iovec_ref *ref = evpl_iovec_get_ref(owned(iov));
    unsigned int           actual;

    if (ref->flags & EVPL_IOVEC_FLAG_SHARED) {
        actual = atomic_load(&ref->refcnt_atomic);
    } else {
        actual = ref->refcnt;
    }

    evpl_test_abort_if(actual != refs + allocator_refs, "reference ledger mismatch: %u != %u + %u", actual, refs,
                       allocator_refs);
    evpl_test_abort_if(iov->length != length, "view length differs from model");
    for (unsigned int j = 0; j < length; j++) {
        evpl_test_abort_if(((unsigned char *) iov->data)[j] != (unsigned char) ((offset + j) * 7 + 3),
                           "retained view bytes differ from model");
    }
} /* check_view */

int
main(void)
{
    struct evpl_global_config   *config = evpl_global_config_init();

    test_evpl_set_core_mech(config);
    evpl_init(config);
    struct evpl                 *evpl = test_mbt_create(NULL);
    struct evpl_iovec            a = { 0 }, b = { 0 }, c = { 0 };
    struct holder               *request        = NULL;
    const struct ownership_step *previous       = NULL;
    unsigned int                 allocator_refs = 0;
    unsigned int                 flags          = getenv("EVPL_TEST_SHARED") ? EVPL_IOVEC_FLAG_SHARED : 0;
    for (size_t i = 0; i < sizeof(ownership_steps) / sizeof(ownership_steps[0]); i++) {
        const struct ownership_step *s = &ownership_steps[i];
        switch (s->op) {
            case ownership_Reset:
                if (previous && previous->a) {
                    evpl_iovec_release(evpl, owned(&a));
                }
                if (previous && previous->b) {
                    evpl_iovec_release(evpl, owned(&b));
                }
                if (previous && previous->c) {
                    evpl_iovec_release(evpl, owned(&c));
                }
                if (request) {
                    if (request->chunk.niov) {
                        evpl_iovec_release(evpl, owned(&request->iov));
                    }
                    free(request);
                    request = NULL;
                }
                break;
            case ownership_Allocate: {
                evpl_test_abort_if(evpl_iovec_alloc(evpl, 64, 1, 1, flags, &a) != 1, "allocate failed");
                struct evpl_iovec_ref *ref = evpl_iovec_get_ref(&a);
                allocator_refs = (flags ? atomic_load(&ref->refcnt_atomic) : ref->refcnt) - 1;
                for (unsigned int j = 0; j < 64; j++) {
                    ((unsigned char *) a.data)[j] = j * 7 + 3;
                }
                break;
            }
            case ownership_Clone: evpl_iovec_clone(&b, owned(&a)); break;
            case ownership_Move: evpl_iovec_move(&c, owned(&a)); break;
            case ownership_Slice: evpl_iovec_move_segment(&c, owned(&a), s->offset, s->length); break;
            case ownership_ReleaseA: evpl_iovec_release(evpl, owned(&a)); break;
            case ownership_ReleaseB: evpl_iovec_release(evpl, owned(&b)); break;
            case ownership_ReleaseC: evpl_iovec_release(evpl, owned(&c)); break;
            case ownership_Request:
                request = calloc(1, sizeof(*request));
                evpl_test_abort_if(!request, "allocate holder failed");
                evpl_iovec_move(&request->iov, owned(&a));
                request->chunk.iov            = &request->iov;
                request->chunk.niov           = 1;
                request->encoding.write_chunk = &request->chunk;
                break;
            case ownership_Take: {
                evpl_test_abort_if(!request, "take requires a live encoding holder");
                struct evpl_iovec *iov;
                int                niov;
                evpl_rpc2_encoding_take_write_chunk(&request->encoding, &iov, &niov);
                evpl_test_abort_if(niov != 1 || iov != &request->iov || request->chunk.niov,
                                   "write chunk ownership not transferred");
                evpl_iovec_move(&a, owned(iov));
                break;
            }
            case ownership_TakeEmpty: {
                evpl_test_abort_if(!request, "empty take requires a live encoding holder");
                int niov = -1;
                evpl_rpc2_encoding_take_write_chunk(&request->encoding, NULL, &niov);
                evpl_test_abort_if(niov, "write chunk transferred twice");
                evpl_rpc2_encoding_take_write_chunk(&request->encoding, NULL, NULL);
                break;
            }
            case ownership_Destroy:
                evpl_test_abort_if(!request, "destroy requires a live encoding holder");
                if (request->chunk.niov) {
                    evpl_iovec_release(evpl, owned(&request->iov));
                }
                free(request);
                request = NULL;
                break;
            case ownership_Inspect: break;
            default: abort();
        } /* switch */
        evpl_test_abort_if(!!request != s->request || (request && request->chunk.niov != s->r),
                           "holder state differs from model");
        if (s->a) {
            check_view(&a, 0, 64, s->refs, allocator_refs);
        }
        if (s->b) {
            check_view(&b, 0, 64, s->refs, allocator_refs);
        }
        if (s->c) {
            check_view(&c, s->offset, s->length, s->refs, allocator_refs);
        }
        if (s->r) {
            evpl_test_abort_if(!request, "model expected a live encoding holder");
            check_view(&request->iov, 0, 64, s->refs, allocator_refs);
        }
        previous = s;
    }
    if (previous->a) {
        evpl_iovec_release(evpl, owned(&a));
    }
    if (previous->b) {
        evpl_iovec_release(evpl, owned(&b));
    }
    if (previous->c) {
        evpl_iovec_release(evpl, owned(&c));
    }
    if (request) {
        if (request->chunk.niov) {
            evpl_iovec_release(evpl, owned(&request->iov));
        }
        free(request);
    }
    test_mbt_destroy(evpl);
    return 0;
} /* main */
