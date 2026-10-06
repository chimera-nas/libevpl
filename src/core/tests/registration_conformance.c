// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <errno.h>
#include "core/rdma_mr.h"
#include "tests/test_mbt.h"
#include "registration_cases.h"

/* This internal component owns exact extents and revokes keys independently
 * of the slab allocator, which retains registrations until global cleanup. */
int
main(void)
{
    struct evpl_rdma_mr_table table;
    struct evpl_rdma_mr      *regions[2] = { NULL, NULL };
    uint32_t                  keys[2] = { 0, 0 }, revoked[2] = { 0, 0 };
    unsigned char             memory[2][64], temporary[64];
    int                       initialized = 0;

    for (size_t i = 0; i < sizeof(registration_steps) / sizeof(registration_steps[0]); i++) {
        const struct registration_step *s    = &registration_steps[i];
        int                             slot = s->slot;
        switch (s->op) {
            case registration_Reset:
                if (initialized) {
                    evpl_rdma_mr_table_cleanup(&table);
                }
                evpl_rdma_mr_table_init(&table);
                initialized = 1;
                memset(regions, 0, sizeof(regions));
                memset(keys, 0, sizeof(keys));
                memset(revoked, 0, sizeof(revoked));
                break;
            case registration_Register:
                regions[slot] = evpl_rdma_mr_register(&table, memory[slot], 64, NULL);
                keys[slot]    = regions[slot]->rkey;
                evpl_test_abort_if(!keys[slot] || keys[slot] == revoked[slot], "revoked key reused");
                break;
            case registration_Unregister:
                revoked[slot]                                                 = keys[slot];
                evpl_rdma_mr_unregister(&table, regions[slot]); regions[slot] = NULL;
                break;
            case registration_Reuse:
                evpl_test_abort_if(evpl_rdma_mr_register(&table, memory[slot], 64, regions[slot]) != regions[slot],
                                   "existing registration replaced");
                break;
            case registration_Churn:
                for (int n = 0; n < 1024; n++) {
                    struct evpl_rdma_mr *mr  = evpl_rdma_mr_register(&table, temporary, sizeof(temporary), NULL);
                    uint32_t             key = mr->rkey;
                    void                *out = NULL;
                    evpl_rdma_mr_unregister(&table, mr);
                    evpl_test_abort_if(evpl_rdma_mr_validate(&table, key, (uintptr_t) temporary, 1, &out) != -EINVAL,
                                       "temporary revoked key still valid");
                }
                break;
            case registration_Validate: {
                void    *out     = temporary;
                uint64_t address = (uintptr_t) memory[slot] + s->offset;
                int      rc      = evpl_rdma_mr_validate(&table, keys[slot], address, s->length, &out);
                evpl_test_abort_if(rc != (s->valid ? 0 : -EINVAL) ||
                                   out != (s->valid ? (void *) (uintptr_t) address : temporary),
                                   "step %zu: registration validation differs from model", i);
                break;
            }
            default: abort();
        } /* switch */
        for (int n = 0; n < 2; n++) {
            void *out  = NULL;
            int   live = n == 0 ? s->a : s->b;
            evpl_test_abort_if(evpl_rdma_mr_validate(&table, keys[n], (uintptr_t) memory[n], 64, &out) !=
                               (live ? 0 : -EINVAL), "step %zu: key lifetime differs from model", i);
            evpl_test_abort_if(live && out != memory[n], "registration points to wrong memory");
            evpl_test_abort_if(evpl_rdma_mr_validate(&table, revoked[n], (uintptr_t) memory[n], 1, &out) != -EINVAL,
                               "revoked key became valid after growth/re-registration");
        }
        evpl_test_abort_if(table.next_rkey != (uint32_t) s->issued + 1, "registration key issuance differs from model");
    }
    evpl_rdma_mr_table_cleanup(&table);
    return 0;
} /* main */
