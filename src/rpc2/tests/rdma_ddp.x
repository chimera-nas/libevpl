/*
 * SPDX-FileCopyrightText: 2025 Ben Jarvis
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * RPC2 RDMA test with Direct Data Placement (DDP) operations
 */

/* READ operation - like NFS read, uses write chunks for DDP (server writes to client) */
struct ReadRequest {
    uint64_t       offset;
    uint32_t       count;
};

struct ReadResponse {
    uint32_t       count;
    bool           eof;
    zcopaque       data<>;
};

/* WRITE operation - like NFS write, uses read chunks for DDP (server reads from client) */
struct WriteRequest {
    uint64_t       offset;
    uint32_t       count;
    zcopaque       data<>;
};

struct WriteResponse {
    uint32_t       count;
    bool           committed;
};

/* REDUCE operation - large response to trigger reply chunk */
struct ReduceRequest {
    uint32_t       response_size;
};

struct ReduceResponse {
    opaque         data<>;
};

program RDMA_DDP_PROGRAM {
    version RDMA_DDP_V1 {
        /* Read data - response uses write chunks for DDP (server writes to client) */
        ReadResponse READ(ReadRequest) = 1;

        /* Write data - request uses read chunks for DDP (server reads from client) */
        WriteResponse WRITE(WriteRequest) = 2;

        /* Reduce - triggers large reply chunk */
        ReduceResponse REDUCE(ReduceRequest) = 3;
    } = 1;
} = 0x20250001;
