// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_rdma.h directly, include evpl/evpl.h instead"
#endif // ifndef EVPL_INCLUDED

void evpl_rdma_get_address(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovec,
    uint32_t          *r_key,
    uint64_t          *r_address);

void evpl_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data);

void evpl_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data);