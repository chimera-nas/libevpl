// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include <stdint.h>

struct evpl_block_device;
struct evpl_block_queue;

struct evpl_block_device *
evpl_block_open_device(
    enum evpl_block_protocol_id protocol,
    const char *uri);

void evpl_block_close_device(
    struct evpl_block_device *blockdev);

uint64_t evpl_block_size(
    struct evpl_block_device *blockdev);

uint64_t evpl_block_max_request_size(
    struct evpl_block_device *blockdev);

struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl *evpl,
    struct evpl_block_device *blockdev);

void evpl_block_close_queue(
    struct evpl *evpl,
    struct evpl_block_queue *queue);

void evpl_block_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void (*callback)(int status, void *private_data),
    void *private_data);

void evpl_block_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void (*callback)(int status, void *private_data),
    void *private_data);

void evpl_block_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void (*callback)(int status, void *private_data),
    void *private_data);