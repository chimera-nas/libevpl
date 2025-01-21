// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

struct evpl_uevent;
struct evpl_poll;

typedef void (*evpl_uevent_callback_t)(
    struct evpl *evpl,
    void *private_data);

struct evpl_uevent *
evpl_add_uevent(
    struct evpl *evpl,
    evpl_uevent_callback_t callback,
    void *private_data);

void evpl_arm_uevent(
    struct evpl *evpl,
    struct evpl_uevent *uevent);

void evpl_destroy_uevent(
    struct evpl *evpl,
    struct evpl_uevent *uevent);

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void *private_data);

struct evpl_poll *
evpl_add_poll(
    struct evpl *evpl,
    evpl_poll_callback_t callback,
    void *private_data);

void evpl_remove_poll(
    struct evpl *evpl,
    struct evpl_poll *poll);