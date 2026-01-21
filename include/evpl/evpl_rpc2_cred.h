// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>

/*
 * Maximum number of supplementary groups in AUTH_SYS credentials.
 * Per RFC 1831, this is limited to 16.
 */
#define EVPL_RPC2_AUTH_SYS_MAX_GIDS 16

/*
 * Authentication flavor values (from ONC RPC).
 * Note: These must match the auth_flavor enum in rpc2_xdr.h
 */
#define EVPL_RPC2_AUTH_NONE  0
#define EVPL_RPC2_AUTH_SYS   1
#define EVPL_RPC2_AUTH_SHORT 2

/*
 * RPC2 credential structure.
 *
 * This structure holds the parsed authentication credentials from an
 * incoming RPC call. It supports AUTH_NONE and AUTH_SYS flavors.
 *
 * For AUTH_SYS, the authsys struct contains the credentials using simple
 * C types. The gids pointer points to externally managed storage:
 * - Server side: allocated by dbuf during unmarshalling
 * - Client side: points directly to the caller's credential storage
 *
 * Note: The actual evpl_rpc2_cred structure has additional internal
 * fields for RCU-based cache management. This header provides only
 * the fields relevant to credential consumers.
 */
struct evpl_rpc2_cred {
    uint32_t               flavor; /* auth_flavor: AUTH_NONE, AUTH_SYS, AUTH_SHORT */
    uint64_t               key;
    struct evpl_rpc2_cred *next;

    struct {
        uint32_t    uid;
        uint32_t    gid;
        uint32_t    num_gids;
        uint32_t   *gids;
        const char *machinename;
        int         machinename_len;
    } authsys;

    /* Additional internal fields follow in the actual structure */
};

