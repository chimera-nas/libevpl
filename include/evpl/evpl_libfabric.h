// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Optional libfabric integration points.
 *
 * This header uses forward declarations only, so it can be included
 * whether or not libfabric development headers are present; the setter
 * symbol itself only exists in builds compiled with libfabric support.
 */

struct evpl_global_config;
struct fid_fabric;
struct fid_domain;
struct fi_info;

/*
 * Hand evpl an externally owned libfabric fabric/domain to use instead of
 * discovering and opening its own.  All three arguments are required; the
 * fi_info must be the one the domain was created from, as it is the only
 * faithful source of the domain's mr_mode, mode bits, limits and
 * threading model.
 *
 * Contract:
 *  - evpl opens and closes only its own child objects (endpoints, CQs,
 *    EQs, AVs and memory registrations); it never closes the provided
 *    fabric or domain.
 *  - fabric, domain and info must all remain valid until evpl has shut
 *    down (evpl_cleanup runs atexit; the info is duplicated internally at
 *    first use).
 *  - the domain must not have been opened with FI_THREAD_DOMAIN, as evpl
 *    uses it from all of its threads.
 *  - the domain's endpoint type determines which evpl protocols are
 *    usable (FI_EP_MSG for the connected protocols, FI_EP_RDM for the
 *    connectionless datagram protocol).
 *  - without FI_MR_PROV_KEY, evpl allocates its memory registration keys
 *    from a high range (0x80000000 up) to reduce the chance of colliding
 *    with keys the application chose on the same domain.
 */
void evpl_global_config_set_libfabric_external_domain(
    struct evpl_global_config *config,
    struct fid_fabric         *fabric,
    struct fid_domain         *domain,
    const struct fi_info      *info);
