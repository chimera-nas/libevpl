// SPDX-FileCopyrightText: 2025 - 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "evpl/evpl.h"

/*
 * Optional core-mechanism override for the test suite.
 *
 * ctest registers each socket test once per event-loop mechanism compiled into
 * the build (see src/core/socket/tests/CMakeLists.txt) and selects it through
 * EVPL_TEST_CORE_MECH.  Keeping this in the harness rather than in the library
 * means no test source -- and no libevpl consumer -- needs to know about it.
 */
static inline void
test_evpl_set_core_mech(struct evpl_global_config *config)
{
    const char *mech = getenv("EVPL_TEST_CORE_MECH");

    if (!mech || !*mech) {
        return;
    }

    if (strcmp(mech, "epoll") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_EPOLL);
    } else if (strcmp(mech, "kqueue") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_KQUEUE);
    } else if (strcmp(mech, "select") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_SELECT);
    } else {
        fprintf(stderr, "EVPL_TEST_CORE_MECH: unknown mechanism '%s'\n", mech);
        exit(1);
    }
} /* test_evpl_set_core_mech */

static inline void
test_evpl_config(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_tls_verify_peer(config, 0);

    test_evpl_set_core_mech(config);

    evpl_init(config);
} // test_setup_tls_config

/*
 * Endpoint helpers for the protocol-parameterized tests.
 *
 * A local (AF_UNIX) transport has no wildcard bind address and no port: both
 * ends must name the same socket.  The IP convention of listening on 0.0.0.0
 * while dialing 127.0.0.1 has no analogue, so each test normalizes its
 * `address` global through test_address() once, right after getopt, and
 * derives the listen address from test_listen_address().
 *
 * For IP protocols both are identities and behavior is unchanged.
 */

static char test_path_buf[108];

static inline int
test_address_is_local(const char *address)
{
    return address && (address[0] == '/' || address[0] == '@');
} /* test_address_is_local */

/*
 * Resolve the effective address for this run.
 *
 * IP protocols: returned unchanged (-a, else 127.0.0.1).
 *
 * Local protocols: an explicit -a path wins; otherwise synthesize a
 * per-binary, per-process path under TMPDIR.  A network namespace does not
 * isolate the filesystem, so unlike ports these names are shared across every
 * concurrently running test -- the binary name and pid are what keep
 * `ctest -j` collision-free, and they also guarantee a socket left behind by
 * a crashed run is never reused.
 */
static inline const char *
test_address(
    enum evpl_protocol_id proto,
    const char           *address,
    const char           *argv0)
{
    const char *tmpdir, *base, *slash;
    int         len;

    if (!evpl_protocol_is_local(proto) || test_address_is_local(address)) {
        return address;
    }

    tmpdir = getenv("TMPDIR");

    if (!tmpdir || tmpdir[0] != '/') {
        tmpdir = "/tmp";
    }

    base  = argv0 ? argv0 : "evpl";
    slash = strrchr(base, '/');

    if (slash) {
        base = slash + 1;
    }

    len = snprintf(test_path_buf, sizeof(test_path_buf),
                   "%s/evpl-%.32s-%d.sock", tmpdir, base, (int) getpid());

    /* sun_path is only 108 bytes, so a long TMPDIR would truncate into a
     * nonsensical path; fall back to /tmp rather than guess. */
    if (len < 0 || (size_t) len >= sizeof(test_path_buf)) {
        snprintf(test_path_buf, sizeof(test_path_buf), "/tmp/evpl-%.32s-%d.sock",
                 base, (int) getpid());
    }

    return test_path_buf;
} /* test_address */

/* The address a server should bind.  For IP that is the wildcard; a local
 * transport has no wildcard, so it is the socket name itself.
 *
 * The endpoint itself still comes from plain evpl_endpoint_create(), which
 * recognizes a leading '/' or '@' as a local socket name. */
static inline const char *
test_listen_address(const char *address)
{
    return test_address_is_local(address) ? address : "0.0.0.0";
} /* test_listen_address */
