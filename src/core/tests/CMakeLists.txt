# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(core init_no_config init_no_config.c)

# Builds the binary and registers the platform-default case; the loop below
# then runs the same binary once per mechanism compiled into this build.
# These create and destroy an evpl without touching the network, so they need
# neither a namespace nor the shared port lock.
unit_test(core init_core_mech init_core_mech.c)

foreach(mech ${EVPL_MECHANISMS})
    add_test(NAME libevpl/core/init_core_mech_${mech}
             COMMAND ${CMAKE_CURRENT_BINARY_DIR}/core_init_core_mech ${mech})
endforeach()
unit_test(core init_auto_no_config init_auto_no_config.c)
unit_test(core init_with_clean_config init_with_clean_config.c)
unit_test(core unused_config unused_config.c)
unit_test(core tls_cipher_config tls_cipher_config.c)
unit_test_all_mechs(core timer_oneshot timer_oneshot.c)

# Local (AF_UNIX) endpoints.
unit_test_all_mechs(core endpoint_local endpoint_local.c)
