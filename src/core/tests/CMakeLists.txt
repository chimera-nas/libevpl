# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(core init_no_config init_no_config.c)
unit_test(core init_auto_no_config init_auto_no_config.c)
unit_test(core init_with_clean_config init_with_clean_config.c)
unit_test(core unused_config unused_config.c)
unit_test(core tls_cipher_config tls_cipher_config.c)
