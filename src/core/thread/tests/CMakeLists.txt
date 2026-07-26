# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Run against every core mechanism compiled in: thread create/destroy exercises
# the cross-thread wakeup descriptors through each mechanism's wait path.
unit_test_all_mechs(thread thread_basic thread_basic.c)
unit_test_all_mechs(thread threadpool_basic threadpool_basic.c)

