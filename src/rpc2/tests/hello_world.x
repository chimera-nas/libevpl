
/*
 * SPDX-FileCopyrightText: 2025 Ben Jarvis
 * SPDX-License-Identifier: BSD-3-Clause
 */

struct Hello {
    unsigned int    id;
    string          greeting;
};

program HELLO_PROGRAM {
    version HELLO_V1 {
        Hello GREET(Hello) = 1;
        /* Never called by the tests; declared so the generated void-reply
         * dispatch branch is compiled by CI, which no other test .x covers. */
        void  NOOP(void)   = 2;
    } = 1;
} = 42;
