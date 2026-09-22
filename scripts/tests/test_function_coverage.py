# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ci_function_coverage import functions


class FunctionInventoryTests(unittest.TestCase):
    def test_inline_copies_merge_but_uncovered_functions_remain(self):
        def fn(name, path, line, count):
            return dict(name=name, filenames=[path], regions=[[line, 1, line + 2, 1, count, 0]], count=count)
        entries = [fn('a.c:helper', '/repo/include/evpl/api.h', 10, 0),
                   fn('b.c:helper', '/repo/include/evpl/api.h', 10, 4),
                   fn('never_called', '/repo/src/core/api.c', 20, 0),
                   fn('test_only', '/repo/src/core/tests/a.c', 1, 20),
                   fn('foreign', '/elsewhere/src/core/api.c', 1, 20)]
        rows = functions({'data': [{'functions': entries}]}, '/repo')
        self.assertEqual([(r['function'], r['count']) for r in rows], [('helper', 4), ('never_called', 0)])
