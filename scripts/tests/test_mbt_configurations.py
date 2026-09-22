# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mbt_configurations import MANIFEST, configurations, config_api, render, valid
from ci_mbt_matrix import check_functions


class ConfigurationTests(unittest.TestCase):
    def test_all_feasible_pairs_and_values_are_present(self):
        spec = json.loads(MANIFEST.read_text())
        rows, _ = configurations(spec)
        factors = spec['factors']
        # Independently enumerate obligations rather than using generator pairs().
        legal = [dict(zip(factors, v)) for v in itertools.product(*factors.values())]
        legal = [row for row in legal if valid(row)]
        for a, b in itertools.combinations(factors, 2):
            expected = {(r[a], r[b]) for r in legal}
            self.assertEqual(expected, {(r[a], r[b]) for r in rows}, (a, b))
        for name, values in factors.items():
            self.assertEqual(set(values), {r[name] for r in rows})
        self.assertIn(spec['stress'], rows)
        self.assertLessEqual(len(rows), 12)  # bounded CI process budget
        self.assertEqual(rows, configurations(spec)[0])

    def test_constraint_and_reproduction(self):
        rows, _ = configurations()
        bad = dict(rows[0], buffer_size=65536, slab_size=131072)
        self.assertFalse(valid(bad))
        self.assertFalse(valid(dict(rows[0], dgram_ring_size=3)))
        for name, contents in render()[0].items():
            self.assertEqual((MANIFEST.parent / name).read_text(), contents, name)

    def test_new_public_accessor_is_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'include/evpl').mkdir(parents=True)
            (root / 'src/core').mkdir(parents=True)
            (root / 'src/core/evpl.h').write_text('')
            (root / 'include/evpl/config.h').write_text(
                '/* EVPL_API void evpl_global_config_set_comment(void); */\n'
                'EVPL_API void evpl_global_config_set_new_setting(void *c, int v);\n'
                'EVPL_API int evpl_thread_config_get_new_setting(void *c);\n')
            self.assertEqual(config_api(root), {'evpl_global_config_set_new_setting',
                                               'evpl_thread_config_get_new_setting'})

    def test_every_accessor_requires_execution(self):
        # Obtain existing behavioral requirements from the guard's error, then
        # check each configuration accessor independently cannot be dropped.
        with self.assertRaises(ValueError) as error:
            check_functions([], ['libfabric'])
        required = str(error.exception).split(': ', 1)[1].split(', ')
        rows = [{'function': name, 'count': '1'} for name in required]
        check_functions(rows, ['libfabric'])
        for name in config_api():
            with self.assertRaisesRegex(ValueError, name):
                check_functions([r for r in rows if r['function'] != name], ['libfabric'])


if __name__ == '__main__':
    unittest.main()
