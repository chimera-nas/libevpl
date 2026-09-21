# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Exercise report accounting using llvm-cov-shaped fixtures and real diffs."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import ci_patch_coverage as patch
import ci_coverage_report as report


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.diff = self.root / 'pr.diff'
        self.lcov = self.root / 'coverage.lcov'

    def run_script(self, name, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / name), *map(str, args)],
                              text=True, capture_output=True)

    def patch_report(self):
        return self.run_script('ci_patch_coverage.py', self.diff, self.lcov,
                               self.root, 'chimera-nas/libevpl', 'abc123')

    def test_real_git_diff_add_modify_delete_rename_and_spaces(self):
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.root), *args], text=True)
        git('init', '-q')
        (self.root / 'src').mkdir()
        original = self.root / 'src/original.c'
        original.write_text('one\ntwo\nthree\nfour\n')
        git('add', '.')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.org',
            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        original.write_text('one\nchanged\nfour\n')
        (self.root / 'src/space name.c').write_text('added\n')
        git('add', '.')
        self.diff.write_text(git('-c', 'core.quotePath=false', 'diff', '--cached',
                                 '--no-renames', '-U0'))
        self.assertEqual(patch.changed_lines(self.diff),
                         {'src/original.c': {2}, 'src/space name.c': {1}})
        git('mv', 'src/original.c', 'src/renamed.c')
        self.diff.write_text(git('diff', '--cached', '--no-renames', '-U0'))
        changed = patch.changed_lines(self.diff)
        self.assertNotIn('src/original.c', changed)
        self.assertEqual(changed['src/renamed.c'], {1, 2, 3})

    def test_patch_misses_nonexecutable_and_unbuilt_are_distinct(self):
        self.diff.write_text('+++ b/src/core/a.c\n@@ -1,0 +2,3 @@\n'
                             '+++ b/src/core/windows.c\n@@ -0,0 +1 @@\n'
                             '+++ b/src/core/comment.c\n@@ -0,0 +8 @@\n')
        self.lcov.write_text(f'SF:{self.root}/src/core/a.c\nDA:2,0\nDA:3,4\n'
                             f'end_of_record\nSF:{self.root}/src/core/comment.c\nDA:1,3\nend_of_record\n')
        result = self.patch_report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('50% (1/2 changed lines executed)', result.stdout)
        self.assertIn('not measured', result.stdout)
        self.assertIn('no executable lines changed', result.stdout)
        self.assertIn('/blob/abc123/src/core/a.c#L2', result.stdout)

    def test_duplicate_lcov_records_union_hits(self):
        self.lcov.write_text(f'SF:{self.root}/src/a.c\nDA:3,0\nDA:4,7\nend_of_record\n'
                             f'SF:{self.root}/src/a.c\nDA:3,1\nDA:4,0\nend_of_record\n')
        self.assertEqual(patch.lcov_hits(self.lcov, self.root)['src/a.c'], {3: 1, 4: 7})

    def test_documentation_only_needs_no_lcov(self):
        self.diff.write_text('+++ b/docs/building.md\n@@ -0,0 +1 @@\n')
        self.assertEqual(self.patch_report().returncode, 0)
        self.assertIn('nothing to measure', self.patch_report().stdout)

    def test_missing_export_fails_for_source_changes(self):
        self.diff.write_text('+++ b/src/core/a.c\n@@ -0,0 +1 @@\n')
        self.assertNotEqual(self.patch_report().returncode, 0)

    def test_all_unbuilt_does_not_claim_nonexecutable(self):
        self.diff.write_text('+++ b/src/core/windows.c\n@@ -0,0 +1 @@\n')
        self.lcov.write_text('')
        result = self.patch_report()
        self.assertIn('not measured', result.stdout)
        self.assertNotIn('comments, declarations or build files only', result.stdout)

    def test_totals_filter_tests_dependencies_and_foreign_sources(self):
        summary = {m: {'count': 10, 'covered': 4} for m in report.METRICS}
        files = [{'filename': str(self.root / p), 'summary': summary} for p in
                 ('src/core/a.c', 'src/core/spdk/a.c', 'src/http/a.c',
                  'src/http/tests/a.c', 'src/tests/a.c', 'ext/dependency/a.c',
                  'build/src/generated.c', '../elsewhere/a.c')]
        export = self.root / 'export.json'
        export.write_text(json.dumps({'data': [{'files': files}]}))
        result = self.run_script('ci_coverage_report.py', export, self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('12/30', result.stdout)
        self.assertIn('src/core/spdk', result.stdout)
        self.assertNotIn('dependency', result.stdout)
        export.write_text('{"data": [{"files": []}]}')
        self.assertNotEqual(self.run_script('ci_coverage_report.py', export, self.root).returncode, 0)

    def test_sources_match_aggregate_scope(self):
        self.diff.write_text(''.join('+++ b/' + p + '\n@@ -0,0 +1 @@\n' for p in
                                     ('src/core/a.c', 'include/evpl/a.h',
                                      'src/core/tests/a.c', 'ext/a.c', 'docs/a.md')))
        result = self.run_script('ci_patch_coverage.py', '--sources', self.diff)
        self.assertEqual(result.stdout.splitlines(), ['include/evpl/a.h', 'src/core/a.c'])


if __name__ == '__main__':
    unittest.main()
