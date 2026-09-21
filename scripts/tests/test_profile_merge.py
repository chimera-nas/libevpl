# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Exercise profile union with one real instrumented binary and two test batches."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TOOLS = ('clang', 'llvm-profdata', 'llvm-cov', 'readelf')
AVAILABLE = all(shutil.which(tool) for tool in TOOLS)
if os.environ.get('EVPL_REQUIRE_LLVM_TEST') == '1' and not AVAILABLE:
    raise RuntimeError('The coverage container must provide ' + ', '.join(TOOLS))


@unittest.skipUnless(AVAILABLE, 'requires matching Clang/LLVM coverage tools')
class ProfileMergeTests(unittest.TestCase):
    def test_native_and_guest_profiles_union_without_doubling_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            source = root / 'fixture.c'
            source.write_text('int native(void) { return 0; }\n'
                              'int guest(void) { return 0; }\n'
                              'int main(int argc, char **argv) {\n'
                              '  if (argc > 1) return guest();\n'
                              '  return native();\n}\n')
            binary = build / 'fixture'
            subprocess.run(['clang', '-O0', '-fprofile-instr-generate',
                            '-fcoverage-mapping', str(source), '-o', str(binary)], check=True)
            profiles = build / 'coverage/profraw'
            for name, args in [('native', []), ('rdma', ['guest'])]:
                folder = profiles / name
                folder.mkdir(parents=True)
                subprocess.run([str(binary), *args], check=True,
                               env={**os.environ, 'LLVM_PROFILE_FILE': str(folder / '%m-%p.profraw')})
            summaries = []
            script = Path(__file__).resolve().parents[2] / 'etc/coverage-report.sh'
            for folder in (profiles / 'native', profiles / 'rdma', profiles):
                export = root / 'coverage.json'
                subprocess.run(['bash', str(script), str(build)], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, 'COVERAGE_PROFILE_DIR': str(folder),
                                    'COVERAGE_JSON': str(export)})
                files = json.loads(export.read_text())['data'][0]['files']
                summaries.append(next(f['summary'] for f in files if f['filename'] == str(source)))
            native, guest, merged = summaries
            self.assertEqual(native['functions']['covered'], 2)
            self.assertEqual(guest['functions']['covered'], 2)
            self.assertEqual(merged['functions']['covered'], 3)
            self.assertEqual(merged['lines']['count'], native['lines']['count'])
            self.assertEqual(merged['lines']['count'], guest['lines']['count'])
            self.assertGreater(merged['lines']['covered'], native['lines']['covered'])
            self.assertGreater(merged['lines']['covered'], guest['lines']['covered'])


if __name__ == '__main__':
    unittest.main()
