# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Check that behavioral witnesses require the relationships they advertise."""
import importlib.util
import pathlib
import unittest

source = pathlib.Path(__file__).resolve().parents[2] / 'src/core/tests/quint/itf_to_core_cases.py'
spec = importlib.util.spec_from_file_location('core_cases', source)
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)


def step(op, *, conn=0, side=0, queue=0, region=0, pattern=-1):
    result = [0] * 22
    result[0] = op
    result[6], result[7] = conn, side
    result[12], result[13], result[15] = queue, region, pattern
    return tuple(result)


def observed(program):
    mask = cases.witnesses(program)
    return {name for i, name in enumerate(cases.WITNESSES) if mask & (1 << i)}


class CoreGenerationTests(unittest.TestCase):
    def test_drain_separates_bursts_and_progress(self):
        program = [step('OpSend'), step('OpProgress'), step('OpSend')]
        self.assertTrue({'send_burst', 'send_progress_send'} <= observed(program))
        program.insert(2, step('OpQuiesce'))
        self.assertFalse({'send_burst', 'send_progress_send'} & observed(program))

    def test_bidirectional_requires_same_connection(self):
        self.assertIn('bidirectional', observed([step('OpSend'), step('OpSend', side=1)]))
        self.assertNotIn('bidirectional', observed([step('OpSend'), step('OpSend', conn=1, side=1)]))

    def test_cross_queue_read_requires_known_data_in_same_region(self):
        prefix = [step('OpBlockWrite', queue=0, region=2), step('OpQuiesce')]
        self.assertIn('cross_queue_read', observed(prefix + [step('OpBlockRead', queue=1, region=2, pattern=1)]))
        self.assertNotIn('cross_queue_read', observed(prefix + [step('OpBlockRead', queue=1, region=2)]))
        self.assertNotIn('cross_queue_read', observed(prefix + [step('OpBlockRead', queue=1, region=3, pattern=1)]))

    def test_finish_witness_requires_pending_send_on_finished_side(self):
        self.assertIn('finish_pending', observed([step('OpSend'), step('OpFinish')]))
        self.assertNotIn('finish_pending', observed([step('OpSend'), step('OpFinish', side=1)]))
        self.assertNotIn('finish_pending', observed([step('OpSend'), step('OpQuiesce'), step('OpFinish')]))


if __name__ == '__main__':
    unittest.main()
