"""TLC evidence counters must come from the final summary, never progress."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'formal_check', Path(__file__).resolve().parents[1] / 'formal/check.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class FormalResults(unittest.TestCase):
    def test_progress_thousands_suffix_is_not_a_final_state_count(self):
        text = ('Progress(10): 2,140 states generated, 469 distinct states found, '
                '0 states left on queue.\n'
                '2140 states generated, 469 distinct states found, 0 states left on queue.\n')
        self.assertEqual(check.state_counts(text), dict(generated=2140, distinct=469, remaining=0))

    def test_interrupted_tool_without_final_summary_has_no_claimed_counts(self):
        self.assertEqual(check.state_counts('Progress: 2,140 states generated, 469 distinct states found, '
                                           '20 states left on queue.\n'), {})

    def test_final_summary_takes_precedence(self):
        self.assertEqual(check.state_counts('12 states generated, 7 distinct states found, 1 states left on queue.\n'
                                           '23 states generated, 11 distinct states found, 0 states left on queue.\n'),
                         dict(generated=23, distinct=11, remaining=0))


if __name__ == '__main__':
    unittest.main()
