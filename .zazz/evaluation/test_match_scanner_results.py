#!/usr/bin/env python3
"""Tests for match-scanner-results.py. Run: python3 .zazz/evaluation/test_match_scanner_results.py"""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('m', pathlib.Path(__file__).with_name('match-scanner-results.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

VULN = {'id': 'V1', 'app': 'a', 'kind': 'sql_query_candidate', 'expect': 'positive', 'file': 'q.js', 'line': 10}
SAFE = {'id': 'N1', 'app': 'a', 'kind': 'sql_query_candidate', 'expect': 'no_record', 'file': 'safe.js', 'line': 5}


def result(rule, file, line):
    return {'rule': rule, 'file': file, 'line': line}


class MatchTest(unittest.TestCase):
    def cells(self, rows, results):
        table, rest = m.match(rows, {'t': results})
        return {row['id']: cells['t'] for row, cells in table}, rest['t']

    def test_line_window(self):
        for line, found in ((10, True), (13, True), (7, True), (14, False), (6, False)):
            cells, rest = self.cells([VULN], [result('lang_sql_injection', 'q.js', line)])
            self.assertEqual(bool(cells['V1']), found, line)
            self.assertEqual(len(rest), 0 if found else 1)

    def test_other_class_on_the_line_is_not_a_match(self):
        cells, rest = self.cells([VULN], [result('express_open_redirect', 'q.js', 10)])
        self.assertFalse(cells['V1'])
        self.assertEqual(len(rest), 1)

    def test_other_file_is_not_a_match(self):
        cells, _ = self.cells([VULN], [result('lang_sql_injection', 'other.js', 10)])
        self.assertFalse(cells['V1'])

    def test_control_hit_is_reported_on_the_control_row(self):
        cells, rest = self.cells([VULN, SAFE], [result('tainted-sql-string', 'safe.js', 6)])
        self.assertTrue(cells['N1'])
        self.assertFalse(cells['V1'])
        self.assertEqual(rest, [])

    def test_result_goes_to_the_nearer_of_two_rows(self):
        a = dict(VULN, id='A', kind='password_hash_candidate', line=41)
        b = dict(VULN, id='B', kind='password_hash_candidate', line=42)
        cells, _ = self.cells([a, b], [result('weak_hash_md5', 'q.js', 41)])
        self.assertTrue(cells['A'])
        self.assertFalse(cells['B'])

    def test_file_level_row_matches_any_line(self):
        row = dict(VULN, id='F')
        del row['line']
        cells, _ = self.cells([row], [result('lang_sql_injection', 'q.js', 400)])
        self.assertTrue(cells['F'])

    def test_anchor_map(self):
        row = {'id': 'M', 'app': 'a', 'kind': 'password_hash_candidate', 'expect': 'positive', 'anchors': {'a.php': [15], 'b.php': [41]}}
        cells, rest = self.cells([row], [result('md5-used-as-password', 'b.php', 41), result('md5-used-as-password', 'c.php', 41)])
        self.assertEqual(len(cells['M']), 1)
        self.assertEqual(len(rest), 1)

    def test_unmapped_rule_is_listed_and_never_matched(self):
        cells, rest = self.cells([VULN], [result('npm-missing-minimum-release-age', 'q.js', 10)])
        self.assertFalse(cells['V1'])
        self.assertEqual(m.rule_class(rest[0]['rule']), 'other')


if __name__ == '__main__':
    unittest.main()
