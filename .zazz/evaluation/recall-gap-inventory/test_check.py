#!/usr/bin/env python3
"""Unit test for the checker's precision and noise measures (python3 test_check.py)."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('check', Path(__file__).parent / 'check.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def span(file, line, start):
    return {'file': file, 'start_line': line, 'end_line': line, 'start_byte': start, 'end_byte': start + 5}


def use(uid, kind, file, line, start=0, entry='e1', deps=(), gaps=(), blockers=(), **extra):
    u = {'id': uid, 'kind': kind, 'entry_id': entry, 'sink': {'span': span(file, line, start)},
         'dependencies': [{'source': {'kind': k, 'span': span(file, line - 1, 0)}} for k in deps],
         'gaps': [{'kind': g} for g in gaps], 'completeness': {'blockers': [{'kind': b} for b in blockers]}}
    u.update(extra)
    return u


def finding(uid, status='poor_practice'):
    return {'use_id': uid, 'record_type': 'finding' if status in ('poor_practice', 'confirmed_vulnerability') else 'analysis', 'status': status}


class FrozenKeyTest(unittest.TestCase):
    def test_judged_key_distinguishes_confirmed_from_practice_and_control_findings(self):
        reports = {'entries': [{'id': 'e1', 'name': 'GET /page'}],
                   'uses': [use('a', 'xss_candidate', 'a.twig', 3, deps=['input_source'])],
                   'findings': [finding('a')]}
        row = {'kind': 'xss_candidate', 'expect': 'positive', 'file': 'a.twig', 'line': 3,
               'entry_names': ['GET /page']}
        self.assertEqual(check.judged_outcome(row, reports), 'practice_finding')
        reports['findings'] = [finding('a', 'confirmed_vulnerability')]
        self.assertEqual(check.judged_outcome(row, reports), 'confirmed')
        row['entry_names'] = ['POST /page']
        self.assertEqual(check.judged_outcome(row, reports), 'missed')
        del row['entry_names']
        row['expect'] = 'not_raw'
        self.assertEqual(check.judged_outcome(row, reports), 'control_finding')

    def test_multiple_anchors_and_whole_sample_control(self):
        report = {'uses': [use('a', 'xss_candidate', 'a.twig', 3),
                           use('b', 'xss_candidate', 'b.twig', 5),
                           use('c', 'xss_candidate', 'b.twig', 6)]}
        row = {'kind': 'xss_candidate', 'expect': 'no_record',
               'anchors': {'a.twig': [3], 'b.twig': [5]}}
        self.assertEqual([u['id'] for u in check.select(row, report, {})], ['a', 'b'])
        del row['anchors']
        self.assertEqual([u['id'] for u in check.select(row, report, {})], ['a', 'b', 'c'])

    def test_automatic_check_on_both_sink_records(self):
        report = {'uses': [use('a', 'sql_query_candidate', 'a.php', 3,
                               check={'id': 'automatic-php-query', 'fields': ['s']}),
                           use('b', 'sql_query_candidate', 'b.php', 5,
                               check={'id': 'automatic-php-query', 'fields': ['email']})]}
        row = {'kind': 'sql_query_candidate', 'expect': 'present',
               'anchors': {'a.php': [3], 'b.php': [5]},
               'required_checks': [['a.php', 3, 'automatic-php-query', 's'],
                                   ['b.php', 5, 'automatic-php-query', 'email']]}
        self.assertEqual(check.classify(row, report)['outcome'], 'candidate_present')
        report['uses'][1]['check']['fields'] = ['other']
        self.assertEqual(check.classify(row, report)['outcome'], 'missing_candidate')

    def test_sourceless_positive_needs_anchor_and_no_blocker(self):
        report = {'entries': [{'id': 'e1', 'name': 'FILE /info.php'}],
                  'uses': [use('a', 'info_exposure_candidate', 'info.php', 2)]}
        row = {'kind': 'info_exposure_candidate', 'expect': 'positive', 'file': 'info.php', 'line': 2,
               'entry_names': ['FILE /info.php']}
        self.assertEqual(check.classify(row, report)['outcome'], 'candidate_with_witness')
        report['uses'][0]['completeness']['blockers'] = [{'kind': 'diagnostic_output_environment_dependent'}]
        self.assertEqual(check.classify(row, report)['outcome'], 'candidate_evidence_gap')
        row['line'] = 3
        self.assertEqual(check.classify(row, report)['outcome'], 'missing_candidate')
        # A kind with a request source still needs a witness.
        mass = {'uses': [use('m', 'mass_assignment_candidate', 'E.php', 9)]}
        self.assertEqual(check.classify({'kind': 'mass_assignment_candidate', 'expect': 'positive', 'file': 'E.php', 'line': 9}, mass)['outcome'],
                         'candidate_evidence_gap')
        mass['uses'][0]['dependencies'] = [{'source': {'kind': 'input_source', 'span': span('C.php', 4, 0)}}]
        self.assertEqual(check.classify({'kind': 'mass_assignment_candidate', 'expect': 'positive', 'file': 'E.php', 'line': 9,
                                         'source': ['C.php', 4]}, mass)['outcome'], 'candidate_with_witness')

    def test_report_wide_only_lines(self):
        report = {'uses': [use('a', 'info_exposure_candidate', 'info.php', 2)], 'findings': []}
        row = {'kind': 'info_exposure_candidate', 'expect': 'only_lines', 'anchors': {'info.php': [2]}, 'max_uses': 1}
        self.assertEqual(check.classify(row, report)['outcome'], 'control_pass')
        report['uses'].append(use('b', 'info_exposure_candidate', 'info.php', 2, start=9, entry='e2'))
        self.assertEqual(check.classify(row, report)['outcome'], 'control_fail')
        report['uses'][1] = use('b', 'info_exposure_candidate', 'other.php', 4)
        self.assertEqual(check.classify(row, report)['outcome'], 'control_fail')
        report['findings'] = [finding('b', 'confirmed_vulnerability')]
        self.assertEqual(check.judged_outcome(row, report), 'control_finding')
        # The precision pass reads the anchored form too.
        prec = check.precision({'s': report}, [{**row, 'app': 's'}], [], [])['s']
        self.assertEqual(prec['info_exposure']['records'], 2)

    def test_guarded_needs_candidate_with_guard_or_entry_roles(self):
        guard = {'kind': 'ownership_check', 'evidence': {'span': {'file': 'UserController.php', 'start_line': 75}}}
        report = {'entries': [{'id': 'e1', 'name': 'POST /user/avatar/{user}',
                               'access': {'authentication': 'required', 'roles': ['ROLE_USER']}}],
                  'uses': [use('a', 'authorization_candidate', 'UserController.php', 101, deps=['input_source'],
                               authorization={'guards': [guard]})]}
        row = {'kind': 'authorization_candidate', 'expect': 'guarded', 'file': 'UserController.php',
               'anchors': {'UserController.php': [101]}, 'guard_kind': 'ownership_check', 'guard_lines': [75]}
        self.assertEqual(check.classify(row, report)['outcome'], 'control_pass')
        report['uses'][0]['authorization']['guards'] = [{'kind': 'role_check', 'evidence': {'span': {'file': 'UserController.php', 'start_line': 75}}}]
        self.assertEqual(check.classify(row, report)['outcome'], 'control_fail')
        report['uses'] = []
        self.assertEqual(check.classify(row, report)['outcome'], 'control_fail')
        roles = {'kind': 'authorization_candidate', 'expect': 'guarded', 'file': 'AdminController.php',
                 'anchors': {'AdminController.php': [53]}, 'entry_roles': ['ROLE_ADMIN']}
        report['entries'][0]['access']['roles'] = ['ROLE_USER']
        report['uses'] = [use('b', 'authorization_candidate', 'AdminController.php', 53)]
        self.assertEqual(check.classify(roles, report)['outcome'], 'control_fail')
        report['entries'][0]['access']['roles'] = ['ROLE_ADMIN']
        self.assertEqual(check.classify(roles, report)['outcome'], 'control_pass')
        report['findings'] = [finding('b', 'confirmed_vulnerability')]
        self.assertEqual(check.judged_outcome(roles, report), 'control_finding')
        report['findings'] = [finding('b', 'protected_for_claim')]
        self.assertEqual(check.judged_outcome(roles, report), 'control_protected')


class PrecisionTest(unittest.TestCase):
    def setUp(self):
        uses = [
            use('a', 'sql_query_candidate', 'db.php', 10, gaps=['query_text_interpolated']),  # no origin
            use('b', 'sql_query_candidate', 'db.php', 20, deps=['input_source'], gaps=['query_text_interpolated']),
            use('c', 'xss_candidate', 'page.php', 5, entry='e1', deps=['input_source']),
            use('d', 'xss_candidate', 'page.php', 5, entry='e2', deps=['input_source']),
            use('e', 'xss_candidate', 'page.php', 5, entry='e2', deps=['storage_source']),
            use('f', 'input_validation_candidate', 'form.py', 3, deps=['input_source']),
            use('g', 'xss_candidate', 'tests/view.js', 7, deps=['input_source'], xss={'output_context': 'unknown', 'protection': 'raw'}),
            use('h', 'command_execution_candidate', 'safe.php', 9, deps=['input_source'],
                assessment={'status': 'completed', 'provider': 'openai', 'model': 'm', 'question_version': 'command-components-v3', 'answers': {'shell_syntax_protection': 'vulnerable'},
                            'blocking_gaps': [{'kind': 'unknown_transfer'}]}, completeness={'blockers': [{'kind': 'unknown_transfer'}]}),
        ]
        self.report = {'uses': uses, 'entries': [], 'findings': [
            finding('a'), finding('b'), finding('c'), finding('d'), finding('e', 'needs_review'),
            finding('f', 'needs_review'), finding('g', 'needs_review'), finding('h', 'needs_review')]}
        keyed = [{'app': 's', 'kind': 'sql_query_candidate', 'file': 'db.php', 'line': 20, 'expect': 'positive'},
                 {'app': 's', 'kind': 'xss_candidate', 'file': 'page.php', 'line': 5, 'expect': 'no_record'}]
        controls = [{'app': 's', 'kind': 'command_execution_candidate', 'file': 'safe.php'}]
        self.prec = check.precision({'s': self.report}, keyed, [], controls)['s']

    def test_keyed_and_unkeyed(self):
        self.assertEqual(self.prec['sql_query']['keyed_true'], 1)
        self.assertEqual(self.prec['sql_query']['unkeyed_findings'], 1)
        self.assertEqual(self.prec['xss']['keyed_false'], 2)  # c and d present as findings at a no_record control
        self.assertEqual(self.prec['xss']['unkeyed'], 1)  # g

    def test_noise_classes(self):
        self.assertEqual(self.prec['sql_query']['construction_no_origin'], 1)
        self.assertEqual(self.prec['sql_query']['construction_no_origin_finding'], 1)
        self.assertEqual(self.prec['input_validation']['undecidable_validation'], 1)
        self.assertEqual(self.prec['xss']['shared_sink_fanout'], 3)
        self.assertEqual(self.prec['xss']['same_entry_sink_extra'], 1)
        self.assertEqual(self.prec['xss']['unknown_context_raw'], 1)
        self.assertEqual(self.prec['xss']['test_path'], 1)

    def test_controls_and_fixed_outcome(self):
        cmd = self.prec['command_execution']
        self.assertEqual(cmd['control_review'], 1)
        self.assertEqual(cmd['fixed_outcome_requests'], 1)
        self.assertEqual(cmd['substantive_discarded'], 1)
        self.assertEqual(cmd['judged_by'], ['openai/m/command-components-v3'])
        self.assertNotIn('judged_by', self.prec['sql_query'])

    def test_resolution_measures(self):
        resolved = use('r', 'path_traversal_candidate', 'app.py', 4, deps=['input_source'], blockers=['python_comprehension_unresolved'],
                       assessment={'status': 'completed', 'finding_status': 'confirmed_vulnerability',
                                   'resolutions': [{'blocker': {'kind': 'python_comprehension_unresolved'}, 'citation': ['e0', 'g0', 'e1'], 'verified': True, 'discharged': True}],
                                   'follow_up': {'status': 'sent'}})
        rejected = use('s', 'path_traversal_candidate', 'app.py', 9, deps=['input_source'], blockers=['unknown_transfer'],
                       assessment={'status': 'completed', 'resolutions': [{'blocker': {'kind': 'unknown_transfer'}, 'citation': ['e9'], 'verified': False}],
                                   'follow_up': {'status': 'follow_up_cap_reached'}})
        gated = use('t', 'xss_candidate', 'v.html', 1, assessment={'status': 'not_run', 'reason': 'blocker_unresolvable: render_protection_unresolved fixes ...'})
        report = {'uses': [resolved, rejected, gated], 'findings': [finding('r', 'confirmed_vulnerability'), finding('s', 'needs_review'), finding('t', 'needs_review')]}
        r = check.resolution(report)
        self.assertEqual(r['path_traversal'], {'blocked_sent': 2, 'blockers_resolved': 1, 'citations_rejected': 1, 'follow_ups_sent': 1,
                                               'follow_ups_follow_up_cap_reached': 1, 'model_resolved_finding': 1})
        self.assertEqual(r['xss'], {'gated_unresolvable': 1})

    def test_decidable_validation(self):
        u = use('v', 'input_validation_candidate', 'f.py', 1)
        u['completeness'] = {'blockers': [], 'required': [], 'evidence': {r: [{}] for r in check.VALIDATION_ROLES}}
        self.assertTrue(check.validation_decidable(u))
        u['completeness']['evidence'].pop('field_policy')
        self.assertFalse(check.validation_decidable(u))


if __name__ == '__main__':
    unittest.main()
