#!/usr/bin/env python3
"""Classify every frozen phase 5 row against saved offline findings.json reports.

Usage: check.py <reports.json> [--lab <vuln-nextjs checkout>] [--json out.json]
reports.json maps app name to its findings.json path. Python rows come from
docs/samples/<app>/cases.json; vuln-nextjs rows from the lab key at the pin.

Besides the recall rows it prints precision and noise measures per family and
sample (see precision()): keyed findings true and false, the noise classes of
the false-positive contract, the unkeyed and test-path censuses, the
protected-control set, and, for judged reports, fixed-outcome requests.
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WITNESS = {'input_source', 'storage_read', 'storage_source', 'browser_source', 'api_response', 'file_read', 'fetched_content', 'external_response_source'}
PYTHON_APPS = ('ThreatByte', 'python-insecure-app', 'vulnerable-flask-app', 'vulnpy')
LAB_FAMILIES = {'CWE-22': 'path_traversal_candidate', 'CWE-78': 'command_execution_candidate',
                'CWE-89': 'sql_query_candidate', 'CWE-918': 'ssrf_candidate', 'CWE-79': 'xss_candidate',
                'CWE-95': 'code_execution_candidate', 'CWE-601': 'open_redirect_candidate'}
PY_EXPECT = {'construction': 'positive', 'raw_xss': 'positive', 'candidate': 'positive',
             'validation_defect': 'present', 'not_confirmed': 'present', 'validation_enforced': 'present',
             'form_policy': 'present', 'encoded': 'encoded', 'bound': 'bound', 'absent': 'no_record',
             'registration_or_gap': 'registration'}
ASSESSMENT = {'validation_defect', 'not_confirmed', 'validation_enforced'}


def evaluator():
    spec = importlib.util.spec_from_file_location('evaluate_python', ROOT / 'docs/samples/evaluate-python.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def spans(obj):
    if isinstance(obj, dict):
        span = obj.get('span') or (obj if 'start_line' in obj and 'file' in obj else None)
        if span:
            yield span.get('file'), span.get('start_line')
        for v in obj.values():
            yield from spans(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from spans(v)


def select(row, report, entries):
    out = []
    for u in report['uses']:
        if u['kind'] != row['kind']:
            continue
        sink = u['sink']['span']
        if sink['file'] != row['file']:
            continue
        if 'line' in row and sink['start_line'] != row['line']:
            continue
        if 'lines' in row and row['expect'] in ('no_record', 'present') and sink['start_line'] not in row['lines']:
            continue
        if 'entry_file' in row and entries.get(u.get('entry_id'), {}).get('location', {}).get('span', {}).get('file') != row['entry_file']:
            continue
        if 'dep_file' in row and row['dep_file'] not in {f for f, _ in spans(u.get('dependencies', []))}:
            continue
        out.append(u)
    return out


def witnessed(u, row):
    deps = u.get('dependencies', [])
    if not any(d.get('source', {}).get('kind') in WITNESS for d in deps):
        return False
    if 'source' in row:
        # The key's source anchor must be a dependency's origin, not a transfer step.
        origins = {(d['source']['span']['file'], d['source']['span']['start_line']) for d in deps if d.get('source', {}).get('span')}
        return tuple(row['source']) in origins
    return True


def blockers(u):
    return [g['kind'] for g in (u.get('completeness') or {}).get('blockers') or []]


def classify(row, report):
    entries = {e['id']: e for e in report.get('entries', [])}
    expect = row['expect']
    uses = select(row, report, entries)
    counted = [u for u in uses if 'source' not in row or witnessed(u, row)] if expect == 'positive' else uses
    res = {'uses': len(counted), 'entries': len({u.get('entry_id') for u in counted})}
    if expect in ('positive', 'review', 'present'):
        if len(uses) < row.get('min_uses', 1):
            res['outcome'] = 'missing_candidate'
        elif expect == 'positive' and any(witnessed(u, row) and not blockers(u) for u in uses):
            res['outcome'] = 'candidate_with_witness'
        elif expect == 'positive':
            res['outcome'] = 'candidate_evidence_gap'
            res['blockers'] = sorted({b for u in uses for b in blockers(u)}) or ['no_witnessed_source']
        else:
            res['outcome'] = 'candidate_present'
            res['blockers'] = sorted({b for u in uses for b in blockers(u)})
        return res
    if expect == 'no_record':
        res['outcome'] = 'control_pass' if not uses else 'control_fail'
    elif expect == 'not_raw':
        res['outcome'] = 'control_pass' if all((u.get('xss') or {}).get('protection') != 'raw' for u in uses) else 'control_fail'
    elif expect == 'encoded':
        res['outcome'] = 'control_pass' if uses and all((u.get('xss') or {}).get('protection') == 'encoded' for u in uses) else 'control_fail'
    elif expect == 'not_decisive':
        ok = all(blockers(u) or not any(d.get('source', {}).get('kind') == 'input_source' for d in u.get('dependencies', [])) for u in uses)
        res['outcome'] = 'control_pass' if ok else 'control_fail'
    elif expect == 'only_lines':
        lines = sorted({u['sink']['span']['start_line'] for u in report['uses'] if u['kind'] == row['kind'] and u['sink']['span']['file'] == row['file']})
        res['outcome'] = 'control_pass' if set(lines) <= set(row['lines']) else 'control_fail'
        res['observed_lines'] = lines
    elif expect == 'only_sources':
        allowed = {tuple(s) for s in row['only_sources']}
        ok = all((d['source']['span']['file'], d['source']['span']['start_line']) in allowed for u in uses for d in u.get('dependencies', []))
        res['outcome'] = 'control_pass' if ok else 'control_fail'
    elif expect == 'bound':
        ok = all(not any(g['kind'] == 'query_text_interpolated' for g in u.get('gaps', [])) for u in uses)
        res['outcome'] = 'control_pass' if ok else 'control_fail'
    elif expect == 'control_assessment':
        res['outcome'] = 'assessment_dependent'
    else:
        raise ValueError(expect)
    # A control that matches no record passes vacuously; flag it so a vanished
    # candidate cannot pass silently.
    if expect in ('bound', 'not_raw', 'not_decisive', 'only_sources') and not uses:
        res['vacuous'] = True
    return res


def python_rows(app, report, ev):
    cases = json.loads((ROOT / 'docs/samples' / app / 'cases.json').read_text())['cases']
    for c in cases:
        row = {'id': c['id'], 'app': app, 'key': f'docs/samples/{app}/cases.json', 'kind': c['kind'],
               'file': c['file'], 'line': c['line'], 'expect': PY_EXPECT[c['expect']], 'key_expect': c['expect'],
               'tag': 'post_delivery' if any(k.startswith('previous_') for k in c) else 'independent'}
        if row['expect'] == 'registration':
            gaps = report.get('gaps', [])
            gap = any(g['kind'] == c['kind'] and g.get('at', {}).get('file') == c['file'] and g.get('at', {}).get('start_line') == c['line'] for g in gaps)
            ok = ev.evaluate(c, report['uses'], gaps, report)
            res = {'outcome': 'explicit_gap' if gap else ('resolved' if ok else 'missing_registration')}
        else:
            res = classify(row, report)
            if c['expect'] in ASSESSMENT:
                res['assessment'] = 'unmeasured_offline'
        res['evaluator_pass'] = ev.evaluate(c, report['uses'], report.get('gaps', []), report)
        yield row, res


def lab_rows(lab, report):
    truth = json.loads((Path(lab) / 'tests/expected-scanner-findings.json').read_text())
    for s in truth['sources']:
        row = {'id': s['id'], 'app': 'vuln-nextjs', 'key': 'tests/expected-scanner-findings.json (lab)', 'tag': 'independent'}
        kind = LAB_FAMILIES.get(s.get('cwe') or '')
        if s.get('scanner') != 'SAST' or not kind:
            row['expect'] = 'excluded'
            row['reason'] = 'no_security_finding_expected' if not s.get('cwe') else 'out_of_family (' + (s.get('cwe') or '') + ', ' + s.get('scanner', '') + ')'
            yield row, {'outcome': 'excluded'}
            continue
        row.update(kind=kind, file=s['source'])
        if s['expectedFinding']:
            row['expect'] = 'positive'
        else:
            row['expect'] = 'not_raw' if kind == 'xss_candidate' else 'control_assessment'
            row['control_for'] = s.get('controlFor')
        yield row, classify(row, report)


# Precision measures (false-positive contract W5). Expected labels stay here;
# none of this reaches scanner or model input.
EXTERNAL = WITNESS | {'api_response_source', 'browser_storage'}
CONTROL_EXPECT = {'no_record', 'not_raw', 'not_decisive', 'only_lines', 'only_sources', 'bound', 'encoded', 'control_assessment'}
VALIDATION_ROLES = ('input_source', 'field_policy', 'invoked_callable', 'control_flow')
TEST_PATH = re.compile(r'(^|/)(tests?|__tests__|spec|specs|fixtures?|cypress|e2e)(/|$)|\.(test|spec)\.[a-z]+$', re.I)
UNDECIDED = {'', 'uncertain', 'unknown', 'not_applicable', 'guard_semantics_unknown'}
VERDICT_KEYS = ('validation', 'injection_protection', 'xss_exposure', 'path_traversal', 'destination_control',
                'log_exposure', 'shell_syntax_protection', 'argument_control', 'code_exposure', 'redirect_exposure')


def family(kind):
    return (kind or '').replace('_candidate', '')


def presented(report):
    """Finding record per use ID; a report without findings presents nothing."""
    return {f['use_id']: f for f in report.get('findings', [])}


def is_finding(f):
    return bool(f) and f.get('record_type') == 'finding'


def span_key(u):
    s = u['sink']['span']
    return (u['kind'], s['file'], s.get('start_byte'), s.get('end_byte'))


def external_origin(u):
    return any(d.get('source', {}).get('kind') in EXTERNAL for d in u.get('dependencies', []))


def validation_decidable(u):
    """Mirror of the judge's validation policy gate: every required role has evidence."""
    c = u.get('completeness') or {}
    if not c or c.get('blockers'):
        return False
    roles = list(c.get('required') or []) + list(VALIDATION_ROLES) + list((u.get('analysis_components') or {}).get('required') or [])
    ev = c.get('evidence') or {}
    return all(ev.get(r) for r in roles)


def construction(u):
    return u['kind'] in ('sql_query_candidate', 'nosql_query_candidate') and any(g['kind'] == 'query_text_interpolated' for g in u.get('gaps', []))


def noise_classes(report, rows):
    """Count records per noise class. Generic classes read the record; keyed
    classes (own-API origin, literal-only storage, closed type map) count the
    source-reviewed anchors in cases.json noise_rows."""
    uses, fs = report['uses'], presented(report)
    entries = {e['id']: e for e in report.get('entries', [])}
    out = {}
    def inc(fam, cls, n=1):
        out.setdefault(fam, {}).setdefault(cls, 0)
        out[fam][cls] += n
    by_site, by_entry_site = {}, {}
    for u in uses:
        fam = family(u['kind'])
        if construction(u) and not external_origin(u):
            inc(fam, 'construction_no_origin')
            if is_finding(fs.get(u['id'])):
                inc(fam, 'construction_no_origin_finding')
        if u['kind'] == 'input_validation_candidate' and u.get('check') is None and not validation_decidable(u):
            inc(fam, 'undecidable_validation')
        x = u.get('xss') or {}
        if x.get('output_context') == 'unknown' and x.get('protection') == 'raw':
            inc(fam, 'unknown_context_raw')
        if any(g['kind'] == 'storage_origin_unresolved' for g in (u.get('completeness') or {}).get('blockers') or []):
            inc(fam, 'stored_origin_unresolved')
        if u['kind'] != 'outbound_http_candidate':
            by_site.setdefault(span_key(u), []).append(u)
            by_entry_site.setdefault((u.get('entry_id'),) + span_key(u), []).append(u)
    for k, group in by_site.items():
        if len({u.get('entry_id') for u in group}) > 1:
            inc(family(k[0]), 'shared_sink_fanout', len(group))
    for k, group in by_entry_site.items():
        if len(group) > 1:
            inc(family(k[1]), 'same_entry_sink_extra', len(group) - 1)
    for row in rows:
        for u in select(row, report, entries):
            cond = row['class']
            ok = (cond == 'own_api_request_origin' and any(d.get('source', {}).get('kind') == 'input_source' for d in u.get('dependencies', []))) or \
                 (cond == 'stored_literal_writes' and any(g['kind'] == 'storage_origin_unresolved' for g in (u.get('completeness') or {}).get('blockers') or [])) or \
                 cond == 'closed_type_map'
            if ok:
                inc(family(u['kind']), cond)
    return out


def fixed_outcome(report):
    """Judged requests whose outcome a scanner blocker had already fixed, and
    how many of them discarded a substantive model answer."""
    out = {}
    for u in report['uses']:
        a = u.get('assessment') or {}
        if a.get('status') != 'completed' or a.get('deduplicated_from'):
            continue
        scanner = {g['kind'] for g in (u.get('completeness') or {}).get('blockers') or []} | {'validation_evidence_missing'}
        if not any(g.get('kind') in scanner for g in a.get('blocking_gaps') or []):
            continue
        d = out.setdefault(family(u['kind']), {'fixed_outcome_requests': 0, 'substantive_discarded': 0})
        d['fixed_outcome_requests'] += 1
        answers = a.get('answers') or {}
        if any(answers.get(k, '') not in UNDECIDED for k in VERDICT_KEYS if k in answers):
            d['substantive_discarded'] += 1
    return out


def resolution(report):
    """Evidence-resolution measures per family for a judged report: blocked
    records sent, blockers resolved, citations rejected, follow-ups and
    model-resolved outcomes, and records the send gate kept back."""
    out = {}
    fs = presented(report)
    for u in report['uses']:
        a = u.get('assessment') or {}
        d = out.setdefault(family(u['kind']), {})
        def inc(k, n=1):
            d[k] = d.get(k, 0) + n
        if (a.get('reason') or '').startswith('blocker_unresolvable'):
            inc('gated_unresolvable')
        if a.get('status') != 'completed' or a.get('deduplicated_from'):
            continue
        if (u.get('completeness') or {}).get('blockers'):
            inc('blocked_sent')
        for r in a.get('resolutions') or []:
            if r.get('discharged') and r.get('blocker'):
                inc('blockers_resolved')
            if r.get('citation') and not r.get('verified'):
                inc('citations_rejected')
        f = a.get('follow_up') or {}
        if f.get('status') == 'sent':
            inc('follow_ups_sent')
        elif f.get('status') in ('unresolved', 'follow_up_cap_reached'):
            inc('follow_ups_' + f['status'])
        if any(r.get('discharged') for r in a.get('resolutions') or []):
            st = (fs.get(u['id']) or {}).get('status', a.get('finding_status'))
            inc('model_resolved_protected' if st == 'protected_for_claim' else 'model_resolved_finding' if is_finding(fs.get(u['id'])) else 'model_resolved_review')
    return {k: v for k, v in out.items() if v}


RESOLUTION_COLS = ['gated_unresolvable', 'blocked_sent', 'blockers_resolved', 'citations_rejected', 'follow_ups_sent',
                   'follow_ups_unresolved', 'follow_ups_follow_up_cap_reached', 'model_resolved_finding',
                   'model_resolved_protected', 'model_resolved_review']


def precision(reports, keyed, noise_rows, controls):
    """Per sample and family: keyed true/false findings, unkeyed and test-path
    census, noise classes, protected-control outcomes and fixed-outcome requests.
    keyed is a list of (row, app) whose rows can select records."""
    result = {}
    for app, report in reports.items():
        fs = presented(report)
        entries = {e['id']: e for e in report.get('entries', [])}
        role = {}
        for row in keyed:
            if row.get('app') != app or 'kind' not in row or 'file' not in row:
                continue
            pol = 'positive' if row['expect'] == 'positive' else 'control' if row['expect'] in CONTROL_EXPECT else 'assessment'
            sel = dict(row)
            if row['expect'] == 'only_lines':
                sel.pop('lines', None)
            for u in select(sel, report, entries):
                if row['expect'] == 'only_lines' and u['sink']['span']['start_line'] in row['lines']:
                    pol_u = 'assessment'
                else:
                    pol_u = pol
                role.setdefault(u['id'], set()).add(pol_u)
        fam = {}
        def get(k):
            return fam.setdefault(k, {'records': 0, 'findings': 0, 'keyed_true': 0, 'keyed_false': 0, 'unkeyed': 0, 'unkeyed_findings': 0, 'test_path': 0})
        for u in report['uses']:
            d = get(family(u['kind']))
            d['records'] += 1
            finding = is_finding(fs.get(u['id']))
            d['findings'] += finding
            r = role.get(u['id'])
            if r is None:
                d['unkeyed'] += 1
                d['unkeyed_findings'] += finding
            elif finding and 'positive' in r:
                d['keyed_true'] += 1
            elif finding and r == {'control'}:
                d['keyed_false'] += 1
            if TEST_PATH.search(u['sink']['span']['file'] or ''):
                d['test_path'] += 1
        for k, classes in noise_classes(report, [n for n in noise_rows if n['app'] == app]).items():
            get(k).update(classes)
        for k, v in fixed_outcome(report).items():
            get(k).update(v)
        for k, v in resolution(report).items():
            get(k).update(v)
        # A judged row names who judged it, so the corpus can be re-measured
        # when a model or question set changes.
        for u in report['uses']:
            a = u.get('assessment') or {}
            if a.get('status') == 'completed':
                d = get(family(u['kind']))
                judged = set(d.get('judged_by', []))
                judged.add('/'.join([a.get('provider', ''), a.get('model', ''), a.get('question_version', '')]))
                d['judged_by'] = sorted(judged)
        for c in controls:
            if c['app'] != app:
                continue
            d = get(family(c['kind']))
            for u in select(c, report, entries):
                st = (fs.get(u['id']) or {}).get('status', 'needs_review')
                key = 'control_false_finding' if is_finding(fs.get(u['id'])) else 'control_protected' if st == 'protected_for_claim' else 'control_review'
                d[key] = d.get(key, 0) + 1
        result[app] = dict(sorted(fam.items()))
    return result


def precision_markdown(prec):
    cols = ['records', 'findings', 'keyed_true', 'keyed_false', 'unkeyed', 'unkeyed_findings', 'test_path',
            'construction_no_origin', 'construction_no_origin_finding', 'undecidable_validation', 'shared_sink_fanout',
            'same_entry_sink_extra', 'own_api_request_origin', 'stored_origin_unresolved', 'stored_literal_writes',
            'unknown_context_raw', 'closed_type_map', 'control_false_finding', 'control_protected', 'control_review',
            'fixed_outcome_requests', 'substantive_discarded'] + RESOLUTION_COLS
    lines = ['| App | Family | ' + ' | '.join(cols) + ' | Judged by |', '|---|---|' + '---|' * len(cols) + '---|']
    for app, fams in prec.items():
        for f, d in fams.items():
            lines.append(f'| {app} | {f} | ' + ' | '.join(str(d.get(c, 0)) for c in cols) + ' | ' + (', '.join(d.get('judged_by', [])) or 'offline') + ' |')
    return '\n'.join(lines) + '\n'


def markdown(out):
    lines = ['| Case | App | Kind | Anchor | Expectation | Tag | Result | Uses / entries | Notes |',
             '|---|---|---|---|---|---|---|---|---|']
    for o in out:
        anchor = o.get('file', '')
        if o.get('line'):
            anchor += f":{o['line']}"
        expect = o['expect'] + (f" ({o['key_expect']})" if o.get('key_expect') else '')
        notes = o.get('reason') or ', '.join(o.get('blockers') or []) or ''
        if o.get('vacuous'):
            notes = (notes + '; ' if notes else '') + 'no matching record (vacuous)'
        if o.get('assessment'):
            notes = (notes + '; ' if notes else '') + 'assessment unmeasured offline'
        if 'observed_lines' in o:
            notes = (notes + '; ' if notes else '') + 'lines ' + ','.join(map(str, o['observed_lines']))
        fan = f"{o['uses']} / {o['entries']}" if 'uses' in o else ''
        kind = (o.get('kind') or '').replace('_candidate', '')
        anchor = anchor.replace('|', '\\|')
        lines.append(f"| {o['id']} | {o['app']} | {kind} | `{anchor}` | {expect} | {o.get('tag', '')} | {o['outcome']} | {fan} | {notes} |" if anchor else f"| {o['id']} | {o['app']} | {kind} | | {expect} | {o.get('tag', '')} | {o['outcome']} | {fan} | {notes} |")
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('reports', type=Path)
    p.add_argument('--lab')
    p.add_argument('--json', type=Path)
    p.add_argument('--markdown', type=Path, help='write the per-row Markdown table')
    p.add_argument('--precision-markdown', type=Path, help='write the per-family precision and noise table')
    a = p.parse_args()
    reports = {k: json.loads(Path(v).read_text()) for k, v in json.loads(a.reports.read_text()).items()}
    frozen = json.loads((Path(__file__).parent / 'cases.json').read_text())
    ev = evaluator()
    rows = []
    for c in frozen['cases']:
        c.setdefault('tag', 'independent')
        res = {'outcome': 'excluded'} if c['expect'] == 'excluded' else classify(c, reports[c['app']])
        rows.append((c, res))
    for app in PYTHON_APPS:
        rows.extend(python_rows(app, reports[app], ev))
    if a.lab:
        rows.extend(lab_rows(a.lab, reports['vuln-nextjs']))
    out = [{**{k: v for k, v in r.items() if k in ('id', 'app', 'kind', 'file', 'line', 'expect', 'key_expect', 'tag', 'reason', 'key')}, **res} for r, res in rows]
    summary = {}
    for o in out:
        summary.setdefault(o['outcome'], 0)
        summary[o['outcome']] += 1
    summary['vacuous_control_pass'] = sum(1 for o in out if o.get('vacuous'))
    keyed = [r for r, _ in rows if r.get('expect') not in ('excluded', 'registration')]
    controls = json.loads((Path(__file__).parent / 'protected-controls.json').read_text())['controls']
    prec = precision(reports, keyed, frozen.get('noise_rows', []), controls)
    doc = {'rows': out, 'summary': summary, 'total': len(out), 'precision': prec}
    if a.json:
        a.json.write_text(json.dumps(doc, indent=2) + '\n')
    if a.markdown:
        a.markdown.write_text(markdown(out))
    if a.precision_markdown:
        a.precision_markdown.write_text(precision_markdown(prec))
    for o in out:
        if o['outcome'] in ('missing_candidate', 'candidate_evidence_gap', 'control_fail', 'missing_registration'):
            print(o['app'], o['id'], o['outcome'], o.get('blockers', ''), o.get('observed_lines', ''))
    for app, fams in prec.items():
        for f, d in fams.items():
            print('precision', app, f, json.dumps(d, sort_keys=True))
    print(json.dumps(summary, sort_keys=True), 'total', len(out))


if __name__ == '__main__':
    main()
