#!/usr/bin/env python3
"""Classify every frozen phase 5 row against saved offline findings.json reports.

Usage: check.py <reports.json> [--lab <vuln-nextjs checkout>] [--json out.json]
reports.json maps app name to its findings.json path. Python rows come from
docs/samples/<app>/cases.json; vuln-nextjs rows from the lab key at the pin.
"""
import argparse
import importlib.util
import json
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
    doc = {'rows': out, 'summary': summary, 'total': len(out)}
    if a.json:
        a.json.write_text(json.dumps(doc, indent=2) + '\n')
    if a.markdown:
        a.markdown.write_text(markdown(out))
    for o in out:
        if o['outcome'] in ('missing_candidate', 'candidate_evidence_gap', 'control_fail', 'missing_registration'):
            print(o['app'], o['id'], o['outcome'], o.get('blockers', ''), o.get('observed_lines', ''))
    print(json.dumps(summary, sort_keys=True), 'total', len(out))


if __name__ == '__main__':
    main()
