"""Score sample reports against their answer keys.

Usage: accuracy.py <check.py> <reports.json> <vuln-nextjs checkout> <out.json>
reports.json maps app name to a findings.json (or .json.gz) path. For each keyed
positive it reports the final presented status (confirmed, practice_finding,
protected, review, missed); for each keyed control and protected control it
reports whether a record presents as a finding (a false positive). A positive with
expect_status confirmed counts a construction-practice finding as review. A record that
also matches a keyed positive is never counted as a control false positive.
Findings outside the key are counted, not judged: their truth needs source review.
"""
import importlib.util, json, sys, gzip, collections
from pathlib import Path
CHK = Path(sys.argv[1]); reports_map = json.loads(Path(sys.argv[2]).read_text()); lab = sys.argv[3]
spec = importlib.util.spec_from_file_location('check', CHK); ck = importlib.util.module_from_spec(spec); spec.loader.exec_module(ck)
def load(p):
    b = Path(p).read_bytes()
    return json.loads(gzip.decompress(b) if p.endswith('.gz') else b)
reports = {k: load(v) for k, v in reports_map.items()}
frozen = json.loads((CHK.parent / 'cases.json').read_text())
ev = ck.evaluator(); rows = []
for c in frozen['cases']:
    if c['expect'] != 'excluded': rows.append(c)
for app in ck.PYTHON_APPS:
    rows.extend(r for r, _ in ck.python_rows(app, reports[app], ev))
rows.extend(r for r, _ in ck.lab_rows(lab, reports['vuln-nextjs']))
controls = json.loads((CHK.parent / 'protected-controls.json').read_text())['controls']
CONTROL = ck.CONTROL_EXPECT
out = collections.defaultdict(lambda: collections.Counter()); detail = []
positive_ids = set()
for r in rows:
    if r.get('expect') == 'positive' and 'kind' in r:
        rep = reports[r['app']]; ents = {e['id']: e for e in rep.get('entries', [])}
        positive_ids |= {u['id'] for u in ck.select(r, rep, ents)}
for r in rows:
    if r.get('expect') in ('excluded', 'registration') or 'kind' not in r: continue
    rep = reports[r['app']]; fs = ck.presented(rep); ents = {e['id']: e for e in rep.get('entries', [])}
    sel = dict(r)
    if r['expect'] == 'only_lines': sel.pop('lines', None)
    uses = ck.select(sel, rep, ents)
    if r['expect'] == 'positive':
        uses = [u for u in uses if 'source' not in r or ck.witnessed(u, r)] or uses
        st = [ (fs.get(u['id']) or {}).get('status', 'needs_review') for u in uses ]
        if not uses: s = 'missed'
        elif any((fs.get(u['id']) or {}).get('status') == 'confirmed_vulnerability' for u in uses): s = 'confirmed'
        elif any(ck.is_finding(fs.get(u['id'])) for u in uses): s = 'practice_finding'
        elif any(x == 'protected_for_claim' for x in st): s = 'protected'
        else: s = 'review'
        # A row that names the status it needs is not satisfied by a weaker finding.
        if r.get('expect_status') == 'confirmed' and s == 'practice_finding': s = 'review'
        out[r['app']]['positive'] += 1; out[r['app']]['pos_' + s] += 1
        if s != 'confirmed': detail.append((r['app'], r.get('id'), r['kind'], r['file'], r.get('line'), s, sorted({b for u in uses for b in ck.blockers(u)})))
    elif r['expect'] in CONTROL:
        if r['expect'] == 'only_lines':
            uses = [u for u in uses if u['sink']['span']['start_line'] not in r['lines']]
        fp = [u for u in uses if ck.is_finding(fs.get(u['id'])) and u['id'] not in positive_ids]
        if r['expect'] == 'only_sources':
            fp = [] if ck.classify(r, rep)['outcome'] == 'control_pass' else fp
        out[r['app']]['control'] += 1
        if fp:
            out[r['app']]['control_fp'] += 1; detail.append((r['app'], r.get('id'), r['kind'], r['file'], r.get('line'), 'FALSE_POSITIVE', []))
for c in controls:
    rep = reports[c['app']]; fs = ck.presented(rep); ents = {e['id']: e for e in rep.get('entries', [])}
    uses = ck.select(c, rep, ents)
    out[c['app']]['pcontrol'] += 1
    if any(ck.is_finding(fs.get(u['id'])) and u['id'] not in positive_ids for u in uses):
        out[c['app']]['pcontrol_fp'] += 1; detail.append((c['app'], c.get('id'), c['kind'], c['file'], c.get('line'), 'FALSE_POSITIVE(protected control)', []))
for app, rep in reports.items():
    fs = ck.presented(rep)
    out[app]['records'] = len(rep['uses'])
    out[app]['findings'] = sum(1 for u in rep['uses'] if ck.is_finding(fs.get(u['id'])))
    out[app]['keyed_findings'] = sum(1 for u in rep['uses'] if ck.is_finding(fs.get(u['id'])) and u['id'] in positive_ids)
    out[app]['confirmed'] = sum(1 for u in rep['uses'] if (fs.get(u['id']) or {}).get('status') == 'confirmed_vulnerability')
    out[app]['confirmed_unkeyed'] = sum(1 for u in rep['uses'] if (fs.get(u['id']) or {}).get('status') == 'confirmed_vulnerability' and u['id'] not in positive_ids)
json.dump({'apps': {k: dict(v) for k, v in out.items()}, 'detail': detail}, open(sys.argv[4], 'w'), indent=1)
for k, v in out.items(): print(k, dict(v))
for d in detail: print(*d)
