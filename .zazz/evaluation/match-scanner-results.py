#!/usr/bin/env python3
"""Match Semgrep and Bearer results to answer-key rows.

A result matches a key row when it is in the row's file, its rule maps to the
row's weakness class, and, when the row gives a line, it is within three lines.
A result near two rows of one class belongs to the nearer one. A row whose
expectation is a control (no record, guarded and the like) that a result
matches is a false positive of that scanner. Results that match no row are
listed by rule and are not judged.
"""
import collections
import json

KIND_CLASS = {
    'sql_query_candidate': 'sql', 'nosql_query_candidate': 'nosql', 'xss_candidate': 'xss',
    'command_execution_candidate': 'command', 'path_traversal_candidate': 'path',
    'file_upload_candidate': 'upload', 'ssrf_candidate': 'ssrf', 'code_execution_candidate': 'code',
    'template_injection_candidate': 'code', 'deserialization_candidate': 'deserialization',
    'info_exposure_candidate': 'exposure', 'mass_assignment_candidate': 'mass-assignment',
    'authorization_candidate': 'authorization', 'account_enumeration_candidate': 'enumeration',
    'recovery_delivery_candidate': 'recovery', 'password_hash_candidate': 'weak-hash',
    'configuration_candidate': 'configuration', 'open_redirect_candidate': 'redirect',
    'log_sink_candidate': 'logging', 'prototype_write_candidate': 'pollution',
}
# First match wins. Substrings of the tool's rule identifier.
RULE_CLASS = [
    ('nosql', 'nosql'), ('sql_injection', 'sql'), ('sql-injection', 'sql'), ('sequelize-injection', 'sql'),
    ('tainted-sql', 'sql'), ('doctrine-dbal-dangerous-query', 'sql'),
    ('cross_site_scripting', 'xss'), ('xss', 'xss'), ('dangerouslysetinnerhtml', 'xss'),
    ('dangerously_set_inner_html', 'xss'), ('raw_html', 'xss'), ('raw_output', 'xss'),
    ('dangerous_insert_html', 'xss'), ('echoed-request', 'xss'),
    ('var-in-href', 'xss'), ('template-explicit-unescape', 'xss'), ('unquoted-attribute-var', 'xss'),
    ('unknown-value-with-script-tag', 'xss'), ('detect-replaceall-sanitization', 'xss'),
    ('detect-child-process', 'command'), ('exec-use', 'command'),
    ('tainted-exec', 'command'), ('exec_using_user_input', 'command'), ('os_command', 'command'),
    ('path_traversal', 'path'), ('tainted-filename', 'path'), ('res-sendfile', 'path'),
    ('non_literal_fs_filename', 'path'), ('path_using_user_input', 'path'), ('external_file_upload', 'path'),
    ('path-join-resolve-traversal', 'path'), ('unlink-use', 'path'),
    ('server_side_request_forgery', 'ssrf'), ('http_url_using_user_input', 'ssrf'),
    ('eval', 'code'), ('code-string-concat', 'code'),
    ('open_redirect', 'redirect'), ('open-redirect', 'redirect'), ('unknown-value-in-redirect', 'redirect'),
    ('deserialization', 'deserialization'), ('unserialize-use', 'deserialization'),
    ('insecure-object-assign', 'mass-assignment'), ('prototype-pollution', 'pollution'),
    ('directory-listing', 'configuration'), ('exposed_dir_listing', 'configuration'),
    ('cookie_missing_http_only', 'configuration'), ('insecure_cookie', 'configuration'),
    ('md5-used-as-password', 'weak-hash'), ('weak_hash', 'weak-hash'),
    ('weak-crypto', 'weak-hash'), ('node_md5', 'weak-hash'),
    ('phpinfo', 'exposure'), ('information_leakage', 'exposure'),
    ('generic_error_disclosure', 'exposure'),
    ('logger_leak', 'logging'),
]
POSITIVE = {'positive'}
SAFE = {'no_record', 'guarded', 'not_raw', 'bound', 'encoded', 'control_assessment', 'only_lines'}

def rule_class(rule):
    r = rule.lower()
    for part, cls in RULE_CLASS:
        if part in r:
            return cls
    return 'other'

def load_semgrep(path, root):
    out = []
    for x in json.load(open(path))['results']:
        out.append({'rule': x['check_id'].split('.')[-1], 'file': x['path'].replace(root, ''), 'line': x['start']['line']})
    return out

def load_bearer(path, root):
    out = []
    for level, items in json.load(open(path)).items():
        if isinstance(items, list):
            for x in items:
                out.append({'rule': x['id'], 'file': x['filename'].replace(root, ''), 'line': x['line_number']})
    return out

def anchors(row):
    if 'anchors' in row and isinstance(row['anchors'], dict):
        return [(f, l) for f, ls in row['anchors'].items() for l in ls]
    if 'lines' in row:
        return [(row.get('file'), l) for l in row['lines']]
    return [(row.get('file'), row.get('line'))]

def hits(row, results):
    cls = KIND_CLASS.get(row.get('kind'))
    found = []
    for f, line in anchors(row):
        for r in results:
            if r['file'] != f or rule_class(r['rule']) != cls:
                continue
            if line is None or abs(r['line'] - line) <= 3:
                found.append(r)
    return found

def distance(row, r):
    """Smallest line distance from a result to an anchor of the row in its file."""
    best = None
    for f, line in anchors(row):
        if f != r['file']:
            continue
        d = 0 if line is None else abs(r['line'] - line)
        best = d if best is None else min(best, d)
    return best


def match(rows, tools):
    rows = [r for r in rows if r['expect'] in POSITIVE | SAFE and r.get('kind')]
    table, used = [], {t: set() for t in tools}
    cells = {id(row): {t: [] for t in tools} for row in rows}
    for t, results in tools.items():
        for r in results:
            # A result belongs to the nearest row of its class in its file, so
            # two rows on neighbouring lines do not share one result.
            near = [(distance(row, r), i) for i, row in enumerate(rows) if r in hits(row, [r])]
            if not near:
                continue
            best = min(d for d, _ in near)
            for d, i in near:
                if d == best:
                    cells[id(rows[i])][t].append(r)
            used[t].add((r['rule'], r['file'], r['line']))
    for row in rows:
        table.append((row, cells[id(row)]))
    rest = {t: [r for r in results if (r['rule'], r['file'], r['line']) not in used[t]] for t, results in tools.items()}
    return table, rest

def load_rows(check, app, cases=None):
    """Key rows of one app from a check.py --json file, with anchors from cases.json."""
    data = json.load(open(check))
    rows = [dict(r) for r in (data if isinstance(data, list) else data['rows']) if r['app'] == app]
    if cases:
        full = {c['id']: c for c in json.load(open(cases))['cases']}
        for r in rows:
            for k in ('anchors', 'lines', 'line', 'file'):
                if k in full.get(r['id'], {}):
                    r[k] = full[r['id']][k]
    return rows


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('check', help='output of recall-gap-inventory/check.py --judged --json')
    p.add_argument('app', help='application name as the key spells it')
    p.add_argument('root', help='absolute path prefix to strip from result paths, with a trailing slash')
    p.add_argument('tools', nargs='+', help='semgrep=<results.json> and/or bearer=<results.json>')
    p.add_argument('--cases', help='recall-gap-inventory/cases.json, for row anchors')
    a = p.parse_args()
    tools = {}
    for spec in a.tools:
        name, path = spec.split('=', 1)
        tools[name] = (load_semgrep if name == 'semgrep' else load_bearer)(path, a.root)
    table, rest = match(load_rows(a.check, a.app, a.cases), tools)
    for row, cells in table:
        kind = 'VULN' if row['expect'] in POSITIVE else 'SAFE'
        z = row.get('judged_outcome') or row.get('outcome')
        loc = ';'.join(f'{f}:{l}' if l else str(f) for f, l in anchors(row))
        cols = [t + '=' + (','.join(sorted({f"{r['rule']}@{r['line']}" for r in cells[t]})) or '-') for t in tools]
        print(f"{kind} {row['id']:<22} {KIND_CLASS.get(row['kind'], '?'):<15} zazzles={z:<18} {' | '.join(cols)}  [{loc}]")
    for t in tools:
        c = collections.Counter((rule_class(r['rule']), r['rule']) for r in rest[t])
        print(f'-- {t} results outside the key: {len(rest[t])}')
        for (cls, rule), n in sorted(c.items(), key=lambda kv: (kv[0][0] == 'other', -kv[1])):
            print(f'     {n:4} {cls:<14} {rule}')


if __name__ == '__main__':
    main()
