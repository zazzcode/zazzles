#!/usr/bin/env python3
"""Count reviewed false positives, checking that each tool reported each location.

Usage: count-scanner-false-positives.py <config.json>
config.json maps app -> {"root": prefix, "code-scan": findings.json,
"semgrep": results.json, "bearer": results.json, "semgrep-focused": results.json}.
"""
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location('m', HERE / 'match-scanner-results.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def code_scan(path):
    d = json.load(open(path))
    uses = {u['id']: u for u in d['uses']}
    out = set()
    for f in d['findings']:
        if f['status'] == 'confirmed_vulnerability':
            s = uses[f['use_id']]['sink'].get('span') or {}
            out.add(f"{s.get('file')}:{s.get('start_line')}")
    return out


def reported(tool, conf):
    if tool == 'code-scan':
        return code_scan(conf[tool])
    load = m.load_bearer if tool == 'bearer' else m.load_semgrep
    return {f"{r['file']}:{r['line']}" for r in load(conf[tool], conf['root'])}


def main():
    conf = json.load(open(sys.argv[1]))
    tools = json.load(open(HERE / 'scanner-false-positives.json'))['tools']
    failed = False
    for name, listed in (('code-scan', 'code-scan'), ('semgrep', 'semgrep'), ('semgrep-focused', 'semgrep'), ('bearer', 'bearer')):
        total = 0
        for app, c in conf.items():
            if name not in c:
                continue
            locations = [l for g in tools[listed][app] for l in g['locations']]
            assert len(locations) == len(set(locations)), (name, app, 'duplicate')
            seen = reported(name, c)
            missing = [l for l in locations if l not in seen]
            if missing and name != 'semgrep-focused':
                failed = True
                print('NOT REPORTED', name, app, missing)
            n = sum(l in seen for l in locations)
            total += n
            print(f'{name:16} {app:13} {n}')
        print(f'{name:16} {"total":13} {total}')
    sys.exit(failed)


if __name__ == '__main__':
    main()
