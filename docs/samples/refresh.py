#!/usr/bin/env python3
"""Regenerate the checked-in sample views offline from their canonical JSON."""
import argparse
import gzip
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scan', default='./bin/scan', help='compiled scan executable')
    names = ('juice-shop', 'vulnerable-typescript-app', 'nodejs-goof',
             'ThreatByte', 'python-insecure-app', 'vulnerable-flask-app', 'vulnpy',
             'oss-oopssec-store', 'vuln-nextjs', 'vuln-nextjs-prototype-pollution', 'dvwa')
    parser.add_argument('--sample', action='append', choices=names, help='refresh only selected samples')
    parser.add_argument('--compress', action='store_true', help='store complete JSON/SARIF as gzip files for large reports')
    args = parser.parse_args()
    executable = str(Path(args.scan).resolve())
    for name in args.sample or names:
        folder = Path(__file__).resolve().parent / name
        source = folder / 'findings.json'
        if not source.exists():
            source = folder / 'findings.json.gz'
        compressed = args.compress or (folder / 'findings.json.gz').exists()
        data = gzip.decompress(source.read_bytes()) if source.suffix == '.gz' else source.read_bytes()
        report = json.loads(data)
        report['root'] = name  # Public sample label; never publish a developer's home path.
        canonical = (json.dumps(report, indent=2, ensure_ascii=False) + '\n').encode()
        destination = folder / ('findings.json.gz' if compressed else 'findings.json')
        destination.write_bytes(gzip.compress(canonical, mtime=0) if compressed else canonical)
        # Exporters consume the unchanged canonical schema, even when the stored
        # artifact is compressed to stay below hosting file-size limits.
        with tempfile.TemporaryDirectory(prefix='zazzles-sample-') as scratch:
            export_source = Path(scratch) / 'findings.json'
            export_source.write_bytes(canonical)
            for mode, suffix in (('--export-html', 'html'), ('--export-sarif', 'sarif')):
                rendered = subprocess.run([executable, mode, str(export_source)], check=True, capture_output=True).stdout
                if suffix == 'html':
                    # Source whitespace remains exact in canonical JSON; normalize the published view.
                    rendered = b'\n'.join(line.rstrip() for line in rendered.splitlines()).rstrip(b'\n') + b'\n'
                if compressed and suffix == 'sarif':
                    suffix += '.gz'
                    rendered = gzip.compress(rendered, mtime=0)
                destination = folder / ('findings.' + suffix)
                temporary = destination.with_suffix(destination.suffix + '.tmp')
                temporary.write_bytes(rendered)
                temporary.replace(destination)
        if compressed:
            for suffix in ('json', 'sarif'):
                (folder / ('findings.' + suffix)).unlink(missing_ok=True)
        print(f'Refreshed {name}: HTML and SARIF from saved JSON (no model calls)')


if __name__ == '__main__':
    main()
