#!/usr/bin/env python3
"""Reject mixed or locally edited shared-library sources before a coordinated build."""
import argparse
import json
import pathlib
import subprocess
import sys


def verify(manifest, common_root):
    failures = []
    for name, expected in manifest['commonLibraries'].items():
        repository = common_root / name
        try:
            actual = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
            dirty = subprocess.check_output(['git', '-C', str(repository), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            failures.append(f'{name}: required source checkout is unavailable')
            continue
        if actual != expected:
            failures.append(f'{name}: source revision does not match the release manifest')
        if dirty:
            failures.append(f'{name}: tracked source changes have not been committed')
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=pathlib.Path)
    parser.add_argument('--common-root', type=pathlib.Path, required=True)
    args = parser.parse_args()
    failures = verify(json.loads(args.manifest.read_text()), args.common_root)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print('Shared source revisions match the candidate release manifest.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
