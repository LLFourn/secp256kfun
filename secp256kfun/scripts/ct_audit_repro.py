#!/usr/bin/env python3
"""Require the pinned snapshot to survive a relocated Cargo home and fresh build."""
import argparse
import json
import os
from pathlib import Path
import tempfile

import ct_audit


def compare(first, second, baseline):
    functions = first['functions'].keys() | second['functions'].keys()
    return {
        'snapshots_equal': first == second,
        'matches_baseline': first == baseline,
        'configuration_equal': first['config'] == second['config'],
        'differing_functions': sorted(f for f in functions
                                      if first['functions'].get(f) != second['functions'].get(f)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=ct_audit.CONFIGS)
    args = parser.parse_args()
    destination = ct_audit.OUT / 'repro' / args.platform
    destination.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((ct_audit.AUDIT/'baselines'/f'{args.platform}.json').read_text())
    original_home = ct_audit.cargo_home()
    original_env = os.environ.get('CARGO_HOME')
    first = ct_audit.build(args.platform, destination/'original')
    with tempfile.TemporaryDirectory(prefix='relocated-home-of-ci-runner-', dir=destination) as tmp:
        relocated = Path(tmp)/'.cargo'
        relocated.symlink_to(original_home.resolve(), target_is_directory=True)
        try:
            os.environ['CARGO_HOME'] = str(relocated)
            second = ct_audit.build(args.platform, destination/'relocated')
        finally:
            if original_env is None:
                os.environ.pop('CARGO_HOME', None)
            else:
                os.environ['CARGO_HOME'] = original_env
        result = {**compare(first, second, baseline),
                  'original_cargo_home':str(original_home), 'relocated_cargo_home':str(relocated),
                  'binary_sha256':{name:ct_audit.sha(destination/name/args.platform/'ct_audit')
                                   for name in ('original','relocated')}}
    (destination/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    if not (result['snapshots_equal'] and result['matches_baseline']):
        raise SystemExit('REPRODUCIBILITY FAILED: see '+str(destination/'result.json'))
    print('Fresh builds with different Cargo home paths match the pinned snapshot.')


if __name__ == '__main__':
    main()
