"""Reject every executed secret-dependent branch/address; self-test rejection paths."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET

import ct_audit


def findings(xml):
    root = ET.fromstring(xml)
    assert root.tag == 'valgrindoutput'
    assert root.findtext('protocoltool') == 'memcheck'
    assert root.findtext('status/state') == 'RUNNING'
    assert any(s.findtext('state') == 'FINISHED' for s in root.findall('status'))
    errors = []
    for error in root.findall('error'):
        frames = [{'function': f.findtext('fn', '?'), 'ip': f.findtext('ip', '?')}
                  for f in error.find('stack').findall('frame')]
        errors.append({'kind': error.findtext('kind'), 'frames': frames})
    return errors


def completed(stdout, mode, manifest):
    if '-control-' in mode:
        return stdout.strip() == f'{mode}: 4 scalar control cases completed'
    pairs = re.findall(r'^case=(\d+) root=(audit_\w+) completed$', stdout, re.M)
    expected = {(str(case['case']), root) for case in manifest['fixtures'] for root in manifest['roots']}
    return len(pairs) == len(expected) and set(pairs) == expected


def clean(run):
    return run['returncode'] == 0 and run['errors'] == [] and run['completed']


def detected(run, kind):
    expected = 'UninitCondition' if kind == 'branch' else 'UninitValue'
    return (run['gate_exit_code'] == 99 and run['returncode'] == 99 and run['completed']
            and bool(run['errors'])
            and all(e['kind'] == expected and any(f'ct_control_{kind}' in f['function']
                    for f in e['frames']) for e in run['errors']))


def input_pins():
    paths = [p for base in ('secp256kfun/src', 'arithmetic_macros/src', 'secp256kfun/ct-audit/src')
             for p in (ct_audit.REPO/base).rglob('*.rs')]
    paths += list((ct_audit.REPO/'secp256kfun/scripts').glob('ct_audit*.py'))
    paths += [ct_audit.REPO/p for p in ('Cargo.toml', 'secp256kfun/Cargo.toml',
              'arithmetic_macros/Cargo.toml', 'secp256kfun/README.md',
              'secp256kfun/ct-audit/Cargo.toml', 'secp256kfun/ct-audit/Cargo.lock',
              'secp256kfun/ct-audit/contracts.json')]
    return {str(p.relative_to(ct_audit.REPO)): ct_audit.sha(p) for p in sorted(paths)}


def build_native(destination):
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64', 'native gate requires Linux x86_64'
    rustc = ct_audit.capture(['rustc', '-Vv'])
    assert 'release: 1.98.1\n' in rustc and 'LLVM version: 22.1.8\n' in rustc
    assert 'host: x86_64-unknown-linux-gnu\n' in rustc
    outputs = []
    for kind in ('normal', 'controls'):
        env = os.environ.copy()
        for key in tuple(env):
            if key.startswith(('CARGO_PROFILE_', 'CARGO_TARGET_')) or key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS'):
                env.pop(key)
        flags = ['-C', 'target-cpu=x86-64', '-C', 'relocation-model=static', '-C', 'link-arg=-no-pie']
        env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
        target_dir = destination/'build'/kind
        env['CARGO_TARGET_DIR'] = str(target_dir)
        features = 'std,negative-controls' if kind == 'controls' else 'std'
        command = ['cargo', 'build', '--manifest-path', str(ct_audit.AUDIT/'Cargo.toml'),
                   '--release', '--locked', '--bin', 'ct_audit', '--target',
                   'x86_64-unknown-linux-gnu', '--no-default-features', '--features', features]
        subprocess.run(command, env=env, check=True)
        binary = target_dir/'x86_64-unknown-linux-gnu/release/ct_audit'
        pins = {'binary_sha256': ct_audit.sha(binary), 'rustc': rustc,
                'linker': ct_audit.capture(['cc', '--version']), 'command': command,
                'flags': flags, 'profile': 'release: opt=3, cgu=1, no LTO, panic=abort, debug=1',
                'inputs': input_pins(), 'hardware': platform.uname()._asdict(),
                'scope': 'This native Linux build is measured per run; it is not the Mac-cross drift image.'}
        (destination/f'{kind}-build.json').write_text(json.dumps(pins, indent=2)+'\n')
        outputs.append(binary)
    return outputs


def check_run(binary, mode, runner, destination, manifest):
    command = shlex.split(runner)+['valgrind', '--tool=memcheck', '--xml=yes', '--xml-fd=2',
               '--error-exitcode=99', '--track-origins=yes', '--error-limit=no', str(binary), mode]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=900)
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        stdout, stderr, rc = '', 'Valgrind run timed out', -999
    (destination/'output.xml').write_text(stderr)
    (destination/'output.stdout').write_text(stdout)
    try:
        errors = findings(stderr)
    except (ET.ParseError, AssertionError, AttributeError):
        errors = None
    result = {'command': command, 'binary_sha256': ct_audit.sha(binary), 'returncode': rc,
              'errors': errors, 'completed': completed(stdout, mode, manifest)}
    result['gate_exit_code'] = 0 if clean(result) else 99
    (destination/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result['gate_exit_code']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', default='', help='optional local emulation prefix; absent on hosted native CI')
    parser.add_argument('--binary', type=Path, default=ct_audit.OUT/'x86/ct_audit')
    parser.add_argument('--controls-binary', type=Path, default=ct_audit.OUT/'controls/x86/ct_audit')
    parser.add_argument('--build-native', action='store_true')
    parser.add_argument('--output', type=Path, default=ct_audit.OUT/'taint')
    parser.add_argument('--inject-control', choices=['branch', 'address'])
    parser.add_argument('--control-switch', type=Path)
    parser.add_argument('--check-run', choices=['--defined', '--taint', '--secret-control-branch',
                        '--secret-control-address', '--public-control-branch', '--public-control-address'])
    args = parser.parse_args()
    if args.control_switch:
        switch = json.loads(args.control_switch.read_text())
        assert set(switch) == {'inject'} and switch['inject'] in (None, 'branch', 'address'), 'invalid CI control switch'
        assert not args.inject_control, 'use only one control trigger'
        args.inject_control = switch['inject']
    manifest = ct_audit.coverage()
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if args.check_run:
        return check_run(args.binary, args.check_run, args.runner, destination, manifest)
    if args.build_native:
        assert not args.runner, 'native CI must not use an emulator'
        args.binary, args.controls_binary = build_native(destination)
    version = ct_audit.capture(shlex.split(args.runner)+['valgrind', '--version']).strip()
    if version != 'valgrind-3.22.0':
        raise SystemExit('re-audit required: expected Valgrind 3.22.0')
    report = {'valgrind': version, 'host': platform.uname()._asdict(), 'runner': args.runner,
              'native_build': args.build_native, 'inputs': input_pins(),
              'control_switch_sha256': ct_audit.sha(args.control_switch) if args.control_switch else None,
              'normal_binary_sha256': ct_audit.sha(args.binary),
              'controls_binary_sha256': ct_audit.sha(args.controls_binary), 'runs': {}}
    modes = ['--defined', '--taint', '--public-control-branch', '--secret-control-branch',
             '--public-control-address', '--secret-control-address']
    for mode in modes:
        dest = destination/mode[2:]
        binary = args.controls_binary if '-control-' in mode else args.binary
        command = [sys.executable, str(Path(__file__).resolve()), '--check-run='+mode,
                   '--binary', str(binary), '--runner', args.runner, '--output', str(dest)]
        proc = subprocess.run(command, timeout=930)
        result = json.loads((dest/'result.json').read_text())
        assert proc.returncode == result['gate_exit_code'], 'checker exit status disagrees with evidence'
        report['runs'][mode] = result
        print(mode, 'gate exit', proc.returncode, flush=True)
    valid = all(clean(report['runs'][mode]) for mode in modes if not mode.startswith('--secret-control-'))
    valid &= all(detected(report['runs'][f'--secret-control-{kind}'], kind) for kind in ('branch', 'address'))
    report['self_tests_passed'] = bool(valid)
    report['injected_control'] = args.inject_control
    (destination/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    if not valid:
        raise SystemExit('CT VIOLATION or invalid/incomplete detector control; inspect per-run evidence')
    if args.inject_control:
        print('CT VIOLATION: deliberately enabled secret-scalar '+args.inject_control+' control', flush=True)
        return report['runs']['--secret-control-'+args.inject_control]['gate_exit_code']
    print('Zero production taint findings; secret controls rejected and public controls accepted. Sampled paths only.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
