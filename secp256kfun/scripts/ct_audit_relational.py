#!/usr/bin/env python3
"""BINSEC checks on the pinned rv32 binary; never accepts incomplete exploration."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import ct_audit

CASES = {
    'audit_scalar_add': 'binary', 'audit_scalar_sub': 'binary',
    'audit_scalar_mul': 'binary', 'audit_scalar_negate': 'unary',
    'audit_scalar_eq': 'predicate2', 'audit_scalar_is_high': 'predicate',
    'audit_scalar_is_zero': 'predicate',
    'audit_scalar_cond_negate': 'conditional',
    'audit_scalar_invert': 'invert', 'audit_scalar_dot': 'dot',
    'audit_mul_base': 'basepoint', 'audit_mul_normalize': 'basepoint',
}
ORDER = '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'


def script(root, kind, public=False, lengths=None):
    lines = [f'starting from <{root}>', 'load sections .text, .rodata from file',
             'sp := 0x08000000', 'ra := 0x0bad0000']
    if kind == 'dot':
        left, right = lengths
        lines += ['a0 := 0x02000000', 'a1 := 0x02100000', f'a2 := {left}',
                  'a3 := 0x02200000', f'a4 := {right}']
        for register, name, count in [('a1', 'x', left), ('a3', 'y', right)]:
            for i in range(count):
                lines += [f'@[{register} + {i*32}, 32] := secret as {name}{i}',
                          f'assume {name}{i} < {ORDER}']
        return '\n'.join(lines+['halt at 0x0bad0000', 'explore all'])+'\n'
    if kind in ('binary', 'unary', 'conditional', 'invert', 'basepoint'):
        lines += ['a0 := 0x02000000', 'a1 := 0x02100000', 'a2 := 0x02200000']
        first, second = 'a1', 'a2'
    else:
        lines += ['a0 := 0x02100000', 'a1 := 0x02200000']
        first, second = 'a0', 'a1'
    if kind == 'control':
        secrecy = 'nondet' if public else 'secret'
        lines += [f'@[{first}, 32] := {secrecy} as x', f'assume x < {ORDER}', '@[a1, 256] := 0']
    else:
        lines += [f'@[{first}, 32] := secret as x', f'assume x < {ORDER}']
        if kind in ('binary', 'predicate2'):
            lines += [f'@[{second}, 32] := secret as y', f'assume y < {ORDER}']
    if kind in ('invert', 'basepoint'):
        lines += ['assume x <> 0']
    if kind == 'conditional':
        lines += ['a2 := secret as flag', 'assume flag < 2']
    lines += ['halt at 0x0bad0000', 'explore all']
    return '\n'.join(lines)+'\n'


def accepted(log, expected):
    complete = all(re.search(r'\b'+label+r'\s+0\b', log) for label in
                   ('pending paths', 'discontinued paths', 'failed assertions'))
    complete &= bool(re.search(r'completed/cut paths\s+[1-9][0-9]*\b', log))
    # The SMT summary prints a benign "unknown 0" counter.
    scrubbed = re.sub(r'unknown\s+0\b', '', log)
    bad = re.search(r'\b(timeout|unknown|unsupported|error|fatal)\b', scrubbed, re.I)
    status = f'Program status is : {expected}' in log
    return bool(complete and not bad and status)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binsec', default=os.environ.get('BINSEC', 'binsec'))
    p.add_argument('--platform', choices=['rv32','rv32-firmware'], default='rv32')
    p.add_argument('--only', choices=[*CASES, 'ct_control_branch', 'ct_control_address'])
    args = p.parse_args()
    ct_audit.coverage()
    dest = ct_audit.OUT / args.platform / 'relational'
    dest.mkdir(parents=True, exist_ok=True)
    binary = ct_audit.OUT/args.platform/'ct_audit'
    control_binary = ct_audit.OUT/'controls'/args.platform/'ct_audit'
    result = {'binary_sha256':ct_audit.sha(binary), 'controls_binary_sha256':ct_audit.sha(control_binary),
              'checker_sha256':ct_audit.sha(Path(__file__)), 'binsec':ct_audit.capture([args.binsec,'-version']).strip(),
              'solver':ct_audit.capture(['z3','--version']).strip(), 'cases':{}}
    if '0.11.3' not in result['binsec'] or result['solver'] != 'Z3 version 5.3.3 - 64 bit':
        raise SystemExit('re-audit required: expected BINSEC 0.11.3 and Z3 5.3.3')
    cases = [(root, kind, False, lengths) for root, kind in CASES.items()
             for lengths in ([(a, b) for a in range(3) for b in range(3)] if kind == 'dot' else [None])]
    cases += [(root, 'control', public, None) for root in ('ct_control_branch', 'ct_control_address') for public in (False, True)]
    for root, kind, public, lengths in cases:
        if args.only and root != args.only:
            continue
        case = root + ('-public' if public else '') + (f'-{lengths[0]}x{lengths[1]}' if lengths else '')
        image = control_binary if kind == 'control' else binary
        ini, output = dest/f'{case}.ini', dest/f'{case}.log'
        ini.write_text(script(root,kind,public,lengths))
        depth = '10000000' if kind == 'basepoint' else '1000000'
        command = [args.binsec,'-sse','-checkct','-smt-solver','z3','-smt-timeout','10',
                   '-sse-depth',depth,'-sse-timeout','90','-sse-script',str(ini),str(image)]
        with output.open('w') as f:
            try:
                proc = subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, timeout=100)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                rc = -999
        log = output.read_text()
        expected = 'insecure' if kind == 'control' and not public else 'secure'
        ok = rc == 0 and accepted(log,expected)
        result['cases'][case] = {'binary_sha256':ct_audit.sha(image),'expected':expected,'accepted':ok,'returncode':rc,'command':command}
        print(case, 'accepted' if ok else 'GAP / FAILED', flush=True)
    (dest/('result.json' if not args.only else f'{args.only}-result.json')).write_text(json.dumps(result,indent=2)+'\n')
    if not all(r['accepted'] for r in result['cases'].values()):
        raise SystemExit('relational check incomplete or failed; inspect logs, never a clean result')

if __name__ == '__main__': main()
