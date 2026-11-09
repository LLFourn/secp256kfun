#!/usr/bin/env python3
"""Require review records to bind baseline claims to exact code, not branch counts."""
import argparse
import json
from pathlib import Path
import subprocess

import ct_audit
import ct_audit_analyze as analyzer
import ct_audit_relational as relational


def root_hash(snapshot, root):
    return analyzer.digest({f:snapshot['functions'][f] for f in snapshot['roots'][root]})


def validate(snapshot, record):
    assert record['configuration_sha256'] == analyzer.digest(snapshot['config']), 'reviewed configuration changed'
    assert set(record['roots']) == set(snapshot['roots']), 'review coverage differs'
    for root, review in record['roots'].items():
        assert review['code_sha256'] == root_hash(snapshot,root), f'{root}: stale review record'
        assert review['status'] in ('known-leak','inspected-with-gaps','bounded-relational'), f'{root}: unsupported claim'
        assert review['reason'].strip() and review['memory_scope'].strip(), f'{root}: missing rationale'
        assert review['review_note'].strip(), f'{root}: missing re-audit note'
        if review['status'] == 'bounded-relational':
            assert snapshot['config']['target'] == 'riscv32imc-unknown-none-elf' and root in relational.CASES, f'{root}: no implemented relational check'
    assert set(record['functions']) == set(snapshot['functions']), 'function review coverage differs'
    for name, info in record['functions'].items():
        assert info['code_sha256'] == snapshot['functions'][name]['code_sha256'], f'{name}: changed instructions need review'
        assert info['branch_reason'].strip() and info['address_reason'].strip(), f'{name}: missing analysis'
        assert set(info['branches']) == {str(x) for x in snapshot['functions'][name]['branch_offsets']}, f'{name}: unclassified branch'
        assert all(x['class'] in ('public-structure','fixed-loop','valid-input-invariant','secret-dependent','unresolved') and x['reason'].strip() for x in info['branches'].values()), f'{name}: incomplete classification'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', help='PR base commit; updated snapshots must update their review records')
    args=parser.parse_args()
    for platform in ct_audit.CONFIGS:
        base=ct_audit.AUDIT/'baselines'/f'{platform}.json'
        notes=ct_audit.AUDIT/'reviews'/f'{platform}.json'
        snapshot=json.loads(base.read_text()); record=json.loads(notes.read_text())
        validate(snapshot,record)
        if args.base:
            def previous(path):
                proc=subprocess.run(['git','show',f'{args.base}:{path.relative_to(ct_audit.REPO)}'],capture_output=True,text=True)
                return json.loads(proc.stdout) if proc.returncode==0 else None
            old=previous(base); old_record=previous(notes)
            if old and old != snapshot:
                assert old_record != record, f'{platform}: baseline changed without a review record change'
                for root in set(old['roots']) & set(snapshot['roots']):
                    if old['config'] != snapshot['config'] or root_hash(old,root) != root_hash(snapshot,root):
                        assert old_record and record['roots'][root]['review_note'] != old_record['roots'][root]['review_note'], f'{root}: add the reasoning for this re-audit'
    print('All candidate baselines have matching review records. Peer approval remains required.')

if __name__=='__main__': main()
