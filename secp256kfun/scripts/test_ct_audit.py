import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import ct_audit
import ct_audit_inventory as inventory
import ct_audit_taint as taint
import ct_audit_analyze as analyzer
import ct_audit_relational as relational
import ct_audit_review as review
import ct_audit_repro as repro


class CallGraphTests(unittest.TestCase):
    def analyze(self, text, symbols, arch='aarch64'):
        return analyzer.analyze(text, symbols, arch, ['audit_root'])

    def test_conditional_tail_call_and_merged_root_alias(self):
        result=self.analyze('''00001000 <merged>:
1000: b.eq 0x2000 <helper>
1004: ret
00002000 <helper>:
2000: ldr x0, [x1, x2]
2004: str x0, [x3]
2008: br x4
''','00001000 T audit_root\n00001000 T merged\n00002000 T helper')
        self.assertEqual(result['roots']['audit_root'], ['merged','helper'])
        self.assertEqual(result['summary']['branches'],1)
        self.assertEqual(result['summary']['memory'],2)
        self.assertEqual(result['summary']['unresolved'],1)

    def test_riscv_signed_auipc_tail_and_zero_offset_jalr(self):
        result=self.analyze('''00001000 <helper>:
1000: ret
00002000 <audit_root>:
2000: auipc t1, 0xfffff
2004: jr 0x0(t1) <helper>
''','00002000 T audit_root\n00001000 T helper','riscv32')
        self.assertEqual(result['summary']['unresolved'],0)
        self.assertIn('helper',result['roots']['audit_root'])

    def test_missing_root_fails_closed(self):
        with self.assertRaises(ValueError):
            self.analyze('00001000 <unused>:\n1000: ret','00001000 T unused')

    def test_same_branch_count_different_code_changes_fingerprint(self):
        code='00001000 <audit_root>:\n1000: add x0, x0, #1\n1004: ret'
        first=self.analyze(code,'00001000 T audit_root')
        second=self.analyze(code.replace('#1','#2'),'00001000 T audit_root')
        self.assertEqual(first['summary']['branches'],second['summary']['branches'])
        self.assertNotEqual(first['functions']['audit_root']['code_sha256'], second['functions']['audit_root']['code_sha256'])

    def test_unknown_indirect_call_survives(self):
        result=self.analyze('00001000 <audit_root>:\n1000: callq *%rax\n1002: retq', '00001000 T audit_root','x86_64')
        self.assertEqual(result['summary']['unresolved'],1)

    def test_undecoded_instruction_and_name_collision_fail(self):
        with self.assertRaises(ValueError):
            self.analyze('00001000 <audit_root>:\n1000: <unknown>', '00001000 T audit_root')
        with self.assertRaises(ValueError):
            self.analyze('00001000 <same::h0123456789abcdef>:\n1000: bl 0x2000 <same>\n00002000 <same::hfedcba9876543210>:\n2000: ret', '00001000 T audit_root')


class GateTests(unittest.TestCase):
    def test_new_trait_method_and_missing_harness_case_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            audit=root/'secp256kfun/ct-audit'
            for relative in ['secp256kfun/ct-audit/contracts.json','secp256kfun/ct-audit/src/lib.rs',
                             'secp256kfun/ct-audit/src/taint.rs','secp256kfun/ct-audit/src/controls.rs','secp256kfun/src/backend/mod.rs','secp256kfun/src/op.rs']:
                dest=root/relative; dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_text((ct_audit.REPO/relative).read_text())
            with mock.patch.object(ct_audit,'REPO',root),mock.patch.object(ct_audit,'AUDIT',audit):
                ct_audit.coverage()
                trait=root/'secp256kfun/src/backend/mod.rs'
                original=trait.read_text()
                trait.write_text(original.replace('pub trait TimeSensitive {','pub trait TimeSensitive {\nfn new_secret_operation();'))
                with self.assertRaises(AssertionError):ct_audit.coverage()
                trait.write_text(original)
                trait.write_text(original+'\nfn unrelated_after_trait() {}\n')
                ct_audit.coverage()
                trait.write_text(original)
                for file, call in [('point.rs', 'ConstantTime::scalar_mul_norm_point'),
                                   ('scalar.rs', '<ConstantTime as TimeSensitive>::scalar_mul_basepoint'),
                                   ('nested/module.rs', 'T::basepoint_double_mul')]:
                    extra=root/'secp256kfun/src'/file; extra.parent.mkdir(parents=True,exist_ok=True)
                    extra.write_text(f'fn extra() {{ {call}(x, y); }}')
                    with self.assertRaises(AssertionError):ct_audit.coverage()
                    extra.unlink()
                lib=audit/'src/lib.rs'; lib_original=lib.read_text()
                lib.write_text(lib_original+'\npub fn audit_unregistered() {}\n')
                with self.assertRaises(AssertionError):ct_audit.coverage()
                lib.write_text(lib_original)
                driver=audit/'src/taint.rs'
                driver.write_text(driver.read_text().replace('check!(audit_scalar_add(', 'check!(removed_scalar_add('))
                with self.assertRaises(AssertionError):ct_audit.coverage()

    def test_inventory_secrecy_is_checked_against_explicit_signatures(self):
        manifest = json.loads((ct_audit.AUDIT/'contracts.json').read_text())
        sources = {p.name: p.read_text() for p in (ct_audit.AUDIT/'src').glob('*.rs')}
        inventory.validate(manifest, sources)
        for mutate in ('label', 'argument', 'alias', 'missing', 'implicit', 'generic', 'hidden-module'):
            m, src = copy.deepcopy(manifest), sources.copy()
            if mutate == 'label':
                m['functions']['audit_scalar_add']['secret_scalar'] = False
            elif mutate == 'argument':
                src['lib.rs'] = src['lib.rs'].replace('k: &Scalar<Secret, NonZero>', 'k: &Scalar<Public, NonZero>')
            elif mutate == 'alias':
                src['lib.rs'] = src['lib.rs'].replace('type S = Scalar<Secret, Zero>', 'type S = Scalar<Public, Zero>')
            elif mutate == 'missing':
                del m['functions']['audit_scalar_add']
            elif mutate == 'implicit':
                src['lib.rs'] = src['lib.rs'].replace('k: &Scalar<Secret, NonZero>', 'k: &Scalar')
            elif mutate == 'generic':
                src['lib.rs'] += '\npub fn audit_new<T>(x: T) {}'
            else:
                src['new.rs'] = 'pub fn audit_new(a: &S) {}'
            with self.assertRaises(AssertionError, msg=mutate):
                inventory.validate(m, src)

    def test_taint_gate_never_accepts_a_finding_or_partial_harness(self):
        good = {'returncode': 0, 'errors': [], 'completed': True}
        self.assertTrue(taint.clean(good))
        for mutation in ({'errors': [{'kind': 'UninitCondition'}]},
                         {'errors': None}, {'returncode': 99}, {'completed': False}):
            self.assertFalse(taint.clean({**good, **mutation}))
        manifest = {'roots': ['audit_scalar_add', 'audit_scalar_mul'], 'fixtures': [{'case': 0}, {'case': 1}]}
        lines = [f'case={case} root={root} completed' for case in (0, 1) for root in manifest['roots']]
        self.assertTrue(taint.completed('\n'.join(lines), '--taint', manifest))
        for broken in (lines[:-1], lines[:-1]+[lines[0]], lines+[lines[0]]):
            self.assertFalse(taint.completed('\n'.join(broken), '--taint', manifest))
        leak = {'gate_exit_code': 99, 'returncode': 99, 'completed': True,
                'errors': [{'kind': 'UninitValue', 'frames': [{'function': 'ct_control_address'}]}]}
        self.assertTrue(taint.detected(leak, 'address'))
        self.assertFalse(taint.detected(leak, 'branch'))
        self.assertFalse(taint.detected({**leak, 'completed': False}, 'address'))
        self.assertFalse(taint.detected({**leak, 'returncode': 1}, 'address'))
        with self.assertRaises(AssertionError):
            taint.findings('<valgrindoutput><protocoltool>memcheck</protocoltool><status><state>RUNNING</state></status></valgrindoutput>')

    def test_compiler_drift_stale_review_and_false_proof_fail(self):
        snap={'config':{'rustc':'one'},'roots':{'audit_root':['f']},'functions':{'f':{'code_sha256':'one','branch_offsets':[]}}}
        record={'configuration_sha256':analyzer.digest(snap['config']),
                'roots':{'audit_root':{'code_sha256':review.root_hash(snap,'audit_root'),'status':'inspected-with-gaps','reason':'reviewed','memory_scope':'fixed','review_note':'initial'}},
                'functions':{'f':{'code_sha256':'one','branch_reason':'none','address_reason':'fixed','branches':{}}}}
        review.validate(snap,record)
        changed=copy.deepcopy(snap);changed['config']['rustc']='two'
        with self.assertRaises(AssertionError):review.validate(changed,record)
        changed=copy.deepcopy(snap);changed['functions']['f']['code_sha256']='two'
        with self.assertRaises(AssertionError):review.validate(changed,record)
        record['roots']['audit_root']['status']='universal-proof'
        with self.assertRaises(AssertionError):review.validate(snap,record)

    def test_secure_word_does_not_hide_incomplete_solver_result(self):
        log='completed/cut paths 1\npending paths 0\ndiscontinued paths 0\nfailed assertions 0\nunknown 0\nProgram status is : secure'
        self.assertTrue(relational.accepted(log,'secure'))
        for mutation in [log.replace('discontinued paths 0','discontinued paths 1'),log+'\ntimeout',log.replace('unknown 0','unknown 1'),log.replace('completed/cut paths 1','completed/cut paths 0')]:
            self.assertFalse(relational.accepted(mutation,'secure'))

    def test_trait_braces_ignore_documentation_and_nested_default_body(self):
        source='pub trait TimeSensitive {\n // }\n fn f() { let s = "}"; if true {} }\n}\nfn outside() {}'
        self.assertNotIn('outside',ct_audit.trait_body(source))
        self.assertIn('fn f',ct_audit.trait_body(source))
        with self.assertRaises(ValueError):ct_audit.trait_body('pub trait TimeSensitive {')

    def test_cargo_home_remaps_symlink_and_binary_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); real=root/'real'; real.mkdir()
            link=root/'different-length-home'; link.symlink_to(real,target_is_directory=True)
            with mock.patch.dict(os.environ,{'CARGO_HOME':str(link)}):
                self.assertEqual(ct_audit.cargo_home(),link)
                remaps=ct_audit.path_remaps()
                self.assertIn((str(link),'/cargo'),remaps)
                self.assertIn((str(real.resolve()),'/cargo'),remaps)
                image=root/'image'; image.write_bytes(b'\0/cargo/registry/src/crate.rs\0')
                ct_audit.check_host_paths(image,remaps)
                for prefix,_ in remaps:
                    image.write_bytes(b'\0'+os.fsencode(prefix)+b'/crate.rs\0')
                    with self.assertRaises(RuntimeError):ct_audit.check_host_paths(image,remaps)
            with mock.patch.dict(os.environ,{'CARGO_HOME':'relative-home'}):
                self.assertEqual(ct_audit.cargo_home(),Path.cwd()/'relative-home')
            with mock.patch.dict(os.environ,{'CARGO_HOME':''}):
                self.assertEqual(ct_audit.cargo_home(),Path.home()/'.cargo')

    def test_repro_gate_rejects_code_drift_and_unreviewed_equal_builds(self):
        first={'config':{'cpu':'generic'},'functions':{'f':{'code_sha256':'one'}}}
        second=copy.deepcopy(first);second['functions']['f']['code_sha256']='two'
        drift=repro.compare(first,second,first)
        self.assertFalse(drift['snapshots_equal'])
        self.assertEqual(drift['differing_functions'],['f'])
        same=repro.compare(second,second,first)
        self.assertTrue(same['snapshots_equal'])
        self.assertFalse(same['matches_baseline'])

if __name__=='__main__':unittest.main()
