#!/usr/bin/env python3
"""Rebuild pinned audit images and inventory their optimized machine code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import ct_audit_analyze as analyzer
import ct_audit_inventory as inventory

REPO = Path(__file__).resolve().parents[2]
AUDIT = REPO / 'secp256kfun/ct-audit'
OUT = REPO / 'target/ct-audit'
CONFIGS = {
    'darwin': ('aarch64-apple-darwin', 'aarch64', 'apple-m1', 'release', 'std'),
    'arm-linux': ('aarch64-unknown-linux-gnu', 'aarch64', 'generic', 'release', 'std'),
    'x86': ('x86_64-unknown-linux-gnu', 'x86_64', 'x86-64', 'release', 'std'),
    'rv32': ('riscv32imc-unknown-none-elf', 'riscv32', 'generic-rv32', 'release', ''),
    'rv32-firmware': ('riscv32imc-unknown-none-elf', 'riscv32', 'generic-rv32', 'firmware', 'firmware'),
}


def capture(args):
    return subprocess.check_output([str(x) for x in args], text=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trait_body(source):
    start = re.search(r'\bpub\s+trait\s+TimeSensitive\s*\{', source)
    if not start:
        raise ValueError('TimeSensitive trait declaration missing')
    depth = 1
    # Ignore quoted strings and comments so documentation cannot end the trait early.
    tokens = re.finditer(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', source[start.end():], re.S)
    for token in tokens:
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if depth == 0:
                return source[start.end():start.end()+token.start()]
    raise ValueError('TimeSensitive trait closing brace missing')


def cargo_home():
    value = os.environ.get('CARGO_HOME')
    # Cargo makes relative overrides absolute but does not canonicalize symlinks.
    return Path(value).absolute() if value else Path.home() / '.cargo'


def path_remaps():
    roots = [(Path.home(), '/build-home'), (cargo_home(), '/cargo'),
             (REPO, '/audit'), (OUT/'zig-cache', '/zig-cache')]
    mappings = {}
    for path, replacement in roots:
        for spelling in (path.absolute(), path.resolve()):
            if spelling == Path('/'):
                raise ValueError('cannot use the filesystem root as a host-specific build prefix')
            mappings[str(spelling)] = replacement
    # rustc uses the last matching prefix; a relocated Cargo home can be inside REPO.
    return sorted(mappings.items(), key=lambda entry: (len(entry[0]), entry[0]))


def check_host_paths(binary, remaps):
    data = binary.read_bytes()
    leaked = [prefix for prefix, _ in remaps if os.fsencode(prefix) in data]
    if leaked:
        raise RuntimeError('host path remains in audit image; remap before recording: '+', '.join(leaked))


def coverage():
    manifest = json.loads((AUDIT / 'contracts.json').read_text())
    trait = trait_body((REPO / 'secp256kfun/src/backend/mod.rs').read_text())
    methods = set(re.findall(r'\bfn (\w+)', trait))
    declared = set(manifest['methods'])
    assert methods == declared, f'trait coverage differs: {methods ^ declared}'
    sources = {str(p.relative_to(AUDIT/'src')): p.read_text() for p in (AUDIT/'src').rglob('*.rs')}
    inventory.validate(manifest, sources)
    import ct_audit_relational as relational
    for root, entry in manifest['functions'].items():
        cases = ([f'{root}-{a}x{b}' for a in range(3) for b in range(3)]
                 if relational.CASES.get(root) == 'dot' else [root] if root in relational.CASES else [])
        assert entry['relational_cases'] == cases, f'relational coverage differs: {root}'
    source = sources['lib.rs']
    roots = set(re.findall(r'pub fn (audit_\w+)\(', source))
    assert len(manifest['roots']) == len(roots) and roots == set(manifest['roots']), 'root inventory differs'
    taint = (AUDIT / 'src/taint.rs').read_text()
    assert roots == set(re.findall(r'check!\((audit_\w+)\(', taint)), 'taint roots differ'
    mapped = set()
    src = REPO / 'secp256kfun/src'
    api = {str(p.relative_to(src)):p.read_text() for p in src.rglob('*.rs')
           if p.relative_to(src).parts[0] != 'backend'}
    for method, contract in manifest['methods'].items():
        assert contract['roots'] or contract.get('unreachable'), f'no case: {method}'
        assert set(contract['roots']) <= roots, f'unknown root for {method}'
        mapped.update(contract['roots'])
        if contract.get('unreachable'):
            # Any qualifier includes aliases, T::method and <T as TimeSensitive>::method.
            uses = [p for p, text in api.items() if re.search(r'::\s*'+method+r'\b', text)]
            assert not uses, f'previously unreachable {method} is now referenced in {uses}'
    assert roots <= mapped, f'unmapped roots: {roots-mapped}'
    return manifest


def llvm_tools():
    sysroot = Path(capture(['rustc', '--print', 'sysroot']).strip())
    host = re.search(r'^host: (.+)$', capture(['rustc', '-Vv']), re.M)[1]
    bindir = sysroot / 'lib/rustlib' / host / 'bin'
    for tool in ('llvm-objdump', 'llvm-nm', 'llvm-readobj', 'llvm-objcopy'):
        if not (bindir / tool).exists():
            raise RuntimeError('install the matching tools with rustup component add llvm-tools')
    return bindir


def build(name, output=OUT, controls=False):
    manifest = coverage()
    target, arch, cpu, profile, features = CONFIGS[name]
    if controls:
        features = ','.join(filter(None, [features, 'negative-controls']))
    rustc = capture(['rustc', '-Vv'])
    if 'release: 1.98.1\n' not in rustc or 'LLVM version: 22.1.8\n' not in rustc:
        raise RuntimeError('this baseline requires rustc 1.98.1 / LLVM 22.1.8; re-audit compiler changes')
    bindir = llvm_tools()
    dest = output / name
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(('CARGO_PROFILE_', 'CARGO_TARGET_')) or key in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
            env.pop(key)
    remaps = path_remaps()
    flags = ['-C', f'target-cpu={cpu}']
    for prefix, replacement in remaps:
        flags += ['--remap-path-prefix', f'{prefix}={replacement}']
    if name in ('x86','arm-linux'):
        flags += ['-C', 'relocation-model=static', '-C', 'link-arg=-no-pie']
    if arch == 'riscv32':
        flags += ['-C', 'link-arg=--entry=_start']
        for root in [*manifest['roots'], *(manifest['controls'] if controls else [])]:
            flags += ['-C', f'link-arg=--undefined={root}']
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    env.pop('RUSTFLAGS', None)
    env['CARGO_TARGET_DIR'] = str(output / 'build' / name)
    env['ZIG_GLOBAL_CACHE_DIR'] = str(OUT / 'zig-cache')
    command = ['cargo', 'build']
    if name in ('x86','arm-linux'):
        if capture(['zig', 'version']).strip() != '0.16.0':
            raise RuntimeError('cross-linking baseline uses Zig 0.16.0')
        if capture(['cargo-zigbuild', '--version']).strip() != 'cargo-zigbuild 0.23.0':
            raise RuntimeError('cross-linking baseline uses cargo-zigbuild 0.23.0')
        command = ['cargo', 'zigbuild']
    command += ['--manifest-path', str(AUDIT/'Cargo.toml'), '--locked', '--bin', 'ct_audit',
                '--profile', profile, '--target', target, '--no-default-features']
    if features:
        command += ['--features', features]
    subprocess.run(command, env=env, check=True)
    linked = Path(env['CARGO_TARGET_DIR']) / target / profile / 'ct_audit'
    binary = dest/'ct_audit'
    if name in ('x86','arm-linux'):
        # Zig's bundled CRT/libunwind DWARF ignores rustc's path remaps. Keep the
        # symbol table for taint stacks, but exclude host-specific debug metadata.
        subprocess.run([bindir/'llvm-objcopy', '--strip-debug', '--keep-section=.debug_gdb_scripts', linked, binary], check=True)
        def allocated(path):
            listing = json.loads(capture([bindir/'llvm-readobj', '--elf-output-style=JSON', '--sections', path]))
            sections = [s['Section'] for s in listing[0]['Sections']
                        if any(flag['Name'] == 'SHF_ALLOC' for flag in s['Section']['Flags']['Flags'])]
            names = [s['Name']['Name'] for s in sections]
            metadata = [(s['Name']['Name'], s['Address'], s['Size'], s['Flags']['Value']) for s in sections]
            dump = capture([bindir/'llvm-objdump', '-s', *[f'--section={s}' for s in names], path])
            return metadata, '\n'.join(line for line in dump.splitlines() if 'file format' not in line)
        if allocated(linked) != allocated(binary):
            raise RuntimeError('debug stripping changed allocated image contents')
    else:
        shutil.copy2(linked, binary)
    if name == 'darwin':
        # Mach-O's linker adds absolute OSO object paths independently of Rust DWARF.
        subprocess.run([bindir/'llvm-objcopy', '--strip-debug', linked, binary], check=True)
        def section_contents(path):
            dump = capture([bindir/'llvm-objdump', '-s', path])
            return '\n'.join(line for line in dump.splitlines() if 'file format' not in line)
        if section_contents(linked) != section_contents(binary):
            raise RuntimeError('debug stripping changed Mach-O section contents')
    check_host_paths(binary, remaps)
    dis = capture([bindir/'llvm-objdump', '-d', '--demangle', '--no-show-raw-insn', binary])
    symbols = capture([bindir/'llvm-nm', '-n', '--demangle', binary])
    (dest/'code.dis').write_text(dis)
    (dest/'symbols.txt').write_text(symbols)
    stubs, relocs = {}, {}
    if name == 'darwin':
        listing = capture(['otool', '-Iv', binary])
        (dest/'stubs.txt').write_text(listing)
        for line in listing.splitlines():
            m = re.match(r'^0x([0-9a-f]+)\s+\d+\s+(\S+)', line)
            if m: stubs[int(m[1],16)] = m[2]
    elif arch == 'x86_64':
        listing = capture([bindir/'llvm-readobj', '--relocations', '--expand-relocs', binary])
        (dest/'relocations.txt').write_text(listing)
        for block in re.findall(r'Relocation \{(.*?)\}', listing, re.S):
            address = re.search(r'Offset: (0x[0-9A-Fa-f]+)',block)
            addend = re.search(r'Addend: (0x[0-9A-Fa-f]+)',block)
            symbol = re.search(r'Symbol: (.+?) \(',block)
            if address and 'R_X86_64_RELATIVE ' in block and addend:
                relocs[int(address[1],16)] = int(addend[1],16)
            elif address and symbol and ('R_X86_64_GLOB_DAT ' in block or 'R_X86_64_JUMP_SLOT ' in block):
                relocs[int(address[1],16)] = symbol[1]
    report = analyzer.analyze(dis, symbols, arch, manifest['roots'], stubs, relocs)
    config = {'target': target, 'cpu': cpu, 'profile': profile, 'features': features,
              'opt_level': 's' if profile == 'firmware' else '3', 'lto': profile == 'firmware',
              'codegen_units':1, 'panic':'abort', 'relocation_model':'static' if name in ('x86','arm-linux') else 'target-default',
              'rustc':'\n'.join(line for line in rustc.splitlines() if not line.startswith(('host:', 'binary:'))),
              'objdump':capture([bindir/'llvm-objdump','--version']).splitlines()[0],
              'cross_linker': 'cargo-zigbuild 0.23.0 / Zig 0.16.0' if name in ('x86','arm-linux') else 'rustc target default',
              'path_remap_policy':'v1: home=/build-home, Cargo home=/cargo, checkout=/audit, Zig cache=/zig-cache; lexical and canonical spellings, most-specific last; reject remaining host prefixes',
              'debug_metadata':'Linux: strip-debug, keep .debug_gdb_scripts, compare allocated sections; Darwin: strip-debug, compare section contents; RV32: retain remapped DWARF. Symbol tables retained on all targets.',
              'source_sha256':analyzer.digest({str(p.relative_to(REPO)):sha(p) for base in ('secp256kfun/src','arithmetic_macros/src') for p in sorted((REPO/base).rglob('*.rs'))}),
              'harness_sha256':analyzer.digest({p.name:sha(p) for p in sorted((AUDIT/'src').glob('*.rs'))}),
              'analyzer_sha256':sha(Path(analyzer.__file__)),
              'build_driver_sha256':sha(Path(__file__)),
              'inventory_checker_sha256':sha(Path(inventory.__file__)),
              'manifests_sha256':analyzer.digest({str(p):sha(REPO/p) for p in map(Path, ('Cargo.toml','secp256kfun/Cargo.toml','arithmetic_macros/Cargo.toml','secp256kfun/ct-audit/Cargo.toml'))}),
              'lock_sha256':sha(AUDIT/'Cargo.lock'), 'contracts_sha256':sha(AUDIT/'contracts.json')}
    pins = {**config, 'rustc_full':rustc,
            'binary_sha256':sha(binary), 'linked_sha256':sha(linked), 'binary_size':binary.stat().st_size,
            'command':command, 'flags':flags,
            'base_vendor_tree':capture(['git','rev-parse','HEAD:secp256kfun/src/vendor']).strip()}
    (dest/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
    (dest/'analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    snapshot = {'config':config, 'roots':report['roots'],
                'functions':{n:{**{k:f[k] for k in ('code_sha256','edges','excluded_leaves','unresolved')},
                                'branch_offsets':[b['offset'] for b in f['branches']],
                                'memory_access_count':len(f['memory'])} for n,f in report['functions'].items()}}
    (dest/'snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
    print(name, json.dumps(report['summary']))
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=[*CONFIGS, 'coverage'])
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--controls', action='store_true', help='separate audit-only negative-control build; never a production baseline')
    parser.add_argument('--record', action='store_true', help='prepare a candidate baseline for review; never approves evidence')
    args = parser.parse_args()
    if args.platform == 'coverage':
        coverage(); print('contract/trait/root coverage matches'); return
    assert not (args.check and args.record)
    assert not (args.controls and (args.check or args.record))
    snapshot = build(args.platform, OUT/'controls' if args.controls else OUT, controls=args.controls)
    baseline = AUDIT/'baselines'/f'{args.platform}.json'
    if args.record:
        baseline.parent.mkdir(parents=True,exist_ok=True)
        baseline.write_text(json.dumps(snapshot,indent=2)+'\n')
        print('Candidate baseline written; classification record and peer review still required.')
    elif args.check:
        if not baseline.exists() or json.loads(baseline.read_text()) != snapshot:
            raise SystemExit('RE-AUDIT REQUIRED: configuration or reachable machine code changed; see target/ct-audit artifacts')
        print('No drift from the reviewed snapshot. This is not a CT proof.')

if __name__ == '__main__':
    main()
