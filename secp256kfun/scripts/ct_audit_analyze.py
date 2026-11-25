#!/usr/bin/env python3
"""Machine-code inventory, not a taint engine or a constant-time proof.

Extends the arith-backend audit's transitive traversal to three architectures,
including tail/conditional transfers, symbol aliases, stores and latency candidates.
All unresolved transfers remain part of the report and drift fingerprint.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

LEAVES = (
    '__rust_alloc', '__rust_dealloc', '__rust_realloc', '__rust_alloc_zeroed',
    'alloc::alloc::handle_alloc_error', 'alloc::raw_vec::handle_error', 'core::panicking::',
    'core::option::expect_failed', 'core::result::unwrap_failed',
    'core::slice::index::slice_index_fail',
)
A64_COND = {'cbz', 'cbnz', 'tbz', 'tbnz'}
RV_COND = {'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu', 'beqz', 'bnez',
           'blez', 'bgez', 'bltz', 'bgtz', 'bgt', 'ble', 'bgtu', 'bleu'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def clean_name(name):
    return re.sub(r'::h[0-9a-f]{16}\b', '', name).removeprefix('_')


def parse(disassembly, symbols):
    functions = {}
    current = None
    for line in disassembly.splitlines():
        m = re.match(r'^([0-9a-fA-F]+) <(.+)>:$', line.strip())
        if m:
            current = int(m[1], 16)
            functions[current] = {'name': clean_name(m[2]), 'instructions': []}
            continue
        m = re.match(r'^\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*)$', line)
        if m and current is not None:
            functions[current]['instructions'].append((int(m[1], 16), m[2], m[3]))
    aliases = {}
    for line in symbols.splitlines():
        m = re.match(r'^([0-9a-fA-F]+)\s+[TtWw]\s+(.+)$', line)
        if m:
            aliases[clean_name(m[2])] = int(m[1], 16)
    if not functions:
        raise ValueError('no disassembled functions: unexpected objdump format')
    return functions, aliases


def conditional(op, arch):
    if arch == 'aarch64':
        return op in A64_COND or op.startswith('b.')
    if arch == 'x86_64':
        return (op.startswith('j') and op not in ('jmp', 'jmpq')) or op.startswith('loop')
    return op.removeprefix('c.') in RV_COND


def transfer(op, arch):
    if conditional(op, arch):
        return True
    return op in {
        'aarch64': {'b', 'bl', 'br', 'blr', 'braa', 'brab', 'blraa', 'blrab'},
        'x86_64': {'call', 'callq', 'jmp', 'jmpq'},
        'riscv32': {'j', 'jal', 'jalr', 'jr', 'call', 'tail', 'c.j', 'c.jal', 'c.jr', 'c.jalr'},
    }[arch]


def memory(op, args, arch):
    if arch == 'aarch64':
        return '[' in args and op.startswith(('ld', 'st', 'cas', 'swp'))
    if arch == 'x86_64':
        return ('(' in args and op not in ('lea', 'leaq', 'leal')) or op.startswith(('push', 'pop', 'stos', 'movs', 'cmps', 'scas'))
    return '(' in args and op.removeprefix('c.') in {
        'lb', 'lbu', 'lh', 'lhu', 'lw', 'lwu', 'ld', 'sb', 'sh', 'sw', 'sd',
        'flw', 'fld', 'fsw', 'fsd', 'lwsp', 'swsp', 'ldsp', 'sdsp'}


def latency(op):
    return any(part in op for part in ('div', 'rem', 'mul')) or op in ('madd', 'msub', 'umaddl', 'smaddl')


def analyze(disassembly, symbols, arch, roots, stubs=None, relocations=None):
    stubs = stubs or {}
    relocations = relocations or {}
    funcs, aliases = parse(disassembly, symbols)
    starts = sorted(funcs)
    import bisect

    def owner(address):
        i = bisect.bisect_right(starts, address) - 1
        if i < 0:
            return None
        start = starts[i]
        ins = funcs[start]['instructions']
        return start if ins and address <= ins[-1][0] else None

    def destination(ins, i):
        addr, op, args = ins[i]
        if arch == 'x86_64' and '*' in args:
            slot = re.search(r'# 0x([0-9a-f]+)', args)
            if slot:
                return relocations.get(int(slot[1], 16))
        m = re.search(r'(?:^|[\s,])0x([0-9a-fA-F]+)\s*(?:<|$)', args)
        if m and not (arch == 'x86_64' and '*' in args):
            return int(m[1], 16)
        # Linked RISC-V calls may retain AUIPC/JALR instead of relaxing to JAL.
        if arch == 'riscv32' and op in ('jalr', 'jr') and i:
            previous, prev_op, prev_args = ins[i - 1]
            a = re.match(r'(\w+),\s*(0x[0-9a-f]+|\d+)', prev_args)
            b = re.search(r'(-?(?:0x[0-9a-f]+|\d+))\((\w+)\)', args)
            if prev_op == 'auipc' and a and re.fullmatch(a[1] + r'(?: <.*>)?', args):
                return (previous + (int(a[2], 0) << 12)) & 0xffffffff
            if prev_op == 'auipc' and a and b and a[1] == b[2]:
                return (previous + (int(a[2], 0) << 12) + int(b[1], 0)) & 0xffffffff
        return None

    reached = {}
    details = {}
    missing = [r for r in roots if r not in aliases or aliases[r] not in funcs]
    if missing:
        raise ValueError(f'missing audit roots: {missing}')
    for root in roots:
        stack, seen = [aliases[root]], set()
        while stack:
            f = stack.pop()
            if f in seen:
                continue
            seen.add(f)
            if f not in details:
                info = funcs[f]
                ins = info['instructions']
                branches, accesses, slow, unresolved, edges, excluded = [], [], [], [], [], []
                normalized = []
                definitions = {}
                for i, (address, op, args) in enumerate(ins):
                    if op in ('<unknown>', '.word', '.long', '.inst', '.byte', '.short', '.2byte', '.4byte'):
                        raise ValueError(f'undecoded instruction in {info["name"]}: {address:x} {op} {args}')
                    text = f'{op} {args}'.strip()
                    record = {'offset': address - f, 'instruction': text}
                    if conditional(op, arch):
                        branches.append({**record, 'context': [f'{o} {a}' for _, o, a in ins[max(0, i-3):i]]})
                    if memory(op, args, arch):
                        address_text = ' '.join(re.findall(r'\[([^]]+)\]|\(([^)]+)\)', args)[0]) if re.search(r'[\[(]', args) else 'implicit stack/string address'
                        regs = re.findall(r'%?[a-z]+[0-9]*', address_text)
                        accesses.append({**record, 'address':address_text,
                            'linear_definitions':{reg:definitions.get(reg, 'argument, implicit register, or loop-carried value; inspect CFG') for reg in regs}})
                    if arch == 'x86_64':
                        dest = re.search(r'(?:^|,\s*)(%[a-z0-9]+)\s*(?:#.*)?$',args)
                        writes = not op.startswith(('cmp','test','j','call','push'))
                    else:
                        dest = re.match(r'([a-z][a-z0-9]*)(?:,|$)',args)
                        writes = not (transfer(op,arch) or op.startswith(('st','cmp','tst','ret')) or op in ('sb','sh','sw','sd','fsw','fsd'))
                    if dest and writes:
                        definitions[dest[1]] = text
                    if latency(op):
                        slow.append(record)
                    if transfer(op, arch):
                        target = destination(ins, i)
                        own = owner(target) if isinstance(target, int) else None
                        if isinstance(target, str):
                            excluded.append('external:' + target)
                        elif target in stubs:
                            excluded.append('external:' + stubs[target])
                        elif own is not None and funcs[own]['name'] in ('_stubs', '.plt', '.plt.got'):
                            unresolved.append({**record, 'reason': 'unresolved external stub'})
                        elif own is None:
                            unresolved.append(record)
                        elif own != f:
                            name = funcs[own]['name']
                            if any(part in name for part in LEAVES):
                                excluded.append(name)
                            else:
                                edges.append(own)
                    # Only control-transfer addresses are normalized. Other immediates,
                    # including PC-relative data locations, must trigger review on drift.
                    norm = text
                    if transfer(op, arch):
                        target = destination(ins, i)
                        own = owner(target) if isinstance(target, int) else None
                        if own is not None:
                            norm = re.sub(r'0x[0-9a-fA-F]+(?:\s*<.*>)?', f'@{funcs[own]["name"]}+{target-own}', norm)
                    normalized.append(re.sub(r'::h[0-9a-f]{16}\b', '', norm))
                details[f] = {
                    'name': info['name'], 'instructions': len(ins), 'code_sha256': digest(normalized),
                    'branches': branches, 'memory': accesses, 'latency_candidates': slow,
                    'unresolved': unresolved, 'edges': sorted(set(edges)), 'excluded_leaves': sorted(set(excluded)),
                }
            stack.extend(details[f]['edges'])
        reached[root] = sorted(seen)
    def label(f):
        return funcs[f]['name']
    names = [label(f) for f in details]
    if len(names) != len(set(names)):
        raise ValueError('distinct reached functions have the same normalized name; preserve their identities before review')
    output = {'schema': 1, 'architecture': arch,
              'roots': {r: [label(f) for f in reached[r]] for r in roots},
              'functions': {label(f): {**d, 'edges': [label(t) for t in d['edges']]} for f, d in sorted(details.items())}}
    output['summary'] = {key: sum(len(d[key]) for d in details.values()) for key in ('branches', 'memory', 'latency_candidates', 'unresolved')}
    output['summary']['functions'] = len(details)
    return output


def parse_relocations(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == 'R_X86_64_RELATIVE':
            result[int(fields[0], 16)] = int(fields[3], 16)
        elif len(fields) >= 5 and fields[2] in ('R_X86_64_GLOB_DAT', 'R_X86_64_JUMP_SLOT'):
            result[int(fields[0], 16)] = fields[4]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disassembly', type=Path)
    parser.add_argument('symbols', type=Path)
    parser.add_argument('--arch', choices=['aarch64', 'x86_64', 'riscv32'], required=True)
    parser.add_argument('--contracts', type=Path, default=Path(__file__).resolve().parents[1] / 'ct-audit/contracts.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--stubs', type=Path)
    parser.add_argument('--relocations', type=Path)
    args = parser.parse_args()
    stubs = {}
    if args.stubs:
        for line in args.stubs.read_text().splitlines():
            m = re.match(r'^0x([0-9a-f]+)\s+\d+\s+(\S+)', line)
            if m:
                stubs[int(m[1], 16)] = m[2]
    relocations = {}
    if args.relocations:
        relocations = parse_relocations(args.relocations.read_text())
    result = analyze(args.disassembly.read_text(), args.symbols.read_text(), args.arch, json.loads(args.contracts.read_text())['roots'], stubs, relocations)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['summary']))

if __name__ == '__main__':
    main()
