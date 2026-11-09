"""Check the restricted audit-wrapper signatures against their secrecy inventory."""
import re


def split_types(text):
    parts, start, depth = [], 0, 0
    for i, char in enumerate(text):
        if char in '<[':
            depth += 1
        elif char in '>]':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
        assert depth >= 0, 'unbalanced signature'
    assert depth == 0, 'unbalanced signature'
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def classify(ty, aliases, seen=()):
    ty = re.sub(r'\s+', '', ty).removeprefix('&').removeprefix('mut')
    if ty in aliases:
        assert ty not in seen, 'recursive type alias'
        return classify(aliases[ty], aliases, (*seen, ty))
    if ty.startswith('[') and ty.endswith(']'):
        return classify(ty[1:-1].split(';')[0], aliases, seen)
    if ty == 'bool':
        return 'secret-predicate'
    if ty == 'u8':
        return 'public-data'
    match = re.fullmatch(r'(Scalar|Point)<(.+)>', ty)
    assert match, f'unsupported or implicit audit input type: {ty}'
    args = split_types(match[2])
    if match[1] == 'Scalar':
        assert len(args) == 2 and args[1] in ('Zero', 'NonZero'), ty
        secrecy = args[0]
        kind = 'scalar'
    else:
        assert len(args) == 3 and args[0] in ('Normal', 'NonNormal') and args[2] in ('Zero', 'NonZero'), ty
        secrecy = args[1]
        kind = 'point'
    assert secrecy in ('Secret', 'Public'), ty
    return f'{secrecy.lower()}-{kind}'


def signatures(source, aliases, prefix):
    result = {}
    for match in re.finditer(r'pub fn (' + prefix + r'\w+)\(([^)]*)\)', source):
        assert match[1] not in result, f'duplicate wrapper: {match[1]}'
        args = {}
        for arg in split_types(match[2]):
            name, ty = arg.split(':', 1)
            name = name.removeprefix('mut ').strip()
            assert re.fullmatch(r'\w+', name), name
            args[name] = classify(ty, aliases)
        result[match[1]] = args
    return result


def validate(manifest, sources):
    aliases = dict(re.findall(r'pub type (\w+)\s*=\s*([^;]+);', sources['lib.rs']))
    production = '\n'.join(sources.values())
    roots = signatures(production, aliases, 'audit_')
    declarations = re.findall(r'pub\s+(?:(?:unsafe|async|const)\s+|extern(?:\s+"[^"]*")?\s+)*fn\s+(audit_\w+)\b', production)
    assert len(declarations) == len(roots) and set(declarations) == set(roots), 'unsupported, duplicate or generic audit wrapper'
    controls = signatures(sources['controls.rs'], aliases, 'ct_control_')
    assert set(roots) == set(manifest['roots']) == set(manifest['functions']), 'function inventory differs'
    assert set(controls) == set(manifest['controls']) == {'ct_control_branch', 'ct_control_address'}
    for actual, entries in [(roots, manifest['functions']), (controls, manifest['controls'])]:
        for name, args in actual.items():
            entry = entries[name]
            assert entry['arguments'] == args, f'secret/public argument classification changed: {name}'
            assert type(entry['secret_scalar']) is bool
            assert entry['secret_scalar'] == ('secret-scalar' in args.values()), f'secret-scalar label differs: {name}'
            assert entry['preconditions'] and entry['coverage'], f'missing scope: {name}'
    assert re.search(r'#\[cfg\(feature = "negative-controls"\)\]\s*pub mod controls;', sources['lib.rs'])
    assert 'ct_control_' not in sources['lib.rs'], 'controls must stay in the feature-gated module'
    assert [f['case'] for f in manifest['fixtures']] == list(range(12))
    assert 'for case in 0..12 {' in sources['taint.rs']
    return roots
