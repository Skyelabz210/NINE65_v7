#!/usr/bin/env python3
"""Reject Rust floats in runtime code, respecting actual test-item boundaries."""
import argparse
from pathlib import Path
import re

from check_no_floats_benches_and_tests import code_only
from check_residue_native_architecture import production_lines

ROOT = Path(__file__).resolve().parents[1]
# Existing explicit offline/reporting exemptions; bins have their own gate.
EXEMPT = {'compiler.rs', 'comprehensive_benchmarks.rs'}
FLOAT = re.compile(
    r'\bf(?:32|64)\b|(?<![\w.])(?:'
    r'[0-9][0-9_]*\.[0-9][0-9_]*(?:[eE][+-]?[0-9][0-9_]*)?(?:f(?:32|64))?'
    r'|[0-9][0-9_]*[eE][+-]?[0-9][0-9_]*(?:f(?:32|64))?'
    r'|[0-9][0-9_]*f(?:32|64))(?![\w.])'
)


def violations(source):
    return [(line, text.strip()) for line, text in production_lines(code_only(source))
            if FLOAT.search(text)]


def self_test():
    long_test = '#[cfg(test)]\nmod tests {\n' + '\n' * 2300 + 'let x: f64 = 1.5;\n}\n'
    assert not violations(long_test)
    assert violations(long_test + 'fn runtime() { let x: f64 = 1.5; }')
    assert not violations('// f64 1.5\nfn f() { let s = "f64 1.5"; let x = a.0.1; for _ in 0..10 {} }')
    for literal in ('1.5', '1e3', '1.0e-3', '1f64', '1.5f32'):
        assert violations(f'fn f() {{ let x = {literal}; }}'), literal
    assert violations('#[cfg(any(test, feature = "research"))]\nfn f() { let x: f64 = 1.5; }')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
    root = ROOT / 'crates/nine65/src'
    files = [p for p in root.rglob('*.rs') if p.name not in EXEMPT
             and 'bin' not in p.relative_to(root).parts]
    if not files:
        raise SystemExit('missing runtime Rust source tree')
    failures = [(p, line, text) for p in files
                for line, text in violations(p.read_text())]
    for path, line, text in failures:
        print(f'{path.relative_to(ROOT)}:{line}: {text}')
    print(f'Runtime no-floats gate: {len(failures)} violations in {len(files)} files')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
