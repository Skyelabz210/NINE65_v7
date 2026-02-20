#!/usr/bin/env python3
"""
Float violation scanner for exact_transcendentals.

Scans all .rs source files for f32/f64 usage in production code.
Correctly skips:
  - Lines inside #[cfg(test)] module blocks
  - Individual #[cfg(test)] annotated functions (skips until closing brace at same indent)
  - Comment-only lines (// ...)

Exit code: 0 if clean, 1 if violations found.
"""

import re
import sys
from pathlib import Path

FLOAT_PAT = re.compile(r'\bf64\b|\bf32\b|as f64|as f32|: f64|: f32')
COMMENT_PAT = re.compile(r'^\s*//')
CFG_TEST_PAT = re.compile(r'#\[cfg\(test\)\]')


def scan_file(path: Path) -> list[str]:
    """Return list of violation descriptions for a single file."""
    violations = []
    lines = path.read_text().splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Check for #[cfg(test)]
        if CFG_TEST_PAT.search(stripped):
            # Look ahead: is the next non-empty, non-attribute line a `mod` or `fn`/`pub fn`/`impl`?
            j = i + 1
            while j < n and (lines[j].strip() == '' or lines[j].strip().startswith('#[')):
                j += 1

            if j < n:
                next_line = lines[j].strip()
                if next_line.startswith('mod ') or next_line.startswith('pub mod '):
                    # It's a test module — count braces from the mod line itself
                    brace_depth = lines[j].count('{') - lines[j].count('}')
                    i = j + 1
                    while i < n:
                        l = lines[i]
                        brace_depth += l.count('{') - l.count('}')
                        if brace_depth <= 0:
                            break
                        i += 1
                    i += 1
                    continue
                else:
                    # It's a #[cfg(test)] on a function/impl — skip that item
                    # Find the opening brace, then match it
                    i = j
                    brace_depth = 0
                    found_open = False
                    while i < n:
                        l = lines[i]
                        for ch in l:
                            if ch == '{':
                                brace_depth += 1
                                found_open = True
                            elif ch == '}':
                                brace_depth -= 1
                        if found_open and brace_depth <= 0:
                            break
                        i += 1
                    i += 1
                    continue
            else:
                i += 1
                continue

        # Skip comment lines
        if COMMENT_PAT.match(stripped):
            i += 1
            continue

        # Check for float patterns
        if FLOAT_PAT.search(line):
            violations.append(f'{path}:{i+1}: {stripped}')

        i += 1

    return violations


def main():
    src = Path('src')
    if not src.is_dir():
        print('ERROR: must run from project root (src/ not found)', file=sys.stderr)
        sys.exit(2)

    all_violations = []
    for rs_file in sorted(src.glob('*.rs')):
        all_violations.extend(scan_file(rs_file))

    if all_violations:
        print(f'FLOAT VIOLATIONS ({len(all_violations)}):')
        for v in all_violations:
            print(f'  {v}')
        sys.exit(1)
    else:
        count = len(list(src.glob('*.rs')))
        print(f'PASS: Zero float violations in {count} source files')
        sys.exit(0)


if __name__ == '__main__':
    main()
