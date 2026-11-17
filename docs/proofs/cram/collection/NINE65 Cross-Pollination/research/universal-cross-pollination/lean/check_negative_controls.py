#!/usr/bin/env python3
"""Ensure the fresh-build checker refuses four invalid proof artifacts."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', default='lean')
    args = parser.parse_args()
    executable = shutil.which(args.lean)
    if executable is None:
        raise RuntimeError('Lean is unavailable')
    source = (ROOT / 'ConsumerTransport.lean').read_text()
    mutations = {
        'admitted_proof': (source.replace(
            'exact Prod.ext (hf x y heq) (hs x y heq)', 'sorry', 1),
            'Admitted or unsafe declaration'),
        'custom_axiom': (source + '\naxiom untrustedFact : False\n',
                         'Custom assumed declaration'),
        'unproved_positive_halving': (source.replace(
            '¬ Stable (fun x : Nat => x % 2) (fun x => x / 2)',
            'Stable (fun x : Nat => x % 2) (fun x => x / 2)', 1),
            'Lean failed or warned'),
        'missing_axiom_audit': (source.replace(
            '#print axioms KElimination.ConsumerTransport.paired_queries_iff\n',
            '', 1), 'Every theorem needs one axiom query'),
    }
    records = []
    for name, (changed, expected) in mutations.items():
        assert changed != source
        with tempfile.TemporaryDirectory(prefix='cram-negative-') as directory:
            work = Path(directory)
            for source_file in [ROOT / 'check_proofs.py', ROOT / 'lean-toolchain', *ROOT.glob('*.lean')]:
                shutil.copy2(source_file, work / source_file.name)
            (work / 'ConsumerTransport.lean').write_text(changed)
            result = subprocess.run(
                ['python3', 'check_proofs.py', '--lean', str(Path(executable).absolute())],
                cwd=work, env=os.environ.copy(), text=True, capture_output=True)
            output = result.stdout + result.stderr
            if result.returncode == 0 or expected not in output:
                raise RuntimeError(f'Negative control failed: {name}\n{output}')
            records.append({'control': name, 'status': 'EXPECTED_REFUSAL',
                            'exit_code': result.returncode, 'reason': expected})
    report = {'status': 'PASS', 'controls': records,
              'scope': 'Build/audit rejection controls; no encrypted execution'}
    (ROOT / 'negative-controls.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
