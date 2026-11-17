"""Write the bounded runtime audit's reproducibility manifest; execute no tests."""
from pathlib import Path
from collections import defaultdict
import datetime
import hashlib
import json
import os
import re
import subprocess
import tomllib

base = Path(__file__).resolve().parent.parent
repo = Path('/workspace/NINE65_v7')
archive = base / 'archives/14-Crate-12'
env = os.environ.copy()
env.update(CARGO_HOME='/workspace/.tooling/cargo', RUSTUP_HOME='/workspace/.tooling/rustup')

def digest(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def command(argv, cwd=repo):
    return subprocess.check_output(argv, cwd=cwd, env=env, text=True).strip()

source_names = [
    'AGENTS.md', 'CLAUDE.md', 'Cargo.toml', 'Cargo.lock',
    'crates/nine65/Cargo.toml',
    'docs/ENCRYPTED_INTEGER_DIVISION_2026-11-02.md',
    'docs/FPD_DIVISION_SCOPE_2026-11-02.md',
    'docs/work_requests/WR1_EXACT_EVALUATOR_INTEGRATION.md',
    'crates/nine65/src/ops/cram_public.rs',
    'crates/nine65/src/ops/cram_main.rs',
    'crates/nine65/src/ops/cram_main_division.rs',
    'crates/nine65/src/ops/cram_main_division_tests.rs',
    'crates/nine65/src/ops/integer_division_circuit.rs',
    'crates/nine65/src/arithmetic/rank_residue_divider.rs',
    'crates/nine65/src/arithmetic/recumbent.rs',
    'crates/nine65/src/arithmetic/exact_scale_round.rs',
    'crates/nine65/src/arithmetic/main_only_base_ext.rs',
    'crates/nine65/src/arithmetic/compare_bit.rs',
    'crates/exact_transcendentals/src/crt.rs',
    'scripts/check_wr1_exact_route_denylist.py',
]
groups = defaultdict(list)
for path in sorted(archive.rglob('*')):
    if path.is_file() and (path.suffix == '.rs' or path.name == 'Cargo.toml'):
        item = digest(path)
        groups[item['sha256']].append(item)

artifacts = []
for path in sorted((base/'experiments').glob('runtime_*')):
    if not path.is_file() or path.name == 'runtime_manifest.json':
        continue
    item = digest(path)
    if path.suffix == '.log':
        item['test_summaries'] = re.findall(r'^test result: .+$', path.read_text(), re.M)
    artifacts.append(item)

staging_checks = []
for name in ['cram', 'cram_spt', 'cram_subproduct']:
    src = archive / 'mnt/user-data/outputs' / name
    dst = base / 'build-runtime/source-crates' / name
    for path in sorted(src.rglob('*')):
        if path.is_file() and (path.suffix == '.rs' or path.name == 'Cargo.toml'):
            target = dst / path.relative_to(src)
            staging_checks.append({'source': str(path), 'staged': str(target),
                                   'same_bytes': target.is_file() and path.read_bytes() == target.read_bytes()})
flat = base / 'build-runtime/source-crates/flat-layout'
for target in sorted(flat.rglob('*')):
    if target.is_file() and (target.suffix == '.rs' or target.name == 'Cargo.toml'):
        source = archive / target.name
        staging_checks.append({'source': str(source), 'staged': str(target),
                               'same_bytes': source.is_file() and target.read_bytes() == source.read_bytes()})

default_features = tomllib.loads((repo/'crates/nine65/Cargo.toml').read_text())['features']['default']
manifest = {
    'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'scope': 'Bounded current runtime and Crate-12 audit; not a full repository certification',
    'current_repository': {
        'path': str(repo), 'commit': command(['git', 'rev-parse', 'HEAD']),
        'status_after': command(['git', 'status', '--porcelain']),
        'rustc': command(['/workspace/.tooling/cargo/bin/rustc', '-Vv']),
        'cargo': command(['/workspace/.tooling/cargo/bin/cargo', '-V']),
        'test_profile': 'release lib unit tests, cfg(test), locked dependency graph',
        'features': {'selection': 'package defaults; no explicit --features or --no-default-features',
                     'default': default_features,
                     'explicitly_not_enabled': ['architecture-meter', 'allow_insecure', 'slow_tests', 'reference_ntt', 'parallel', 'generic-rayon']},
        'test_environment': {
            'CARGO_HOME': env['CARGO_HOME'], 'RUSTUP_HOME': env['RUSTUP_HOME'],
            'CARGO_TARGET_DIR': str(base/'build-runtime/nine65'), 'CARGO_BUILD_JOBS': '2',
            'PATH_prefix': '/workspace/.tooling/cargo/bin'},
        'commands': [
            ['cargo','test','--locked','-p','nine65','--lib','--release','--no-fail-fast',f,'--','--nocapture']
            for f in ['cram_main::division::', 'arithmetic::rank_residue_divider::',
                      'arithmetic::recumbent::', 'arithmetic::exact_scale_round::',
                      'arithmetic::compare_bit::']],
        'targeted_test_count': 52, 'failures': 0, 'ignored': 0,
        'initial_zero_match_filter_retained_not_counted': 'ops::cram_main::division::',
        'source_gate': {'command': ['python3','scripts/check_wr1_exact_route_denylist.py'],
                        'selftest_command': ['python3','scripts/check_wr1_exact_route_denylist.py','--self-test'],
                        'route_sources': 4, 'production_lines': 2762,
                        'patterns': 19, 'violations': 0, 'negative_controls': 16},
        'native_refresh': 'Not rerun; parent audit has separate historical/current refresh evidence',
    },
    'current_source_hashes': [digest(repo/name) for name in source_names],
    'archive': {
        'path': str(archive),
        'source_variants': [{'sha256': h, 'bytes': items[0]['bytes'],
                             'paths': [i['path'] for i in items]}
                            for h,items in sorted(groups.items())],
        'unique_source_contents': len(groups),
        'unique_source_bytes': sum(items[0]['bytes'] for items in groups.values()),
        'staging_integrity_checks': staging_checks,
        'execution_result_files': ['runtime_archive_results.json','runtime_archive_flat_layout.json','runtime_archive_standalone.json'],
        'additional_counterexample': {
            'source': 'runtime_archive_fhe_boundary.rs', 'log': 'runtime_archive_fhe_boundary.log',
            'compile_command': ['/workspace/.tooling/cargo/bin/rustc','--edition=2021',str(base/'experiments/runtime_archive_fhe_boundary.rs'),'-o',str(base/'build-runtime/archive-fhe-boundary')],
            'expected_observation': 'initial 1 plus five 1s produces 0 instead of 6 in archived clear simulator',
        },
    },
    'artifacts': artifacts,
    'review': digest(base/'reviews/runtime.md'),
}
(base/'experiments/runtime_manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(json.dumps({'commit':manifest['current_repository']['commit'],
                  'status':manifest['current_repository']['status_after'],
                  'unique_archive_variants':len(groups),
                  'staging_mismatches':[s for s in staging_checks if not s['same_bytes']],
                  'artifacts':len(artifacts)}, indent=2))
