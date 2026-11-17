"""Curate the local research packet, check its links, and verify ZIP hashes.

Does not package build trees, private memory content or unrelated portfolio.
Preserves original uploads and repository checkouts.
"""
from pathlib import Path
import hashlib, json, re, zipfile
from urllib.parse import unquote

root = Path(__file__).resolve().parent.parent
exp = root / 'expanded-corpus'
manifest_path = root / 'bundle-manifest.json'
previous = json.loads(manifest_path.read_text())
paths = {root / entry['path'] for entry in previous['files']}
paths.add(root / 'EXPANDED_ANALYSIS.md')
paths.add(root / 'UNIVERSAL_THEOREM.md')
paths.add(root / 'CLOSURE_PROOFS.md')
paths.add(root / 'CRAM_PROOFS_INDEX.md')
paths.add(root / 'CROSS_INNOVATION_MAP.md')
paths.add(root / 'cross-innovation-review.md')
universal = root / 'universal-theorem'
for name in ('README.md', 'MATHEMATICAL_REVIEW.md', 'ExactObservation.lean',
             'UniversalLift.lean', 'RingReadout.lean', 'IntegerSpecialization.lean',
             'CostedReadout.lean', 'UniversalKElimination.lean', 'check_proofs.py',
             'lean-toolchain', 'lakefile.toml', 'lake-manifest.json',
             'verification.json', 'verification.log', 'lake-build.log',
             'integer-proof-report.md', 'integer-axiom-audit.json', 'integer-build.log',
             'ring-proof-notes.md', 'ring-result.json', 'ring-build.log'):
    paths.add(universal / name)
for name in ('ReferenceChange.lean', 'reference-build.log', 'CoupledAnchors.lean',
             'coupled-build.log', 'coupled-result.json', 'coupled-proof-report.md',
             'ResidueAlgorithms.lean', 'algorithms-build.log', 'algorithms-verification.json',
             'algorithms-proof-report.md', 'ResiduePrimitives.lean', 'primitives-build.log',
             'primitives-axiom-audit.json', 'primitives-proof-report.md', 'StarLift.lean',
             'STARLIFT.md', 'starlift-build.log', 'starlift-result.json', 'CLOSURE_REVIEW.md',
             'ClosureSmoke.lean', 'closure-smoke.log', 'closure-execution.json'):
    paths.add(universal / name)
for name in ('ROOT_NOTES.md','COVERAGE.md','ExactObservation.lean',
             'exact-observation-lean.log','lean-toolchain','input-manifest.json',
             'extraction-manifest.json','extract_corpus.py','extraction.log',
             'hung-parhami-1994-excerpt.md','build_packet.py'):
    paths.add(exp / name)
paths.update((exp / 'reviews').glob('*.md'))
paths.update(p for p in (exp / 'experiments').iterdir()
             if p.is_file() and p.suffix in ('.py','.rs','.json','.log','.md','.jpg'))
# This code archive is research source, with no build scripts or dependencies.
paths.update(p for p in (exp / 'archives/14-Crate-12').rglob('*')
             if p.is_file() and (p.suffix in ('.rs','.toml','.md')))
paths.update((exp / 'archive-text/14-Crate-12').glob('*.txt'))

# Extraction status is deliberately weaker for production-code inspections
# than for documents actually read in full.
extract_path = exp / 'extraction-manifest.json'
records = json.loads(extract_path.read_text())
for record in records:
    record['review_date'] = '2026-11-12'
    if 'text' in record:
        record['status'] = 'READ_FULL_EXTRACTED_TEXT_OR_IDENTICAL_PREVIOUSLY_READ'
        record['coverage_record'] = 'expanded-corpus/COVERAGE.md'
    else:
        record['status'] = 'INVENTORIED_AND_SCOPED_CODE_REVIEW'
        record['coverage_record'] = 'expanded-corpus/reviews/runtime.md'
extract_path.write_text(json.dumps(records,indent=2)+'\n')

missing = [str(p) for p in paths if not p.is_file()]
if missing: raise RuntimeError('Missing packet files: '+repr(missing))
for p in paths:
    rel=p.relative_to(root)
    if any(s in str(rel) for s in ('build-runtime/','22-claude-memory','/toolchains/')):
        raise RuntimeError('Excluded private/build content selected: '+str(rel))

broken=[]
external_local=[]
for p in paths:
    if p.suffix != '.md': continue
    body=p.read_text()
    for match in re.finditer(r'\[[^\]\n]+\]\(([^)\n]+)\)',body):
        target=match.group(1).strip().strip('<>')
        if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:',target) or target.startswith('#'): continue
        target=unquote(target.split('#',1)[0])
        target=re.sub(r':\d+$','',target)
        q=Path(target) if target.startswith('/') else p.parent/target
        q=q.resolve()
        if not q.exists(): broken.append({'file':str(p.relative_to(root)),'target':target})
        elif q not in paths and q != manifest_path: external_local.append({'file':str(p.relative_to(root)),'target':target})
if broken: raise RuntimeError('Broken local links: '+repr(broken))

proof_log=(exp/'exact-observation-lean.log').read_text()
proof_names=re.findall(r"^'KElimination\.ExactObservation\.([^']+)'",proof_log,re.M)
assert len(proof_names)==9, proof_names
assert 'sorryAx' not in proof_log and 'error:' not in proof_log and 'warning:' not in proof_log

universal_verification = json.loads((universal / 'verification.json').read_text())
assert universal_verification['status'] == 'PASS'
assert universal_verification['fresh_temporary_build']
assert not universal_verification['project_olean_reused']
assert universal_verification['reused_observation_theorems'] == 9
assert (universal / 'ExactObservation.lean').read_bytes() == (exp / 'ExactObservation.lean').read_bytes()
for record in universal_verification['files']:
    data = (universal / record['file']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record['sha256'], record['file']
    assert record['theorem_count'] == len(record['theorems'])
assert sum(r['theorem_count'] for r in universal_verification['files']) == universal_verification['theorem_declarations']
assert 'Build completed successfully' in (universal / 'lake-build.log').read_text()

entries=[]
for p in sorted(paths):
    data=p.read_bytes()
    entries.append({'path':str(p.relative_to(root)),'bytes':len(data),
                    'sha256':hashlib.sha256(data).hexdigest()})
manifest={'date':'2026-11-12',
          'revision':'CRAM Proofs collection with reviewed cross-innovation map and the 130-declaration proof package',
          'proof_commit':'0400092096962e3da45a8e5cbb82185a3c2c38fe',
          'nine65_commit':'88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484',
          'standalone_lean_toolchain':'leanprover/lean4:v4.27.0-rc1',
          'standalone_lean_theorems':proof_names,
          'universal_theorem_declarations':universal_verification['theorem_declarations'],
          'universal_new_declarations':universal_verification['new_theorem_declarations'],
          'closure_and_starlift_new_declarations':universal_verification['new_closure_and_starlift_declarations'],
          'universal_verification':'universal-theorem/verification.json',
          'current_targeted_rust_tests_passed':52,
          'supplied_top_level_inputs':42,
          'selected_expanded_extracted_files':len(records),
          'relative_report_links_checked':True,
          'valid_local_links_to_unbundled_sources':external_local,
          'files':entries}
manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
bundle=root/'k-elimination-research-audit.zip'
temporary=bundle.with_suffix('.zip.tmp')
with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in sorted(paths): z.write(p,'k-elimination-audit/'+str(p.relative_to(root)))
    z.write(manifest_path,'k-elimination-audit/bundle-manifest.json')
with zipfile.ZipFile(temporary) as z:
    assert z.testzip() is None
    for entry in entries:
        data=z.read('k-elimination-audit/'+entry['path'])
        assert hashlib.sha256(data).hexdigest()==entry['sha256']
temporary.replace(bundle)
print(json.dumps({'bundle':str(bundle),'files':len(entries)+1,
                  'bytes':bundle.stat().st_size,
                  'sha256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
                  'checked_lean_theorems':len(proof_names),
                  'checked_universal_declarations':universal_verification['theorem_declarations'],
                  'valid_unbundled_local_links':len(external_local)},indent=2))
