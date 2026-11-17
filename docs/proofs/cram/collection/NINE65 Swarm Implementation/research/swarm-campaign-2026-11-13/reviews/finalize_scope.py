"""Record immutable inputs actually reviewed and check cited author manifests."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
CAMPAIGN=HERE.parent
MAIN=CAMPAIGN.parents[1]
RESIDUE=Path('/workspace/NINE65-swarm-residue')
GCD=Path('/workspace/NINE65-swarm-gcd')
LEAN=Path('/workspace/k-elimination-swarm-proof')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
checked=[]
for root,manifest in [(RESIDUE,RESIDUE/'research/swarm-campaign-2026-11-13/runtime-residue/adapter-tests.json'),(GCD,GCD/'research/swarm-campaign-2026-11-13/runtime-gcd/evidence/verification.json')]:
 d=json.loads(manifest.read_text())
 for path,expected in d['source_sha256'].items():
  p=root/path;assert sha(p)==expected,p
  checked.append({'path':str(p),'sha256':expected,'review_kind':'implementation and contract review; author execution evidence checked'})
 if root==GCD:
  for run in d['commands']:
   p=manifest.parent.parent/run['log'];assert sha(p)==run['log_sha256'],p
for name in ['FutureQuotient.lean','AnchorValuations.lean','ReflectionInvariant.lean']:
 p=CAMPAIGN/'proofs'/name;checked.append({'path':str(p),'sha256':sha(p),'review_kind':'complete new statements and proof bodies; independent fresh build'})
p=LEAN/'KElimination/AnchorSaturation.lean';checked.append({'path':str(p),'sha256':sha(p),'review_kind':'complete13 statements and proof bodies; author build and axiom evidence checked'})
original_manifest=CAMPAIGN/'proofs/original-repository/verification.json'
d=json.loads(original_manifest.read_text())
for row in d['files']:assert sha(LEAN/row['file'])==row['sha256'],row['file']
for row in d['theorems']:assert set(row['axioms']) <= {'Classical.choice','propext','Quot.sound'}
assert len(d['theorems'])==223
for row in json.loads((CAMPAIGN/'proofs/integration-provenance.json').read_text())['modules']:
 name=row['module']+'.lean';a=(CAMPAIGN/'proofs'/name).read_text();b=(LEAN/'KElimination/UniversalResearch'/name).read_text()
 assert b.replace('import KElimination.UniversalResearch.','import ')==a,name
for rel in ['discovery/models.py','discovery/REPORT.md','discovery/candidates.jsonl','discovery/discoverygraph.json','discovery/sources.json','registry/SOURCE_COVERAGE.md','registry/sources.jsonl','registry/lineage.json']:
 p=CAMPAIGN/rel;checked.append({'path':str(p),'sha256':sha(p),'review_kind':'mathematical/API/source-scope review; actual models independently exercised where identified'})
for rel in ['rational_pair_reference.py','README.md']:
 p=GCD/'research/swarm-campaign-2026-11-13/runtime-gcd'/rel;checked.append({'path':str(p),'sha256':sha(p),'review_kind':'reference semantics and reported scope review'})
evidence={p.name:sha(p) for p in HERE.iterdir() if p.is_file() and p.name not in {'reviewer_scope.json','finalize_scope.py'}}
report={
 'status':'ACCEPTED_WITH_DECLARED_RESEARCH_SCOPE',
 'date':'2026-11-13','reviewer':'campaign_review','implementation_authors_reviewed':['campaign_residue','campaign_gcd','campaign_formal','campaign_discovery','campaign_corpus'],
 'blocking_findings':[],
 'independent_executions':{'fresh_std_modules':17,'fresh_std_axiom_reports':180,'new_proof_bodies_reviewed':49,'actual_residue_api_output_checks':136020,'fixed_euclid_dag_pairs':94548,'direct_table_dag_pairs':900,'module_certificate_cases':432,'decoded_vectors':2954,'kernel_collision_certificates':198,'geometry_triples':729,'bbs_configurations':1023,'rational_interpolation_points':50187,'jet_instances_including_composites':1100,'source_byte_hash_checks':150},
 'author_executions_reviewed':{'integrated_lean_declarations':223,'new_std_declarations':36,'new_nat_anchor_declarations':13,'current_residue_core_tests':29,'serial_adapter_tests':3,'accelerated_adapter_tests':3,'current_gcd_tests':7,'current_clear_circuit_tests':5,'native_direct_gcd_two_bit_cases':3,'native_direct_gcd_output_coefficient_checks':49152,'native_fixed_gcd_one_bit_output_coefficient_checks':16384,'private_feedback_tests':1},
 'reviewed_sources':checked,
 'reviewer_evidence_sha256':evidence,
 'remaining_boundaries':[
  'No whole-system security or confidentiality conclusion; native arithmetic tuples are not a new security admission.',
  'No source-level Rust/Python refinement proof; formal recurrence semantics and runtime contracts remain separate.',
  'Clear repeated-subtraction division is variable-time and publicly budgeted; global O(1) arithmetic is not established.',
  'Direct GCD tables are capped at4bits and have exponential public compilation size; fixed Euclid supports1..8bits subject to history-dependent noise admission.',
  'BBS result is nearest-neighbor continuous-space path intertwining with boundary/tail obligations, not a PDE continuum limit.',
  'Jet/value observations still require authentic producers and vanishing/unit/range certificates.',
  'Discovery231-pair screen is capability triage; no exhaustive novelty or whole-corpus verification claim.',
  'Original Mathlib build was author-executed; reviewer independently rebuilt Std package and checked final original source hashes/axioms.',
  'Preserved full-suite GCD exploration contains a known failed admission assumption; later current GCD/circuit tests pass, legacy division pass evidence retains its chronological scope.',
  'Linked chat unavailable and inherited scoped source reads remain explicit unfinished intake scopes.'
 ],
 'finalizer_sha256':sha(Path(__file__))
}
(HERE/'reviewer_scope.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'reviewed_source_files':len(checked),'reviewer_evidence_files':len(evidence),'blocking_findings':0,'scope_sha256':sha(HERE/'reviewer_scope.json')},indent=2))
