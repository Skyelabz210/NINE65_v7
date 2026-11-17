"""Rebuild the explicit capability screen and twelve research candidate records.

The 231-pair screen is rule-based triage, not proof of 462 connections.
Manually curated mathematical fingerprints make every rule inspectable.
"""
from itertools import combinations
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parents[2]
INVENTORY=REPO/'research/universal-cross-pollination/INNOVATION_INVENTORY.md'

# Each entry: source semantic state, supplied capabilities, required capabilities,
# and the specific guard that prevents an unjustified composition.
FINGERPRINTS=[
 ('affine integer/ring coordinate', ['quotient_query','target_projection'], ['authentic_views','public_bounds'], 'Readout needs authentic same-source reference and sufficient query resolution; cheap readout excludes production.'),
 ('heterogeneous product state', ['operator_schema','lane_operations'], ['closure_certificate','source_identity'], 'Independent lane semantics need not represent one common integer operation.'),
 ('two declared representation frames', ['frame_transfer','target_projection'], ['quotient_query','authentic_views','public_bounds'], 'Current canonical helper may form a scalar rank aggregate; output correctness is not residue-native conformance.'),
 ('role-aware residue frame and successor', ['authentic_views','source_identity','public_bounds'], ['operator_schema'], 'Disambiguation is only as strong as the actual frame and source-epoch witness.'),
 ('encrypted word or bounded coefficient', ['division','remainder'], ['public_bounds','ring_kernel'], 'Word circuits and coefficient drops have different plaintext/source semantics and admission.'),
 ('bounded native secret phase chart', ['phase_query','source_identity','root_certificate'], ['polynomial_evaluation','public_bounds','encrypted_admission'], 'G/H is a nonlinear producer with local linear coordinate response; no general production-security consequence.'),
 ('indexed lane tasks', ['parallel_schedule','lane_operations'], ['public_plan'], 'A scheduling optimization must respect data dependencies and actual producer costs.'),
 ('prepared modular/NTT representation', ['ring_kernel','polynomial_evaluation'], ['representation_tag'], 'Montgomery, canonical and transform-domain values require distinct representation contracts.'),
 ('integer-scaled transcendental or rational pair', ['rational_arithmetic','approximation_model'], ['division','public_bounds'], 'Exact rational operations do not make their result an exact irrational number; rigorous enclosures remain separate.'),
 ('scaled integer plus signatures and provenance', ['result_signature','source_identity'], ['public_bounds','error_enclosure'], 'Finite residue agreement needs a strict difference bound to prove equality.'),
 ('integer weights or clear activation vector', ['conserved_total','integer_nonlinearity'], ['division','comparison'], 'Conservation does not prove approximation accuracy or ciphertext realization.'),
 ('negacyclic polynomial phase action', ['phase_action','linear_transition'], ['ring_kernel','representation_tag'], 'Coefficient parity projections are not arbitrary numerical sine/cosine without an embedding.'),
 ('finite modular trajectory or stencil', ['linear_transition','time_powering'], ['closure_certificate','ring_kernel','public_bounds'], 'Discrete congruence closure does not imply real-norm stability or a PDE limit.'),
 ('torus/centered theta chart', ['chart_query','theta_index'], ['quotient_query','chart_certificate','public_bounds'], 'Centered reference and wall policy matter; integer observations do not automatically observe real charts.'),
 ('finite carry Markov chain', ['stochastic_model','exact_probability'], ['probability_assumptions'], 'IID driving digits, detailed balance and invertible operations are separate properties.'),
 ('coefficient polynomial ring or positional bands', ['polynomial_state','polynomial_evaluation'], ['operator_schema','representation_tag'], 'Coefficient-ring addition is not positional integer addition with carries.'),
 ('public bound and modular clock phases', ['public_bounds','phase_clock'], ['quotient_query','source_identity'], 'Oriented phase and folded circular distance have different ambiguity.'),
 ('heuristic public candidate search', ['public_plan','candidate_search'], ['admission_certificate'], 'An improved model estimate is not an arithmetic or noise change.'),
 ('restricted amplitude/state family', ['restricted_state','gate_model'], ['closure_certificate'], 'Only a proved invariant gate family supports exact reduced evolution; arbitrary quantum compression is unestablished.'),
 ('signed bounded integer and MAA geometry', ['integer_oracle','linear_transition'], ['public_bounds'], 'Boundary oracle arithmetic is separate from the residue core; MAA word-size bounds still apply.'),
 ('deterministic stream and local lifecycle', ['lifecycle_policy','repeatable_stream'], ['source_identity'], 'Deterministic mixing and counters do not establish entropy, remote authenticity or anti-copying.'),
 ('bounded private-feedback aggregate', ['aggregate','ciphertext_addition'], ['public_bounds','parallel_schedule','source_identity'], 'Actual key ownership, ingestion semantics and deduplication remain explicit.'),
]

POTENTIAL=['owner_benefit','generalization_reach','portfolio_return','mechanism_distinctiveness','test_information_gain']
READINESS=['precise_statement','authentic_producer','mathematical_premises','implementation_seam','decisive_experiment']


def candidate(i,title,category,families,potential,readiness,status,forward,back,assumptions,
              mapping,claim,evidence,blockers,action,refs):
    return {'id':f'C{i:02d}','title':title,'category':category,'family_ids':[f'F{x:02d}' for x in families],
            'potential':dict(zip(POTENTIAL,potential)),'readiness':dict(zip(READINESS,readiness)),
            'potential_total':sum(potential),'readiness_total':sum(readiness),'status':status,
            'forward_impact':forward,'return_impact':back,'assumptions':assumptions,'mapping':mapping,
            'claim':claim,'evidence_refs':evidence,'source_refs':refs,'blockers':blockers,'next_action':action,
            'score_rationale':{
                'potential':{
                    'owner_benefit':back,
                    'generalization_reach':forward,
                    'portfolio_return':'Concrete family links: '+', '.join(f'F{x:02d}' for x in families)+'. '+back,
                    'mechanism_distinctiveness':mapping+' This scores the usefulness of the composition, not historical priority.',
                    'test_information_gain':'Decisive claim: '+claim+' Existing evidence: '+', '.join(evidence)},
                'readiness':{
                    'precise_statement':claim,
                    'authentic_producer':'Producer obligations: '+' '.join(assumptions),
                    'mathematical_premises':'Premises are explicit: '+' '.join(assumptions)+' Written/model status: '+status,
                    'implementation_seam':'Evidence/attachment: '+', '.join(evidence)+'. Remaining: '+' '.join(blockers),
                    'decisive_experiment':'Next discriminating action: '+action}},
            'novelty_status':'No historical-priority conclusion; distinguish imported tool, new derived connection and concrete integration.'}


def candidates():
    return [
      candidate(1,'Source-bound consumer capabilities','practical_return',[1,3,4,7],
       [5,5,5,3,5],[5,4,4,4,5],'SPECIFIED',
       'Reusable exact observation interfaces for sensing and distributed computation.',
       'Safe transient query reuse and deterministic public scheduling in NINE65.',
       ['Producer owns source identity, epoch, frame and public bounds.','Actual readouts refer to the same semantic source.'],
       'B is the producer observation; C is QuerySpec; QueryPlan carries a constructor D with DB=C.',
       'Multiple consumers may share source observations without a persistent scalar winding.',
       ['../../universal-cross-pollination/lean/ConsumerTransport.lean'],
       ['Runtime source capability/refinement belongs to parallel implementation track.'],
       'Integrate and test source/frame/epoch negative cases on the authentic 36/37 path.', ['F01','F03','F04','F07']),
      candidate(2,'Composite-module query compiler with collision certificates','practical_return',[1,2,13],
       [5,5,5,4,5],[5,5,4,4,5],'TESTED',
       'Solve functional modular constraints even when the observation matrix is noninvertible.',
       'Return an executable weighted decoder or exact ambiguity witness to the public query planner.',
       ['m>0; public integer U,V are unimodular; UBV is diagonal.','Observed y is authentic Bx mod m.'],
       'z=V^-1 x, Uy=Sz, target t=CV; scalar condition gcd(Sjj,m)|tj.',
       'A linear target over Z/m is recoverable iff every diagonal gcd condition holds; failure supplies a kernel witness.',
       ['models.py#compile_integer_query','model-evidence.json#module_queries'],
       ['External normal-form construction not implemented; current verifier uses small cofactor determinants.','Rust/encrypted adapter not yet integrated.'],
       'Use a verified normal-form producer; formalize certificate verification and preserve explicit bit cost.', ['D02','F01','F02','F13']),
      candidate(3,'Residue-only exact geometric orientation','practical_return',[1,9,10],
       [5,4,5,3,5],[5,5,4,4,5],'TESTED',
       'Exact orientation predicates for integer geometry using a sign consumer.',
       'Reusable bounded sign/threshold consumer and capacity tests for Triad and planner.',
       ['All input coordinates in [-H,H].','Adjacent frame MA>16H^2; authentic coordinate views.'],
       'Compute determinant residues, shift by B=8H², compare quotient/remainder of D+B to public B.',
       'The sign can be emitted without reconstructing the full determinant.',
       ['models.py#orientation_from_views','model-evidence.json#geometry'],
       ['This is an integer research model, not encrypted geometry or a measured speedup.'],
       'Refine to actual core query interface and benchmark matched exact-predicate workloads.', ['D01','F01','F09','F10']),
      candidate(4,'Fixed-schedule GCD and rational normalization','practical_return',[5,9,22],
       [5,4,5,3,5],[5,4,4,4,4],'SPECIFIED',
       'Exact rational-pair workloads under encrypted or residue integer semantics.',
       'GCD, cross-cancellation and denominator normalization built from admitted division.',
       ['Unsigned w-bit input words; zero-divisor convention and masked terminal freeze.','2w public rounds; all actual gates admitted.'],
       'Euclidean transition (a,b)->(b,a mod b), freezing b=0; pair normalization divides by final gcd.',
       'A fixed public schedule suffices; runtime cost and encrypted admission remain separate.',
       ['../../universal-cross-pollination/ARITHMETIC_CRYPTO_CONNECTIONS.md'],
       ['Parallel encrypted-GCD worker owns implementation/evidence.'],
       'Link actual DAG and admitted ciphertext execution, then refine rational-pair consumer.', ['F05','F09','F22']),
      candidate(5,'Actual BBS evolution intertwines a continuum path transform','frontier_generalization',[1,13,14],
       [5,5,5,4,5],[5,5,4,4,5],'TESTED',
       'Exact continuous-path representation of finite nearest-neighbor BBS dynamics.',
       'A genuine evolution bridge for the tropical/continuum claim, with bounded residue carrier state.',
       ['H0=0 and increments ±1.','Empty left carrier; outgoing carrier retained or enough empty right tail.'],
       'BBS carrier W=M-H, next height 2M-H; E runningmax(H)=runningmax(EH).',
       'E(T_Z H)=T_R(EH) at every real spatial coordinate; no PDE scaling limit is asserted.',
       ['models.py#bbs_residue_step','model-evidence.json#bbs','REPORT.md#bbs'],
       ['Written general proof, not yet Lean checked.','Continuum PDE or infinite-path probability limits require extra hypotheses.'],
       'Formalize nearest-neighbor max/interpolation commutation and finite carrier refinement.', ['D04','F01','F13','F14']),
      candidate(6,'Hensel precision steps and G/H local corrections','frontier_generalization',[1,6,9],
       [4,5,5,3,4],[5,4,4,3,5],'TESTED',
       'Certified refinement of roots and local coordinates across prime-power precision.',
       'Explicit higher-precision obligations for G/H rather than assuming p² results persist at p³.',
       ['f(a)=0 mod p^e, e>=1; f\'(a) unit mod p.'],
       'Correction t=−(f(a)/p^e)f\'(a)^−1 mod p; a_new=a+p^e t.',
       'The next root class is unique inside the old class under the derivative-unit premise.',
       ['models.py#hensel_step','model-evidence.json#jets_and_hensel'],
       ['Protected polynomial producer and new error budget required for encrypted use.'],
       'Prove and cost a higher-precision local-coordinate adapter before modifying refresh.', ['D03','F01','F06','F09']),
      candidate(7,'Future-query minimal state for heterogeneous dynamics','frontier_generalization',[2,13,19],
       [5,5,5,4,5],[5,4,4,4,5],'SPECIFIED',
       'Exact state reduction for finite programs and restricted state/gate families.',
       'Prevent insufficient observation reuse; minimize public models before lane execution.',
       ['Declared queries and total admitted transitions; all finite operation words quantified.'],
       'x~y iff all future query results agree; invisible subgroup is intersection of ker(CF_w).',
       'The quotient is the coarsest transition-stable representation sufficient for the query family.',
       ['../../universal-cross-pollination/reference/future_query.py'],
       ['Parallel formal worker owns new Lean proof/finite algorithm refinement.','An arbitrary quantum gate need not preserve a restricted family.'],
       'Attach reviewed invariant-domain and transition certificates to concrete operator families.', ['F02','F13','F19']),
      candidate(8,'Hasse-jet observations recover quotient queries at shared roots','frontier_generalization',[1,6,16],
       [5,5,5,4,5],[5,4,4,3,5],'TESTED',
       'Polynomial/jet query recovery when value-only observation annihilates the multiplier.',
       'A concrete nonunit polynomial constructor and higher-order local-observer family for CRAM.',
       ['X=r+MK; M=(t-a)^nu U; U(a) is a unit.','Authentic order-nu jets plus lower-jet vanishing certificate.'],
       'Hasse coefficient of order nu in X-r equals U(a)K(a).',
       'One subtraction and unit multiplication on the supplied jets yields K(a), including nu>=characteristic.',
       ['models.py#jet_quotient_query','model-evidence.json#jets_and_hensel','REPORT.md#jets'],
       ['Jets must actually be produced; their cost can dominate the readout.','General module/jet Lean constructor remains to formalize.'],
       'Add Hasse product/vanishing lemmas and a concrete polynomial-ring producer.', ['D05','D03','F01','F06','F16']),
      candidate(9,'MAA reflection invariants support modular orbit folding','internal_composition',[13,20],
       [4,4,4,3,4],[5,5,4,4,5],'TESTED',
       'Exact modular orbit predicates for Apollonian-type integer reflection dynamics.',
       'Concrete invariant-preserving operator family for dynamic transduction and time folding.',
       ['Reflection changes ki to 2 sum(other k)−ki.','Observation kernel stable under selected reflections; word bounds checked.'],
       'Integer linear involution preserves Q=2 sum(ki²)−(sum ki)²; reduction commutes.',
       'Admitted modular predicates can evolve without emitting full curvatures.',
       ['model-evidence.json#internal_bridges'],
       ['Arbitrary observed subspaces are not automatically invariant.'],
       'Formalize selected reflection matrices and build a bounded orbit query adapter.', ['F13','F20']),
      candidate(10,'StarLift gives centered theta minimizer classes','internal_composition',[1,14,17],
       [5,4,5,3,5],[5,5,4,4,5],'TESTED',
       'Branch-index queries in rank-one tropical theta charts.',
       'A concrete negative-winding consumer with exact centered-reference and wall contracts.',
       ['Q>0, z=g+QK, |g|<Q/2 for unique index.','At walls retain both minima or a declared tie policy.'],
       'argmin_n(Qn²+2nz)=−K; adjacent defect from z and g yields −K mod(Q+1).',
       'The sign-reversed readout answers a real consumer; canonical floor winding may differ from centered-chart K.',
       ['model-evidence.json#internal_bridges'],
       ['Real-valued chart observations need a separate producer; integer finite model does not provide them.'],
       'Formalize minimizer inequality and endpoint tie theorem, then attach chart source binding.', ['F01','F14','F17']),
      candidate(11,'Separate energy invariants from coordinate bounds','internal_composition',[13,17,20],
       [5,4,5,3,5],[5,5,4,4,5],'CONDITIONAL',
       'Correct stability certificates for geometric and scientific-computing operators.',
       'Avoid invalid max-bound/noise conclusions while preserving exact quadratic-energy certificates.',
       ['Specified quadratic form, arithmetic domain and operator.','Coordinate bounds need an additional norm/monotonicity estimate.'],
       'R=[[3/5,−4/5],[4/5,3/5]] preserves norm² but sends (1,1) to (−1/5,7/5).',
       'Energy preservation does not imply nonincrease of maximum coordinate magnitude; repaired bound uses a proved norm relation.',
       ['model-evidence.json#internal_bridges'],
       ['General continuum NS regularity is not supplied by this finite invariant.'],
       'Feed exact quadratic bounds into public admission with the appropriate norm conversion.', ['drive-nsproof','drive-blueprint','F13','F17','F20']),
      candidate(12,'Conserved normalization becomes an aggregate invariant','internal_composition',[5,11,22],
       [4,4,5,3,4],[5,5,4,4,5],'TESTED',
       'Exact integer apportionment and conservative resource allocation.',
       'Shared total-mass certificate across neural references and private-feedback outputs.',
       ['Nonnegative weights with positive sum; nonnegative integer target total.','Selection policy explicitly specified.'],
       'Floor each ideal allocation; distribute deficit to largest exact fractional remainders.',
       'Total is exact and every allocation differs from its ideal by less than one.',
       ['model-evidence.json#internal_bridges'],
       ['Largest-remainder policy differs from current maximal-output repair.','Encrypted sorting/selection is an additional circuit.'],
       'Expose allocation policy explicitly and test a bounded application before encrypted lowering.', ['F05','F11','F22']),
    ]


def build():
    text=INVENTORY.read_text().split('## Inventory',1)[1].split('## Derived',1)[0]
    rows=re.findall(r'^\| \*\*(.*?)\*\* \| (.*)$',text,re.M)
    assert len(rows)==len(FINGERPRINTS)==22
    families=[]
    for i,((name,row),(state,supplies,needs,guard)) in enumerate(zip(rows,FINGERPRINTS),1):
        paths=[p.removeprefix('../../') for p in re.findall(r'\]\(([^)]+)\)',row)]
        for path in paths:
            assert (REPO/path).exists(),path
        families.append({'id':f'F{i:02d}','name':name,'semantic_state':state,
                         'supplies':supplies,'requires':needs,'composition_guard':guard,
                         'source_paths':paths,'coverage':'Inherited selected-source inventory; capability screen is new triage, not fresh full-source verification.'})
    records=candidates()
    pairs=[]
    for a,b in combinations(families,2):
        directions=[]
        for source,target in ((a,b),(b,a)):
            matches=sorted(set(source['supplies'])&set(target['requires']))
            directions.append({'from':source['id'],'to':target['id'],
                               'disposition':'STRUCTURAL_CANDIDATE' if matches else 'NO_DIRECT_CAPABILITY_MATCH',
                               'matched_capabilities':matches,
                               'mapping':f"Use {source['name']} to supply {', '.join(matches)} required by {target['name']}." if matches else
                               f"No declared capability supplied by {source['name']} directly discharges a listed requirement of {target['name']}; an intermediate construction is needed.",
                               'remaining_requirements':sorted(set(target['requires'])-set(matches)),
                               'obstruction_or_guard':source['composition_guard']+' '+target['composition_guard'],
                               'proof_status':'NOT_ESTABLISHED_BY_SCREEN'})
        pair_candidates=[c['id'] for c in records if a['id'] in c['family_ids'] and b['id'] in c['family_ids']]
        pairs.append({'families':[a['id'],b['id']],'directions':directions,'deep_candidate_ids':pair_candidates})
    assert len(pairs)==231 and sum(len(p['directions']) for p in pairs)==462
    graph={'source_base':'88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484',
           'research_baseline':'d883d24','scope':'All family-pair structural screens; twelve deeper candidate records, not 231 proved connections',
           'inventory_sha256':hashlib.sha256(INVENTORY.read_bytes()).hexdigest(),
           'families':families,'pairs':pairs,'candidate_ids':[c['id'] for c in records],
           'screen_summary':{'families':22,'unordered_pairs':231,'directed_screens':462,
                            'structural_candidates':sum(d['disposition']=='STRUCTURAL_CANDIDATE' for p in pairs for d in p['directions'])}}
    (ROOT/'discoverygraph.json').write_text(json.dumps(graph,indent=2)+'\n')
    (ROOT/'candidates.jsonl').write_text(''.join(json.dumps(c)+'\n' for c in records))
    usable=[
      {'id':'U01','method':'Verified integer normal-form multipliers','source_refs':['D02'],'consumer':'C02',
       'adaptation':'Validate public U,V and diagonal form, then compile scalar gcd equations into direct observation weights or a kernel witness.',
       'license_dependency':'Mathematical method imported; no external code copied and no dependency added.',
       'benefit':'Works with composite moduli and target queries even when full source recovery is impossible.',
       'status':'EXECUTABLE_CERTIFICATE_IMPORT','remaining':'Scalable normal-form construction and Rust refinement.'},
      {'id':'U02','method':'Predicate-driven exact arithmetic','source_refs':['D01'],'consumer':'C03',
       'adaptation':'Use determinant sign as the consumer, public determinant bounds and adjacent readout; do not adopt floating point in the residue core.',
       'license_dependency':'Only the predicate-first design principle is imported; implementation is integer-only original reference code.',
       'benefit':'Provides an outward exact-geometry demonstrator and a reusable sign consumer.',
       'status':'EXECUTED_MODEL','remaining':'Matched cost benchmark and integrated producer capabilities.'},
      {'id':'U03','method':'Hasse derivatives / multiplicity observations','source_refs':['D05'],'consumer':'C08',
       'adaptation':'Observe the first nonzero jet of a shared-root multiplier to recover its quotient evaluation.',
       'license_dependency':'Finite-field Taylor coefficient definition; no external code copied.',
       'benefit':'Avoids factorial collapse of ordinary higher derivatives in small characteristic.',
       'status':'EXECUTED_MODEL','remaining':'Formal polynomial/jet constructor and authenticated encrypted producer.'},
      {'id':'U04','method':'Pitman path representation of BBS','source_refs':['D04'],'consumer':'C05',
       'adaptation':'Combine exact carrier dynamics and the nearest-neighbor PL embedding with residue-only bounded carrier state.',
       'license_dependency':'Mathematical representation imported; no third-party implementation copied.',
       'benefit':'Upgrades a given-snapshot interpolation to an actual evolution intertwining theorem.',
       'status':'WRITTEN_PROOF_AND_EXECUTED_MODEL','remaining':'Lean interpolation and continuous-path development; no PDE limit established.'},
    ]
    (ROOT/'usable_now.jsonl').write_text(''.join(json.dumps(c)+'\n' for c in usable))
    print(json.dumps(graph['screen_summary'],indent=2))


if __name__=='__main__':build()
