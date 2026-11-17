"""Validate coverage, source references, reproducibility and model hash binding."""
from collections import Counter
from contextlib import redirect_stdout
from itertools import combinations
from pathlib import Path
import hashlib
import io
import json

import build_registry

ROOT = Path(__file__).resolve().parent


def verify():
    generated = ['discoverygraph.json', 'candidates.jsonl', 'usable_now.jsonl']
    before = {name: (ROOT/name).read_bytes() for name in generated}
    with redirect_stdout(io.StringIO()):
        build_registry.build()
    assert all((ROOT/name).read_bytes() == value for name, value in before.items()), 'registry drift'
    graph = json.loads((ROOT/'discoverygraph.json').read_text())
    sources = json.loads((ROOT/'sources.json').read_text())
    candidates = [json.loads(x) for x in (ROOT/'candidates.jsonl').read_text().splitlines()]
    usable = [json.loads(x) for x in (ROOT/'usable_now.jsonl').read_text().splitlines()]
    evidence = json.loads((ROOT/'model-evidence.json').read_text())
    families = {f['id']: f for f in graph['families']}
    assert set(families) == {f'F{i:02d}' for i in range(1, 23)}
    assert {tuple(p['families']) for p in graph['pairs']} == set(combinations(sorted(families), 2))
    assert len(graph['pairs']) == 231
    direct = 0
    for pair in graph['pairs']:
        a,b = pair['families']
        assert len(pair['directions']) == 2
        assert {(d['from'],d['to']) for d in pair['directions']} == {(a,b),(b,a)}
        for direction in pair['directions']:
            src,dst = (families[direction[k]] for k in ('from','to'))
            expected = set(src['supplies']) & set(dst['requires'])
            assert set(direction['matched_capabilities']) == expected
            assert direction['proof_status'] == 'NOT_ESTABLISHED_BY_SCREEN'
            assert direction['mapping'] and direction['obstruction_or_guard']
            direct += bool(expected)
    assert direct == graph['screen_summary']['structural_candidates'] == 45
    assert {c['id'] for c in candidates} == {f'C{i:02d}' for i in range(1, 13)}
    assert Counter(c['category'] for c in candidates) == {
        'practical_return':4,'frontier_generalization':4,'internal_composition':4}
    source_ids = set(families) | {x['id'] for x in sources['sources']+sources['private_lineage']}
    for candidate in candidates:
        assert candidate['status'] in {'SPECIFIED','TESTED','CONDITIONAL'}
        for axis in ('potential','readiness'):
            scores = candidate[axis]
            assert len(scores) == 5 and all(type(s) is int and 0 <= s <= 5 for s in scores.values())
            assert sum(scores.values()) == candidate[axis+'_total']
        assert set(candidate['source_refs']) <= source_ids
        for ref in candidate['evidence_refs']:
            assert (ROOT/ref.split('#')[0]).exists(), ref
        for field in ('forward_impact','return_impact','assumptions','blockers','next_action'):
            assert candidate[field]
    for item in usable:
        assert set(item['source_refs']) <= source_ids
        assert item['consumer'] in {c['id'] for c in candidates}
    for name, digest in evidence['source_sha256'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest, name
    result = {'status':'PASS','families':22,'unordered_pairs':231,'directional_screens':462,
              'structural_matches_not_proofs':direct,'deep_candidates':12,
              'candidate_categories':dict(Counter(c['category'] for c in candidates)),
              'usable_imports':len(usable),'fetched_source_documents':len(sources['sources']),
              'model_hashes_verified':len(evidence['source_sha256']),
              'registry_regeneration':'byte-identical',
              'limits':'Checks registry integrity and evidence hash binding; run_models and unittest execute behavior.'}
    (ROOT/'discovery-validation.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    verify()
