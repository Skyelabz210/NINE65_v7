#!/usr/bin/env python3
"""Rebuild the bounded corpus registry from pinned intake manifests and fetched snapshots.

Reads original attachments only to recheck hashes. Does not extract, execute, publish,
or interpret archive instructions. Private Drive body text stays outside this worktree.
"""
from __future__ import annotations
import collections
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDIT = Path('/workspace/k-elimination-audit')
ATTACH = Path('/tmp/codex-remote-attachments/6af5c3b0-2710-8191-9704-01ce7a1da0d5')
DATE = '2026-11-13'
RESEARCH_PIN = 'd883d24e6a1462c78564e554f42b3dd54044da59'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def dump(name, data):
    (HERE / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')

def read(path):
    return json.loads(Path(path).read_text())

def check(path, expected):
    p = Path(path)
    if not p.is_file():
        return {'status': 'SOURCE_UNAVAILABLE', 'checked_path': str(p)}
    got = digest(p.read_bytes())
    return {'status': 'MATCH' if got == expected else 'MISMATCH',
            'checked_path': str(p), 'actual_sha256': got}

def table_dispositions(path):
    lines = Path(path).read_text().splitlines()
    rows = []
    for line in lines:
        if not line.startswith('| ') or line.startswith('| Attachment') or line.startswith('| #'):
            continue
        cells = [x.strip() for x in line.strip('|').split('|')]
        if cells and (cells[0].split(' ', 1)[0].isdigit()):
            rows.append(cells)
    return rows

def main():
    manifest_paths = [AUDIT / 'evidence/input-manifest.json',
                      AUDIT / 'expanded-corpus/input-manifest.json',
                      AUDIT / 'expanded-corpus/extraction-manifest.json']
    original, expanded, extraction = [read(p) for p in manifest_paths]
    assert len(original) == 20 and len(expanded) == 22 and len(extraction) == 108
    prior_rows = table_dispositions(AUDIT / 'evidence/coverage.md')
    expanded_rows = table_dispositions(AUDIT / 'expanded-corpus/COVERAGE.md')
    assert len(prior_rows) == 20 and len(expanded_rows) == 22
    records = []
    hash_to_ids = collections.defaultdict(list)
    for cohort, values, covrows in [('original', original, prior_rows), ('expanded', expanded, expanded_rows)]:
        for index, item in enumerate(values, 1):
            source_id = f'upload-{cohort}-{index:02d}'
            if cohort == 'original':
                path = ATTACH / ('FA672DFF-C893-4FB1-82FA-D1DFC6697AD7/1-Untitled.docx' if index == 20 else 'BA795CAC-BB90-4DA1-BF73-BB00814FC7D8/' + item['name'])
                scope = covrows[index-1][1]
                disposition = covrows[index-1][2]
                coverage_record = str(AUDIT / 'evidence/coverage.md')
            else:
                path = Path(item['path'])
                scope = covrows[index-1][2]
                disposition = scope
                coverage_record = str(AUDIT / 'expanded-corpus/COVERAGE.md')
            suffix = path.suffix.lower()
            record = {
                'source_id': source_id, 'source_type': 'uploaded_top_level',
                'cohort': cohort, 'cohort_index': index, 'name': item['name'],
                'revision': None, 'sha256': item['sha256'], 'hash_kind': 'original_file_bytes',
                'bytes': item['bytes'], 'source_path': str(path),
                'status': 'INHERITED_REVIEW_WITH_FRESH_HASH_RECHECK',
                'coverage': {'read_scope': scope, 'read_date': '2026-11-12',
                             're_read_this_campaign': False, 'coverage_record': coverage_record,
                             'disposition': disposition},
                'extraction': {'previous_text_path': item.get('extracted'),
                               'formula_visual_audit': 'NOT_PAGE_BY_PAGE' if suffix == '.pdf' else 'NOT_APPLICABLE_OR_PRIOR_SCOPED_REVIEW'},
                'hash_check': check(path, item['sha256']),
                'verification_scope': 'Prior scoped evidence only; reading a claim does not independently verify its theorem, benchmark, or cited implementation.',
            }
            records.append(record)
            hash_to_ids[item['sha256']].append(source_id)
    for rec in records:
        rec['same_bytes_as'] = [x for x in hash_to_ids[rec['sha256']] if x != rec['source_id']]
    for index, item in enumerate(extraction, 1):
        source_path = item['source']
        parents = [r['source_id'] for r in records if r['source_type'] == 'uploaded_top_level'
                   and (r['source_path'] == source_path or r['name'] == item.get('parent_archive'))]
        if not parents:
            parents = [r['source_id'] for r in records if r['source_type'] == 'uploaded_top_level' and r['sha256'] == item['sha256']]
        records.append({
            'source_id': f'extract-expanded-{index:03d}', 'source_type': 'extracted_artifact',
            'parent_source_ids': parents, 'revision': None, 'sha256': item['sha256'],
            'hash_kind': 'extracted_member_or_original_bytes_not_normalized_text',
            'source_path': source_path, 'bytes': item['bytes'], 'status': item['status'],
            'coverage': {'read_date': item.get('review_date'), 're_read_this_campaign': False,
                         'coverage_record': str(AUDIT / item.get('coverage_record', 'expanded-corpus/COVERAGE.md')),
                         'read_scope': 'Inherited full extracted text or identical prior read' if item['status'].startswith('READ_FULL') else 'Inventoried; scoped production-code/resource inspection only; not all display/demo text read'},
            'extraction': {k: v for k, v in item.items() if k not in {'sha256', 'bytes', 'source', 'status'}},
            'hash_check': check(source_path, item['sha256']),
            'verification_scope': 'Retains the previous manifest disposition; no new theorem or execution result is inferred.',
        })
    snapshot = read(HERE / 'corpus_github_snapshot.json')
    readings = read(HERE / 'corpus_github_readings.json')['readings']
    repos = snapshot['repositories']
    for repo in repos:
        records.append({
            'source_id': repo['source_id'], 'source_type': 'repository',
            'repository_full_name': repo['repository_full_name'], 'revision': repo['revision'],
            'sha256': None, 'git_tree_sha': repo['tree_sha'], 'status': 'METADATA_AND_COMPLETE_TREE_FETCHED_SCOPED_SOURCE_READ',
            'url': 'https://github.com/' + repo['repository_full_name'],
            'coverage': {'default_branch': repo['default_branch'], 'tree_entries': repo['tree_entries'],
                         'tree_truncated': repo['truncated'], 'whole_repository_line_review': False,
                         'fresh_read_source_ids': [r['source_id'] for r in readings if r['repo_source_id'] == repo['source_id']]},
            'extraction': {'method': 'GitHub plugin metadata, branch, recursive Git tree and file-line reads', 'snapshot': 'corpus_github_snapshot.json'},
            'verification_scope': 'No repository-wide build/test/security/priority acceptance is implied.',
        })
    for item in readings:
        r = {k: v for k, v in item.items() if k != 'content'}
        r.update({
            'source_type': 'repository_source_excerpt',
            'sha256': digest(item['content'].encode()), 'hash_kind': 'returned_utf8_excerpt',
            'status': 'READ_RETURNED_LINE_RANGE',
            'coverage': {'read_date': DATE, 'read_ranges': [[item['requested_range'][0], item['requested_range'][0] + item['actual_returned_lines'] - 1]],
                         'whole_file_returned': item['actual_returned_lines'] < item['requested_range'][1] - item['requested_range'][0] + 1},
            'extraction': {'method': 'GitHub plugin UTF-8 line range', 'snapshot': 'corpus_github_readings.json'},
            'verification_scope': 'Source inspection; no fresh compilation or benchmark by this corpus track.',
        })
        records.append(r)
    private_path = AUDIT / 'private-campaign-sources/corpus_drive_fetches.json'
    if private_path.exists():
        private = read(private_path)['sources']
        drive_meta = []
        for item in private:
            r = {k: v for k, v in item.items() if k != 'content'}
            r['sha256'] = digest(item['content'].encode())
            r['hash_kind'] = 'connector_returned_utf8_text_not_original_binary'
            drive_meta.append(r)
        dump('corpus_drive_metadata.json', {'captured_at': DATE, 'sources': drive_meta})
    else:
        drive_meta = read(HERE / 'corpus_drive_metadata.json')['sources']
    for item in drive_meta:
        r = dict(item)
        r.update({
            'source_type': 'private_drive_document', 'revision': {'modifiedTime': item['modifiedTime'], 'text_snapshot_sha256': item['sha256']},
            'status': 'READ_SCOPED_CONNECTOR_TEXT',
            'coverage': {'read_date': DATE, 'read_ranges': item['read_ranges'],
                         'total_returned_lines': item['total_returned_lines'],
                         'complete_text_read': item['read_ranges'] == [[1, item['total_returned_lines']]]},
            'extraction': {'method': 'Google Drive plugin readable-text fetch', 'visual_math_verified': False,
                           'raw_content_bundled': False, 'private_raw_cache': str(private_path)},
            'verification_scope': 'Private primary source claim/scope evidence, not a fresh theorem, benchmark, or external code execution.',
        })
        records.append(r)
    leads = [
        ('cramsept2', '12GQ2rmQUi7v5vj3qMmTZeifmORs16nuRrRyEbwpOxHg', 'Cramsept2'),
        ('cram-rigor', '1CdJjpv1jrWNSXAmVVJay8vQCBGN-Y5INyd2F1ImtOfI', 'CRAM rigor'),
        ('shadow-v2', '1qgwyLjH_r4zuDn7Daatb96O-_bvB2gD7', 'T_SHADOW v2'),
        ('arrow-lift', '1J3LNtrfqsGkIPLm_D8SoFcpQuBCC4Tni8nHg_TKPY1A', 'ARROW_LIFT'),
        ('algebraic-spacetime', '1b6k3lfdG-9qRp050L8sCCbPWTgvSY4Aw', 'Algebraic Spacetime'),
        ('map-of-zero', '1INr7P788ra9mPD1xpcOivjxKXZqS-BrI', 'MAP_OF_ZERO'),
        ('curriculum', '1F53bT2-4ybVIPN0UkeYxQi7See0dwx9v', 'CRAM curriculum'),
        ('regenerative-memory', '18ExKBIL5CjYXTGjNIynxyeWYOT8noH8mPsf30qTa4O8', 'Regenerative Memory'),
    ]
    for key, drive_id, title in leads:
        records.append({'source_id': 'drive-lead-' + key, 'source_type': 'indexed_primary_lead',
                        'title': title, 'drive_id': drive_id, 'revision': None, 'sha256': None,
                        'status': 'INDEXED_NOT_FETCHED_THIS_CAMPAIGN',
                        'coverage': {'read_scope': 'Evidence-index reference only; document body not used as evidence in this track'},
                        'extraction': None,
                        'provenance': 'cram-verified-patterns/references/evidence-index.md'})
    records.append({'source_id': 'chat-6af548dd-c6d8-8191-90ed-c6d29cf470cb',
                    'source_type': 'referenced_codex_thread', 'revision': None, 'sha256': None,
                    'url': 'thread://6af548dd-c6d8-8191-90ed-c6d29cf470cb?hostId=cloud%3Aaccount',
                    'status': 'UNAVAILABLE_READ_THREAD_TOOL_NOT_EXPOSED',
                    'coverage': {'read_scope': 'No thread content read or relied on'},
                    'extraction': None})
    ids = [r['source_id'] for r in records]
    assert len(ids) == len(set(ids))
    source_id_set = set(ids)
    assert all(p in source_id_set for r in records for p in r.get('parent_source_ids', []))
    assert all(r['hash_check']['status'] == 'MATCH' for r in records if 'hash_check' in r)
    assert len([r for r in records if r['source_type'] == 'uploaded_top_level']) == 42
    assert len([r for r in records if r['source_type'] == 'extracted_artifact']) == 108
    assert all(not r['truncated'] for r in repos)
    (HERE / 'sources.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records))
    source_snapshot = {'captured_at': DATE, 'manifest_hashes': [{'path': str(p), 'sha256': digest(p.read_bytes())} for p in manifest_paths],
                       'original': original, 'expanded': expanded, 'extraction': extraction,
                       'coverage_hashes': [{'path': str(p), 'sha256': digest(p.read_bytes())} for p in [AUDIT / 'evidence/coverage.md', AUDIT / 'expanded-corpus/COVERAGE.md']]}
    dump('corpus_upload_manifest_snapshot.json', source_snapshot)
    lineage = {
        'schema_version': 1, 'captured_at': DATE, 'research_snapshot': RESEARCH_PIN,
        'purpose': 'Evidence lineage and reuse map, not a claim of complete Git genealogy or universal validation.',
        'repositories': [{k: v for k, v in r.items() if k != 'tree'} for r in repos],
        'read_source_ids': [r['source_id'] for r in readings],
        'edges': [
            {'from': 'repo-MANA-definitive', 'to': 'repo-MANA-pages', 'relation': 'IDENTICAL_GSO_SOURCE_BLOB',
             'git_blob_sha': '7bffb6db282f314730b29be5502bd4f2a0326769',
             'scope': 'The gso_fhe.rs module only; does not assert whole-repository identity.'},
            {'from': 'repo-NINE65-Rust-Guide', 'to': 'repo-MANA-definitive', 'relation': 'GSO_MECHANISM_COMPARISON',
             'scope': 'Guide explains noise tracking; source distinguishes changing tracking metadata from changing ciphertext.'},
            {'from': 'repo-NINE65-v5-proofstack', 'to': 'repo-NINE65_v7', 'relation': 'CANDIDATE_AHOP_INVARIANT_REUSE',
             'scope': 'Polynomial reflection identities can be generalized to commutative rings; source compilation/integration is a separate gate.'},
            {'from': 'repo-NINE65-v5', 'to': 'repo-NINE65_v7', 'relation': 'CANDIDATE_EXACT_RATIONAL_QUERY_REUSE',
             'scope': 'Numerator/denominator pair representation, quotient equivalence, explicit zero-denominator contract needed.'},
            {'from': 'repo-qmnf-lean-coq-security-proofs', 'to': 'repo-NINE65_v7', 'relation': 'CANDIDATE_STRUCTURED_QUERY_REUSE',
             'scope': 'WASSAN direct-coordinate and sparse-state queries; no arbitrary-data compression or complexity proof inferred.'},
            {'from': 'drive-nsproof', 'to': 'drive-blueprint', 'relation': 'LATER_EXPLICIT_SCOPE_NARROWING',
             'scope': 'April text claims continuum regularity; May blueprint explicitly marks arbitrary-data continuum regularity and named bridges OPEN.'},
        ],
        'mechanisms': [
            {'id': 'corpus-ahop-commring', 'source_id': 'github-NINE65-v5-proofstack-lean4_KElimination_KElimination_AHOP_Algebra_lean-1',
             'finding': 'Reflection k_i -> 2*sum(other k_j)-k_i is an involution and preserves Q=(sum k)^2-2*sum(k_j^2) over any commutative ring.',
             'argument': 'Write s=sum(other coordinates), a=k_i. Reflection a\u2032=2s-a gives a\u2032\u2032=a and Q(a\u2032)-Q(a)=0 by polynomial expansion. No inversion of 2 is used.',
             'scope': 'Written algebraic derivation, no fresh Lean build by corpus track; separate noncommutativity/hardness statements retain their own hypotheses.'},
            {'id': 'corpus-gso-state-separation', 'source_id': 'github-MANA-definitive-crates_nine65_src_ops_gso_fhe_rs-221',
             'finding': 'mul_public computes ciphertext result before the collapse branch; collapse updates swarm and noise metadata and does not replace that result.',
             'scope': 'Scoped wrapper observation only; symmetric mode and underlying multiplication require separate analysis. No public noise reset theorem follows.'},
            {'id': 'corpus-wassan-query', 'source_id': 'github-qmnf-lean-coq-security-proofs-lean4_formalization_swarm_18_WASSAN_lean-1',
             'finding': 'Amplitude state is a 144-coordinate function; direct retrieval is exact. The named constant-time theorem has conclusion True, not an operational cost bound.',
             'scope': 'Useful structured query representation; do not infer lossless arbitrary 144:1 compression or quantum hardware behavior.'},
            {'id': 'corpus-rational-policy', 'source_id': 'github-NINE65-v5-crates_exact_transcendentals_lean4_ExactTranscendentals_ExactRational_lean-1',
             'finding': 'Exact rational numerator/denominator pairs and cross-product equivalence are reusable; div\u2032 returns zero on a zero divisor numerator.',
             'scope': 'A totalized convention must be explicit or replaced by certified nonzero input before reuse as ordinary field division.'},
            {'id': 'corpus-energy-max-boundary', 'source_ids': ['drive-nsproof', 'drive-blueprint'],
             'finding': 'An exact quadratic-energy certificate does not by itself prove a maximum-norm bound. Retain the energy identity and require an independent stability bridge.',
             'counterexample': 'R=[[3/5,-4/5],[4/5,3/5]], x=(1,1), R*x=(-1/5,7/5). Squared Euclidean norm remains 2 while maximum norm grows from 1 to 7/5.',
             'scope': 'Exact rational counterexample to the implication, not a rejection of all discrete CRAM mechanisms or a rerun of the unavailable NS solver.'},
            {'id': 'corpus-synthesis-leads', 'source_ids': ['drive-synthesis', 'drive-frontiers', 'drive-register'],
             'finding': 'Recovered leads: heterogeneous per-lane operators and exceptional-set coupling; clean-window/resonance claims; QEC and wavelet correspondences; exact skew advection; auxiliary-lane FPD error scope.',
             'scope': 'Leads only. A scalar rho=min(moduli) is not automatically a code distance, operator spectral radius, stability constant or cryptographic entropy bound; definitions and concrete maps must be supplied.'},
        ],
        'gaps': ['Linked Codex thread content unavailable because read_thread is not exposed.',
                 'PDF text review is not page-by-page visual/OCR verification; rendered formulas that disagree with extraction remain unverified.',
                 'Only listed repository line ranges are freshly read; trees are not whole-repository acceptance.',
                 'Private Drive document bytes/images/equations were not downloaded or visually verified; hashes identify connector text snapshots.',
                 'Historical claims, proof labels, test totals and performance figures are not current executed results.',
                 'Current genealogy covers pinned sources and one proven identical blob, not a complete commit ancestry analysis.'],
    }
    dump('lineage.json', lineage)
    counts = dict(collections.Counter(r['source_type'] for r in records))
    dump('corpus_validation.json', {
        'captured_at': DATE, 'result': 'PASS', 'total_records': len(records), 'source_type_counts': counts,
        'unique_source_ids': len(set(ids)), 'top_level_original_count': 42, 'extracted_artifact_count': 108,
        'inherited_extraction_status_counts': dict(collections.Counter(x['status'] for x in extraction)),
        'original_and_extracted_hash_rechecks': dict(collections.Counter(r['hash_check']['status'] for r in records if 'hash_check' in r)),
        'complete_repository_trees': len(repos), 'fresh_repository_excerpt_reads': len(readings),
        'private_drive_scoped_reads': len(drive_meta), 'private_raw_bodies_in_repository': False,
        'raw_private_cache': str(private_path), 'sources_jsonl_sha256': digest((HERE / 'sources.jsonl').read_bytes()),
        'checks': ['42 top-level identities retained even for identical bytes', '108 extracted dispositions preserved',
                   'all 150 original/member byte hashes rechecked', 'unique source IDs', 'parent references resolve',
                   'all eight recursive trees have truncated=false', 'Git blob SHA distinguished from excerpt SHA-256',
                   'Drive text digest distinguished from original binary digest'],
    })
    print(json.dumps({'result': 'PASS', 'records': len(records), 'types': counts}, indent=2))

if __name__ == '__main__':
    main()
