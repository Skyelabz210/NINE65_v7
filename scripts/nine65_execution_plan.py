#!/usr/bin/env python3
"""Read/validate the NINE65 task contracts; never execute a worker or mark acceptance."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / 'docs/execution/2026-10-03'


def load_plan():
    return json.loads((PLAN / 'tasks.json').read_text())


def check_graph(data):
    if data.get('schema') != 'nine65-execution-plan-v1':
        raise ValueError('unsupported plan schema')
    tasks = data.get('tasks', [])
    ids = [t['id'] for t in tasks]
    if not ids or len(ids) != len(set(ids)):
        raise ValueError('empty plan or duplicate task IDs')
    index = {t['id']: t for t in tasks}
    for t in tasks:
        if not re.fullmatch(r'[A-Z][0-9]{2}', t['id']):
            raise ValueError(f'invalid task ID: {t["id"]}')
        for field in ('title', 'kind', 'inputs', 'write_scope', 'steps',
                      'acceptance', 'checks', 'stop', 'review'):
            if not t.get(field):
                raise ValueError(f'{t["id"]}: missing {field}')
        for dep in t['depends_on']:
            if dep not in index:
                raise ValueError(f'{t["id"]}: unknown dependency {dep}')
        for name in t['inputs'] + t['write_scope']:
            p = Path(name)
            if p.is_absolute() or '..' in p.parts:
                raise ValueError(f'{t["id"]}: unsafe scoped path {name}')
    done, visiting = set(), set()

    def visit(id):
        if id in visiting:
            raise ValueError(f'cyclic dependency at {id}')
        if id in done:
            return
        visiting.add(id)
        for dep in index[id]['depends_on']:
            visit(dep)
        visiting.remove(id)
        done.add(id)

    for id in ids:
        visit(id)
    return index


def ready_tasks(index, accepted):
    unknown = accepted - index.keys()
    if unknown:
        raise ValueError('unknown accepted IDs: ' + ', '.join(sorted(unknown)))
    for id in accepted:
        missing = set(index[id]['depends_on']) - accepted
        if missing:
            raise ValueError(f'{id}: acceptance set is missing prerequisites {sorted(missing)}')
    return [t for id, t in index.items()
            if id not in accepted and set(t['depends_on']) <= accepted]


def packet(t):
    parts = [f'# {t["id"]}: {t["title"]}',
             f'Kind: {t["kind"]}. Required review: {t["review"]}.',
             'Dependencies: ' + (', '.join(t['depends_on']) or 'none') + '.',
             'Read docs/execution/2026-10-03/WORKER_GUIDE.md before acting. '
             'This task is planned, not accepted. Checks below are commands '
             'to execute after implementation, not reports of completed tests.',
             t['patch_policy']]
    for label, key in [('Read these inputs', 'inputs'),
                       ('Permitted write scope (includes proposed new paths)', 'write_scope'),
                       ('Implementation steps', 'steps'),
                       ('Acceptance criteria', 'acceptance')]:
        parts += [f'## {label}', '\n'.join(f'- {v}' for v in t[key])]
    parts += ['## Checks', '```sh\n' + '\n'.join(t['checks']) + '\n```',
              'Require a positive matching-test count for test commands. '
              'Navigation commands are not validation. Research/protocol '
              'acceptance additionally requires the stated derivation/review.',
              '## Stop condition', t['stop'], '## Issue correspondence',
              ', '.join(f'#{n}' for n in t['issues']) or 'New scoped implementation work.',
              '## Deliverable',
              'Reviewable diff plus result.json/logs following WORKER_GUIDE.md. '
              'Report blocked_design or blocked_infrastructure when appropriate. '
              'Do not weaken a gate or claim acceptance yourself.']
    return '\n\n'.join(parts) + '\n'


def check_inputs(index, exists):
    """A future input must be produced by an upstream task, not any task."""
    ancestors = {}

    def upstream(id):
        if id not in ancestors:
            deps = set(index[id]['depends_on'])
            ancestors[id] = deps | {a for dep in deps for a in upstream(dep)}
        return ancestors[id]

    for t in index.values():
        produced = {p for dep in upstream(t['id']) for p in index[dep]['write_scope']}
        for p in t['inputs']:
            if not exists(p) and p not in produced:
                raise ValueError(f'{t["id"]}: missing input with no upstream producer: {p}')


def validate_files(data, index, check_baseline=False):
    check_inputs(index, lambda p: (ROOT / p).exists())
    for t in index.values():
        card = PLAN / 'tasks' / f'{t["id"]}.md'
        if not card.exists() or card.read_text() != packet(t):
            raise ValueError(f'{t["id"]}: missing/stale card; run render')
    issues = json.loads((PLAN / 'open_issues.json').read_text())
    uncovered = {i['number'] for i in issues} - {n for t in index.values() for n in t['issues']}
    if uncovered:
        raise ValueError(f'baseline issues without a task: {sorted(uncovered)}')
    evidence = json.loads((PLAN / 'evidence.json').read_text())
    if evidence['v7_commit'] != data['base_commit']:
        raise ValueError('plan/evidence base commit mismatch')
    drift = []
    for p, expected in evidence['v7_source_sha256'].items():
        file = ROOT / p
        if not file.is_file():
            drift.append(p)
        elif hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            drift.append(p)
    if drift:
        message = ('Baseline drift: ' + ', '.join(drift)
                   + '; preserve original evidence and record a new run manifest')
        if check_baseline:
            raise ValueError(message)
        print(message)
    else:
        print(f'Baseline unchanged: {len(evidence["v7_source_sha256"])} source hashes checked')


def self_test(data):
    index = check_graph(data)
    if [t['id'] for t in ready_tasks(index, set())] != ['F00']:
        raise AssertionError('unexpected initial ready queue')
    cases = []
    bad = copy.deepcopy(data); bad['tasks'][0]['depends_on'] = ['V05']; cases.append(bad)
    bad = copy.deepcopy(data); bad['tasks'][0]['depends_on'] = ['Z99']; cases.append(bad)
    bad = copy.deepcopy(data); bad['tasks'].append(copy.deepcopy(bad['tasks'][0])); cases.append(bad)
    bad = copy.deepcopy(data); bad['tasks'][0]['write_scope'] = ['../../escape']; cases.append(bad)
    bad = copy.deepcopy(data); bad['tasks'][0]['acceptance'] = []; cases.append(bad)
    for bad in cases:
        try:
            check_graph(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid plan accepted')
    for accepted in ({'F01'}, {'Z99'}):
        try:
            ready_tasks(index, accepted)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid acceptance set accepted')
    if not {'F01', 'F02', 'F03'} <= {t['id'] for t in ready_tasks(index, {'F00'})}:
        raise AssertionError('prerequisite readiness failed')
    fixture = {
        'A00': {'id': 'A00', 'depends_on': [], 'inputs': [], 'write_scope': ['future']},
        'A01': {'id': 'A01', 'depends_on': ['A00'], 'inputs': ['future'], 'write_scope': []},
        'A02': {'id': 'A02', 'depends_on': ['A01'], 'inputs': ['future'], 'write_scope': []},
    }
    check_inputs(fixture, lambda p: False)
    for depends_on in ([], ['A01']):
        bad = copy.deepcopy(fixture)
        bad['A02']['depends_on'] = depends_on
        if depends_on:
            bad['A02']['inputs'] = ['self_produced']
            bad['A02']['write_scope'] = ['self_produced']
        try:
            check_inputs(bad, lambda p: False)
        except ValueError:
            pass
        else:
            raise AssertionError('missing upstream input accepted')
    print('Self-test: 12 dependency/schema/scope/input cases passed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    v = sub.add_parser('validate'); v.add_argument('--self-test', action='store_true')
    v.add_argument('--check-baseline', action='store_true',
                   help='also fail if the original source snapshot has changed')
    sub.add_parser('list')
    r = sub.add_parser('ready'); r.add_argument('--accepted', nargs='*', default=[])
    card = sub.add_parser('packet'); card.add_argument('id'); card.add_argument('--output', type=Path)
    sub.add_parser('render', help='regenerate task cards from tasks.json')
    args = p.parse_args()
    data = load_plan(); index = check_graph(data)
    if args.command == 'render':
        directory = PLAN / 'tasks'; directory.mkdir(exist_ok=True)
        for t in index.values():
            (directory / f'{t["id"]}.md').write_text(packet(t))
        print(f'Rendered {len(index)} task cards')
    elif args.command == 'validate':
        validate_files(data, index, args.check_baseline)
        if args.self_test:
            self_test(data)
        print(f'Plan valid: {len(index)} cards, acyclic dependencies, upstream inputs and issue coverage checked')
    elif args.command in ('list', 'ready'):
        selected = index.values() if args.command == 'list' else ready_tasks(index, set(args.accepted))
        for t in selected:
            print(f'{t["id"]:6} {t["kind"]:15} {t["title"]}')
        if args.command == 'ready':
            print('Dependency-ready only; acceptance requires evidence and independent review.')
    else:
        if args.id not in index:
            raise ValueError(f'unknown task: {args.id}')
        value = packet(index[args.id])
        if args.output:
            # An explicit output path is the only write outside rendered plan cards.
            with args.output.open('x') as handle:
                handle.write(value)
            print(args.output)
        else:
            print(value, end='')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
