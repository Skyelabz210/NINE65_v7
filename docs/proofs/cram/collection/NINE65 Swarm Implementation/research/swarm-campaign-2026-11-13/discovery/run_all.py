"""One-command discovery reproduction; no third-party dependencies."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
COMMANDS = [
    [sys.executable, 'run_models.py'],
    [sys.executable, '-m', 'unittest', '-v', 'test_models.py'],
    [sys.executable, 'build_registry.py'],
    [sys.executable, 'verify_discovery.py'],
]


def main():
    results = []
    for command in COMMANDS:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        results.append({'command':command,'exit_code':result.returncode,
                        'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:
            break
    source_hashes = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(ROOT.glob('*.py'))}
    report = {'status':'PASS' if len(results)==len(COMMANDS) and all(r['exit_code']==0 for r in results) else 'FAIL',
              'commands':results,'source_sha256':source_hashes,
              'scope':'Finite research models, API admission checks, and registry integrity; no production FHE execution.'}
    (ROOT/'execution-evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status':report['status'],'commands_executed':len(results),
                      'source_files_bound':len(source_hashes)}, indent=2))
    if report['status']!='PASS':
        print(results[-1]['stdout'])
        print(results[-1]['stderr'], file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
