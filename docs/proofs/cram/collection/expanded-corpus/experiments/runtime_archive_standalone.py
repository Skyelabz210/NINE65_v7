"""Run untouched archived standalone Rust tests, preserving individual results."""
from pathlib import Path
import os, subprocess, json

base = Path(__file__).resolve().parent.parent
archive = base / 'archives/14-Crate-12'
out = base / 'build-runtime/standalone'
out.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env.update(RUSTUP_HOME='/workspace/.tooling/rustup', CARGO_HOME='/workspace/.tooling/cargo')
rustc = '/workspace/.tooling/cargo/bin/rustc'
results = []
for name in ['band_add', 'fourth_attractor', 'fourth_attractor_fix']:
    binary = out / name
    cmd = [rustc, '--edition=2021', '--test', str(archive / (name + '.rs')), '-o', str(binary)]
    log = base / 'experiments' / ('runtime_archive_' + name + '.log')
    with log.open('w') as stream:
        compilation = subprocess.run(cmd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        execution = subprocess.run([str(binary)], env=env, stdout=stream, stderr=subprocess.STDOUT) if compilation.returncode == 0 else None
    results.append(dict(name=name, command=cmd, compile_exit=compilation.returncode, test_exit=execution.returncode if execution else None, log=str(log)))

# Include the standalone SPT and the exact companion modules without editing them.
for name, source in [('spt_flat',archive/'subproduct_tree.rs'), ('spt_nested', archive/'mnt/user-data/outputs/cram_subproduct/src/subproduct_tree.rs')]:
    harness=out/(name+'.rs')
    harness.write_text('\n'.join(f'#[path = "{p}"]\nmod {m};' for m,p in [('arith',archive/'arith.rs'),('garner',archive/'garner.rs'),('subproduct_tree',source)]))
    binary=out/name
    cmd=[rustc,'--edition=2021','--test',str(harness),'-o',str(binary)]
    log=base/'experiments'/('runtime_archive_'+name+'.log')
    with log.open('w') as stream:
        compilation=subprocess.run(cmd,env=env,stdout=stream,stderr=subprocess.STDOUT)
        execution=subprocess.run([str(binary)],env=env,stdout=stream,stderr=subprocess.STDOUT) if compilation.returncode==0 else None
    results.append(dict(name=name,command=cmd,compile_exit=compilation.returncode,test_exit=execution.returncode if execution else None,log=str(log)))

binary=out/'band_boundary'
cmd=[rustc,'--edition=2021',str(base/'experiments/runtime_archive_boundary.rs'),'-o',str(binary)]
with (base/'experiments/runtime_archive_boundary.log').open('w') as stream:
    compilation=subprocess.run(cmd,env=env,stdout=stream,stderr=subprocess.STDOUT)
    execution=subprocess.run([str(binary)],env=env,stdout=stream,stderr=subprocess.STDOUT) if compilation.returncode==0 else None
results.append(dict(name='band_boundary',command=cmd,compile_exit=compilation.returncode,test_exit=execution.returncode if execution else None))
(base/'experiments/runtime_archive_standalone.json').write_text(json.dumps(results,indent=2)+'\n')
for r in results: print(r['name'],r['compile_exit'],r['test_exit'])
