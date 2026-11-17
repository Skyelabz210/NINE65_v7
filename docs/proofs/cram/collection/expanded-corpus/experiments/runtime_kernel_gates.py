from pathlib import Path
import subprocess, os, json

base = Path(__file__).resolve().parent.parent
env = os.environ.copy()
env.update(CARGO_HOME='/workspace/.tooling/cargo', RUSTUP_HOME='/workspace/.tooling/rustup', CARGO_TARGET_DIR=str(base/'build-runtime/nine65'), CARGO_BUILD_JOBS='2', PATH='/workspace/.tooling/cargo/bin:'+env['PATH'])
results=[]
for kernel in ['rank_residue_divider','recumbent','exact_scale_round','compare_bit']:
    cmd=['cargo','test','--locked','-p','nine65','--lib','--release','--no-fail-fast','arithmetic::'+kernel+'::','--','--nocapture']
    log=base/'experiments'/('runtime_'+kernel+'.log')
    with log.open('w') as f:
        r=subprocess.run(cmd,cwd='/workspace/NINE65_v7',env=env,stdout=f,stderr=subprocess.STDOUT)
    results.append(dict(kernel=kernel,command=cmd,exit_code=r.returncode,log=str(log)))
    print(kernel,r.returncode,flush=True)
(base/'experiments/runtime_kernel_gates.json').write_text(json.dumps(results,indent=2)+'\n')
