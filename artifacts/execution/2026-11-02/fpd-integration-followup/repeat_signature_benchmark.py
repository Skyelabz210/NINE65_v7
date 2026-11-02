import concurrent.futures,json,os,pathlib,re,subprocess,sys
log_path=pathlib.Path(sys.argv[1])
label=sys.argv[2]
text=log_path.read_text()
binary=re.search(r'Running unittests .* \(([^)]+)\)',text).group(1)
name='entropy::crt_shadow::tests::test_benchmark_signature_overhead'
root=pathlib.Path('/workspace/NINE65_v7')
cpu=min(os.sched_getaffinity(0))
out=pathlib.Path('/workspace/work/encrypted-division')
def run(item):
    phase,index=item
    cmd=[str(root/binary),name,'--exact','--nocapture']
    if phase=='contended':
        cmd=['taskset','--cpu-list',str(cpu)]+cmd
    result=subprocess.run(cmd,cwd=root,text=True,capture_output=True)
    transcript=result.stdout+result.stderr
    (out/f'{label}-{phase}-{index:02}.log').write_text(transcript)
    return {'phase':phase,'index':index,'returncode':result.returncode,
            'reported_overhead':re.findall(r'(?:Overhead|Median overhead): ([^\n]+)',transcript),
            'cpu':cpu if phase=='contended' else None}
records=[run(('isolated',i)) for i in range(20)]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    records+=list(pool.map(run,[('contended',i) for i in range(40)]))
(out/f'{label}-summary.json').write_text(json.dumps(records,indent=2)+'\n')
for phase in ['isolated','contended']:
    group=[r for r in records if r['phase']==phase]
    print(phase,'runs=',len(group),'failures=',sum(r['returncode']!=0 for r in group),'overheads=',[r['reported_overhead'] for r in group])
