"""Reviewer fresh build, isolated from author verification outputs."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT.parent/'proofs'
MODULES=['ExactObservation','UniversalLift','RingReadout','IntegerSpecialization','CostedReadout','ReferenceChange','CoupledAnchors','ResidueAlgorithms','ResiduePrimitives','StarLift','UniversalKElimination','ConsumerTransport','AllResearch','FutureQuotient','AnchorValuations','ReflectionInvariant','AllCampaign']
lean='/workspace/k-elimination-audit/proof-check/elan/bin/lean'
records=[]; logs=[]
with tempfile.TemporaryDirectory(prefix='cram-review-lean-') as tmp:
    build=Path(tmp)
    shutil.copy2(SOURCE/'lean-toolchain',build/'lean-toolchain')
    env=os.environ.copy(); env['ELAN_HOME']='/workspace/k-elimination-audit/proof-check/elan';env['LEAN_PATH']=tmp
    for module in MODULES:
        src=SOURCE/(module+'.lean'); target=build/src.name; shutil.copy2(src,target)
        proc=subprocess.run([lean,'-o',module+'.olean',target.name],cwd=build,env=env,text=True,capture_output=True)
        out=proc.stdout+proc.stderr; logs.append('$ lean -o '+module+'.olean '+target.name+'\n'+out)
        assert proc.returncode==0,(module,out)
        assert not re.search(r'\b(error|warning):',out),(module,out)
        queries=re.findall(r"'([^']+)' (?:depends on axioms: \[([^]]*)\]|does not depend on any axioms)",out)
        for name,axioms in queries:
            assert set(a.strip() for a in axioms.split(',') if a.strip()) <= {'Classical.choice','propext','Quot.sound'},(name,axioms)
        records.append({'file':src.name,'sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'axiom_reports':len(queries)})
    version=subprocess.check_output([lean,'--version'],cwd=build,env=env,text=True).strip()
(ROOT/'lean_independent.log').write_text('\n'.join(logs))
report={'status':'PASS','scope':'Fresh reviewer rebuild of all17 modules, each emitted axiom report checked; new36 proof bodies separately reviewed','version':version,'reused_project_olean':False,'total_axiom_reports':sum(r['axiom_reports'] for r in records),'files':records,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(ROOT/'lean_independent.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='files'},indent=2))
