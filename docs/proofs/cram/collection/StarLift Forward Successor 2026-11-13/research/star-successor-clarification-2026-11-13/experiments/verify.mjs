import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {nextStarReadings,restoreStarSource} from './star_transport.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const core = path.resolve(process.env.ASTRO_CORE ?? path.join(here,
  '../../dccms-mechanism-investigation-2026-11-13/sources/astrology_remastered/project/src/core'));
const load = name => import(pathToFileURL(path.join(core, name)).href);
const {adjacencyRecover} = await load('cram.js');
const {starNumber, towerLevel, windingTower} = await load('fixture.js');
const {starLiftBasis} = await load('anchor.js');
const {arrowOfTime} = await load('tray.js');
const {stepForward, stepBackward} = await load('arrow.js');
const mod = (x,m) => ((x%m)+m)%m;
const gcd = (a,b) => b === 0n ? a : gcd(b,a%b);
const lcm = (a,b) => a/gcd(a,b)*b;
const counts = {};

// All finite states: the existing adjacent readout conjugates diagonal unit
// advance to a phase advance with a quotient-class carry at phase wrap.
counts.conjugacy_states = 0;
for (let M=2n; M<=64n; M++) {
  const A=M+1n, seen=new Set();
  for (let r=0n;r<M;r++) for (let s=0n;s<A;s++) {
    const q=adjacencyRecover(r,s,M);
    assert.equal(mod(r-q,A),s);
    const rn=mod(r+1n,M), sn=mod(s+1n,A);
    assert.equal(adjacencyRecover(rn,sn,M),mod(q+(r===M-1n?1n:0n),A));
    seen.add(`${r},${q}`);
    counts.conjugacy_states++;
  }
  assert.equal(BigInt(seen.size),M*A);
}

// Residue state only. The test-loop index is an external expected-answer
// oracle and is never supplied to the readout or transition.
let r=0n,s=0n;
const traceAt=new Set([0,1,35,36,37,71,72,1295,1296,1331,1332,1333]);
const trace=[];
counts.forward_steps=4*36*37;
for (let tick=0;tick<=counts.forward_steps;tick++) {
  const q=adjacencyRecover(r,s,36n), expected=BigInt(tick)/36n;
  assert.equal(q,expected%37n);
  if (traceAt.has(tick)) trace.push({tick,r,s,kClass:q,negativeKClass:mod(s-r,37n),oracleK:expected});
  if (tick===1332) assert.deepEqual([r,s,q],[0n,0n,0n]);
  r=(r+1n)%36n; s=(s+1n)%37n;
}

// Existing orientation code contains a chosen successor and its inverse.
// The forward-only hypothesis admits the successor, not arbitrary reversal.
counts.existing_step_inverse_checks=0;
for (let K=0n;K<4n;K++) for(let phase=0n;phase<36n;phase++) {
  const state={r:phase,K};
  assert.deepEqual(stepBackward(stepForward(state,36n),36n),state);
  counts.existing_step_inverse_checks++;
}
const arrow=arrowOfTime([2n,3n,5n,7n,11n,13n]);
assert.equal(arrow.instantiated,true);

// Exact growth law and the already-documented special S3/S4 alignment.
counts.star_growth_cases=0;
const gapMatches=[],starRows=[];
for(let n=1n;n<=1000n;n++) {
  const A=starNumber(n), next=starNumber(n+1n), gap=next-A;
  assert.equal(gap,12n*n);
  assert.equal(A%12n,1n);
  if(gap===A-1n) gapMatches.push(n);
  if(n<=12n) starRows.push({n,star:A,shell:A-1n,nextGap:gap});
  counts.star_growth_cases++;
}
assert.deepEqual(gapMatches,[3n]);
counts.internal_star_bases=0;
for(let n=2n;n<=12n;n++) {
  const b=starLiftBasis(n);
  assert.equal(b.basis.reduce((a,p)=>a*p,1n),b.shell*b.anchor);
  for(let i=0;i<b.basis.length;i++) for(let j=i+1;j<b.basis.length;j++)
    assert.equal(gcd(b.basis[i],b.basis[j]),1n);
  counts.internal_star_bases++;
}
assert.deepEqual(starLiftBasis(3n).basis,[4n,9n,37n]);
assert.deepEqual(starLiftBasis(5n).anchor_lanes,[121n]);
assert.equal(starNumber(5n),11n*11n);
counts.composite_anchor_cases=0;
for(let x=0n;x<120n*121n;x++) {
  assert.equal(adjacencyRecover(x%120n,x%121n,120n),x/120n);
  counts.composite_anchor_cases++;
}

// A fresh target needs enough observed resolution. Compute the least extra
// anchor using the prior gcd-saturation constructor, without factorization.
const P=36n*37n,D=72n*73n;
let a=D/gcd(P,D);
const saturation=[a];
for(;;) {
  const next=gcd(D,a*a);
  if(next===a) break;
  a=next; saturation.push(a);
}
assert.deepEqual(saturation,[146n,292n,584n]);
assert.equal(lcm(P,a)%D,0n);
counts.anchor_admission_cases=0;
for(let candidate=1n;candidate<=5000n;candidate++) {
  assert.equal(lcm(P,candidate)%D===0n,candidate%584n===0n);
  counts.anchor_admission_cases++;
}
const insufficient=[1n,146n,292n].map(anchor=>{
  const x=lcm(P,anchor);
  assert.equal(x%P,0n); assert.equal(x%anchor,0n);
  assert.notEqual(x%D,0n);
  return {anchor,x,source36:x%36n,source37:x%37n,extra:x%anchor,target72:x%72n,target73:x%73n};
});
counts.next_star_full_period_cases=0;
counts.complete_frame_roundtrips=0;
const distinctInputPairs=new Set();
const jointPeriod=lcm(P,584n);
for(let x=0n;x<jointPeriod;x++) {
  const got=nextStarReadings(x%36n,x%584n);
  assert.deepEqual(got,{r72:x%72n,s73:x%73n,kMod73:(x/72n)%73n});
  distinctInputPairs.add(`${x%36n},${x%584n}`);
  assert.deepEqual(restoreStarSource(got.r72,got.s73,x%37n),
    {r36:x%36n,s37:x%37n,v584:x%584n});
  counts.next_star_full_period_cases++;
  counts.complete_frame_roundtrips++;
}
counts.distinct_constructor_input_pairs=distinctInputPairs.size;
assert.equal(BigInt(distinctInputPairs.size),D);
counts.large_signed_target_cases=0;
for(const x of [-(1n<<256n),-1333n,-1n,1n<<256n,(1n<<256n)+1234567n]) {
  const got=nextStarReadings(mod(x,36n),mod(x,584n));
  const q=(x-mod(x,72n))/72n;
  assert.deepEqual(got,{r72:mod(x,72n),s73:mod(x,73n),kMod73:mod(q,73n)});
  counts.large_signed_target_cases++;
}
const rejected=[[0n,1n],[-1n,0n],[36n,0n],[0n,584n],[0,0n]];
for(const args of rejected) assert.throws(()=>nextStarReadings(...args),RangeError);
counts.constructor_refusals=rejected.length;
const inverseRejected=[[-1n,0n,0n],[72n,0n,0n],[0n,73n,0n],[0n,0n,37n],[0n,0n,0]];
for(const args of inverseRejected) assert.throws(()=>restoreStarSource(...args),RangeError);
counts.inverse_refusals=inverseRejected.length;

// Structural prime-divisor prediction; actual existing starNumber is tested
// against every index class for each prime <= 997. This is finite evidence;
// the universal statement in the report uses quadratic reciprocity.
const isPrime = p => {
  if(p<2) return false;
  for(let d=2;d*d<=p;d++) if(p%d===0) return false;
  return true;
};
counts.prime_moduli=0; counts.index_residue_classes=0;
const rootExamples={};
for(let p=2;p<=997;p++) if(isPrime(p)) {
  const roots=[];
  for(let n=0;n<p;n++) {
    if(starNumber(BigInt(n))%BigInt(p)===0n) roots.push(n);
    counts.index_residue_classes++;
  }
  const expected=p>3 && (p%12===1 || p%12===11) ? 2 : 0;
  assert.equal(roots.length,expected);
  if([5,7,11,13,23,37].includes(p)) rootExamples[p]=roots;
  counts.prime_moduli++;
}

// Distinguish per-level query locality from production of deeper observations.
const tower=windingTower(1332n,36n);
assert.equal(tower[0].k_mod_anchor,0n);
assert.equal(tower[0].k_true,37n);
assert.equal(tower[0].certified,false);
assert.equal(tower[1].value,37n);
assert.deepEqual(tower[1],towerLevel(37n,36n));

const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const coreFiles=fs.readdirSync(core).filter(f=>f.endsWith('.js')).sort();
const result={
  status:'PASS',executed_at_utc:new Date().toISOString(),
  source_repository:'https://github.com/Skyelabz210/astrology_remastered',
  source_commit:'ad0c8380f02b1d0c4f05a3e00726be3bc9680058',
  core_sha256:Object.fromEntries(coreFiles.map(f=>[f,sha(path.join(core,f))])),
  experiment_sha256:{'verify.mjs':sha(fileURLToPath(import.meta.url)),
    'star_transport.mjs':sha(path.join(here,'star_transport.mjs'))},
  counts,trace,starRows,gapMatches,star3Basis:starLiftBasis(3n).basis,
  next_star:{source_period:P,target_period:D,saturation,least_extra_anchor:a,jointPeriod,insufficient},
  rootExamples,existing_arrow_report:arrow,
  scope:'Clear arithmetic/model verification. No new Lean declarations, physical experiment, primality breakthrough, historical identification, or encrypted execution.'
};
const stringify=x=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n';
fs.mkdirSync(path.join(here,'../evidence'),{recursive:true});
fs.writeFileSync(path.join(here,'../evidence/verification.json'),stringify(result));
console.log(stringify({status:result.status,counts,next_star:result.next_star,rootExamples}));
