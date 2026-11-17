// Read-only finite reference checks. The scalar is an oracle/encoder, not a
// claim of a no-scalar production observation source.
import assert from 'node:assert/strict';
import fs from 'node:fs';
const core='file:///workspace/dccms-investigation/sources/astrology_remastered/project/src/core/';
const {towerRecover}=await import(core+'tower-recover.js');
const {towerReport}=await import(core+'fixture.js');
const M=881790n,x=(1n<<256n)-1n;
let checks=0,previous=null,last=null;
for(let e=1;e<=80;e++){
  const A=11n**BigInt(e),recovered=towerRecover(x%M,[x%A],M,[A]);
  assert(recovered!==null);checks++;
  assert.equal(recovered.K,(x/M)%A);checks++;
  assert.equal(recovered.R,A);checks++;
  if(previous!==null){assert.equal(recovered.K%previous.R,previous.K);checks++;}
  previous=recovered;last=recovered;
}
assert.equal(last.K,x/M);checks++;
const collision=x+M*11n;
assert.equal(x%M,collision%M);checks++;
assert.equal(x%11n,collision%11n);checks++;
assert.notEqual(x/M,collision/M);checks++;
const report=towerReport((1n<<128n)-1n,36n);
assert.equal(report.depth,'25');checks++;
assert.equal(report.certified_levels,'2');checks++;
const result={node:process.version,checks,failures:0,
  repo_commit:'ad0c8380f02b1d0c4f05a3e00726be3bc9680058',
  scope:'finite smoke checks; scalar X used only as independent oracle and to encode authentic readings, not a no-scalar production source',
  shell:String(M),source_bits:256,anchors_tested:'11^e for e=1..80',
  last_resolution:String(last.R),exact_final_winding:last.K===x/M,
  compatible_reductions:true,fixed_mod11_collision_preserves_readings:true,
  star36_fixture:report};
fs.writeFileSync(new URL('./tower-smoke-results.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
