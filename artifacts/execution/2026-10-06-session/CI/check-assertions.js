const fs = require('fs');
const yaml = require('yaml');
const cp = require('child_process');
const workflow = yaml.parse(fs.readFileSync('.github/workflows/app_platform_gates.yml', 'utf8'));
let failures = 0;
for (const [jobId, job] of Object.entries(workflow.jobs)) {
  for (const step of job.steps || []) {
    if (!/^(Assert|Enforce)/.test(step.name || '')) continue;
    const run = cp.spawnSync('bash', ['-e', '-c', step.run], {encoding: 'utf8'});
    process.stdout.write(`${jobId}: ${step.name}: ${run.status}\n`);
    if (run.status !== 0) {
      failures++;
      process.stderr.write(run.stdout + run.stderr);
    }
  }
}
process.exitCode = failures ? 1 : 0;
