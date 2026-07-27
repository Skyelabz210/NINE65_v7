# Private v6/v7 Runner Setup

The same-machine comparison workflow reads two private repositories. GitHub's default repository token is scoped to the repository that owns the workflow, so the v7 workflow requires a separate read-only credential for the v6 checkout.

## Required repository secret

Create this Actions secret in `Skyelabz210/NINE65_v7`:

```text
NINE65_CROSS_REPO_TOKEN
```

Use a fine-grained personal access token or GitHub App token with:

```text
Repository access:
  Skyelabz210/NINE65_v6_a_Clockwork_Prime

Repository permissions:
  Contents: Read-only
  Metadata: Read-only
```

The token does not need write access.

## Dispatch

Open **Actions → NINE65 v6 v7 comparative harness → Run workflow** on branch:

```text
cram/exploratory-comparative-v2
```

Recommended exploratory values:

```text
repetitions      7
iterations       100
mul_iterations   10
ct_mul_depth     8
v6_max_depth     8
```

The workflow checks out the pinned v6 commit:

```text
bd5c5c29f5c367bf34831cf5c1b97b3b938ac829
```

and the selected v7 branch head on the same Ubuntu runner.

## Artifacts

The workflow uploads `nine65-v6-v7-same-machine`, containing:

```text
manifest.json
comparison_records.json
comparison_analysis.json
hypothesis_analysis.json
build logs
per-run stdout and stderr
raw v6 and v7 JSON outputs
```

When the secret is absent, the workflow writes `skipped.json` and performs no comparison. It never substitutes public benchmark numbers or results from another machine.
