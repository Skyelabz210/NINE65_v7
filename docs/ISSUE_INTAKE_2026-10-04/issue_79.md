# Issue #79: [P0] Restore active GitHub Actions execution and required release checks

- state: open
- labels: (none)
- created: 2026-08-31T07:07:45Z  updated: 2026-09-03T16:33:55Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/79

---

## Mandatory baseline, captured 2026-09-03

- **Current `main` SHA:** `43a7d335b668b5e5740416f101c6d3f67076f348`
- **Current combined-status result:** zero status checks attached to any recent commit (`total_count: 0` via the GitHub API's combined-status endpoint, checked against `origin/main`'s HEAD before this comment). State reports as `pending` only because nothing has ever posted a check, not because anything is in progress.
- **Current Actions run inventory / most recent run date:** 39 total runs on record for this repo. The most recent is **run #48, `workflow_dispatch`, created 2026-02-27T09:58:47Z, still `status: queued`** as of today (2026-09-03) — over six months stuck queued, never started. Every completed run before that (runs #31–#44, all from 2026-02-24 through 2026-02-27) has `conclusion: failure`. **Nothing has run — successfully or otherwise — since 2026-02-27, and every push/merge across the entire March–September 2026 history (dozens of merged PRs, including the WIRE-Q fail-closed work, Track 1/2, and everything in today's wave) has gone in with zero CI execution.** This is exactly the finding this issue already states; today's check reconfirms it's still true seven months later.
- **Branch/ruleset required-check configuration:** not independently re-verified here (would need a ruleset-listing call this session doesn't have queued up) — worth confirming directly alongside whatever fixes root cause item #1.

## What I could not do

Item #1 ("resolve the repository/account-level cause preventing Actions execution — billing, Actions enablement, permissions, runner availability, or policy") is outside what a coding agent can fix: run #48 sitting `queued` for six months, with zero runner pickup, strongly resembles an account-level Actions-disabled or billing-paused state (the same pattern `CLAUDE.md` already documents for this project's Cloud Run service: "Disabled — billing paused"). That needs the repository owner to check GitHub Actions/billing settings in the web UI (Settings → Actions → General, and the organization/account billing page) — I don't have visibility into or control over that from here.

Everything else in this issue (items #2–#6: manually dispatch and record runs, require the mechanical checks via branch protection, ensure a missing AI-review secret can't satisfy a mechanical gate, verify required-check names map to real jobs, don't declare `main` green prematurely) is blocked on item #1 being resolved first — there's no point wiring up required-status-check enforcement for jobs that structurally cannot execute yet.