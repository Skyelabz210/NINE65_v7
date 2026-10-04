#!/usr/bin/env python3
"""Create linked issues and honest draft kickoff PRs for the execution cards.

Run only after the execution plan has been committed and pushed to main. The
publication manifest makes interrupted runs resumable; issue and PR lookup also
prevents duplicates if the local manifest is lost.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


REPO = "Skyelabz210/NINE65_v7"
PLAN_DIR = Path("docs/execution/2026-10-03")
MANIFEST = Path("artifacts/execution/2026-10-03-backlog-publication.json")


def run(*args, input_text=None, env=None):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, env=env, check=False
    )
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def save(state):
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    temp = MANIFEST.with_suffix(".json.tmp")
    temp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    temp.replace(MANIFEST)


def topological(tasks):
    table = {task["id"]: task for task in tasks}
    if len(table) != len(tasks):
        raise ValueError("duplicate task ID")
    ordered, seen, visiting = [], set(), set()

    def visit(task_id):
        if task_id in seen:
            return
        if task_id in visiting:
            raise ValueError(f"dependency cycle at {task_id}")
        visiting.add(task_id)
        for parent in table[task_id]["depends_on"]:
            visit(parent)
        visiting.remove(task_id)
        seen.add(task_id)
        ordered.append(table[task_id])

    for task in tasks:
        visit(task["id"])
    return ordered


def bullets(items, checkbox=False):
    prefix = "- [ ] " if checkbox else "- "
    return "\n".join(prefix + item for item in items) or "- None."


def task_status(task_id):
    if task_id == "F00":
        return "Baseline snapshot collected; independent acceptance is pending."
    if task_id == "S00":
        return "Reference equations drafted; the owner's live 2/11 phase binding is unresolved."
    if task_id == "S02":
        return "Composite inverse patch and focused tests are on main; S00-dependent sister placement remains pending."
    return "Planned; implementation and acceptance evidence remain pending."


def issue_body(task, issues, base):
    task_id = task["id"]
    card = f"https://github.com/{REPO}/blob/{base}/{PLAN_DIR}/tasks/{task_id}.md"
    parents = [f"{parent}: #{issues[parent]['number']}" for parent in task["depends_on"]]
    related = [f"#{number}" for number in task["issues"]]
    return (
        f"Execution packet: [{task_id}]({card})  \n"
        f"State: {task_status(task_id)}  \n"
        f"Kind: {task['kind']}  \n"
        f"Required review: {task['review']}\n\n"
        f"Dependencies: {', '.join(parents) if parents else 'none'}.  \n"
        f"Existing related issues: {', '.join(related) if related else 'none'}.\n\n"
        "## Work\n\n" + bullets(task["steps"]) + "\n\n"
        "## Acceptance\n\n" + bullets(task["acceptance"], checkbox=True) + "\n\n"
        "## Required checks\n\n" + bullets([f"`{check}`" for check in task["checks"]], checkbox=True) + "\n\n"
        f"Stop condition: {task['stop']}\n\n"
        "Record real test counts, source hashes and review in the task result artifact. "
        "An open issue or a draft PR does not mean the implementation is complete.\n"
    )


def branch_name(task_id):
    return f"codex/execution-{task_id.lower()}"


def work_record(task, issue):
    task_id = task["id"]
    return (
        f"# {task_id}: {task['title']}\n\n"
        f"Tracks {issue['url']}. Source contract: [task packet](../tasks/{task_id}.md).\n\n"
        f"Status: **draft kickoff; acceptance pending**. {task_status(task_id)}\n\n"
        f"Dependencies: {', '.join(task['depends_on']) if task['depends_on'] else 'none'}.\n\n"
        "## Required implementation\n\n" + bullets(task["steps"], checkbox=True) + "\n\n"
        "## Acceptance evidence to add before review\n\n"
        + bullets(task["acceptance"], checkbox=True) + "\n\n"
        "## Checks to execute against the implemented source\n\n"
        + bullets([f"`{check}`" for check in task["checks"]], checkbox=True) + "\n\n"
        f"Stop condition: {task['stop']}\n\n"
        "This branch currently adds only this work record. Implement the packet "
        "and attach its measured result before marking this PR ready for review.\n"
    )


def pull_body(task, issue, base):
    task_id = task["id"]
    card = f"https://github.com/{REPO}/blob/{base}/{PLAN_DIR}/tasks/{task_id}.md"
    return (
        f"Tracks {issue['url']}. [Execution contract]({card}).\n\n"
        f"This draft starts the **{task_id}** work record and acceptance checklist. "
        "The task implementation and its review evidence are still pending. "
        f"Current state: {task_status(task_id)}\n\n"
        "A worker should implement only the packet's write scope, run its checks "
        "with positive matching test counts, attach the result artifact, and "
        "request the specified review before marking this PR ready.\n"
    )


def write_temp_body(body):
    file = tempfile.NamedTemporaryFile(mode="w", prefix="nine65-backlog-", suffix=".md", delete=False)
    try:
        file.write(body)
        file.close()
        return file.name
    except BaseException:
        file.close()
        raise


def find_existing_issues():
    rows = json.loads(run("gh", "issue", "list", "--repo", REPO, "--state", "all", "--limit", "500", "--json", "number,title,url"))
    return {match.group(1): {"number": row["number"], "url": row["url"]}
            for row in rows if (match := re.match(r"^\[([FSCRBHGV]\d\d)\] ", row["title"]))}


def find_existing_prs():
    rows = json.loads(run("gh", "pr", "list", "--repo", REPO, "--state", "all", "--limit", "500", "--json", "number,url,headRefName"))
    return {row["headRefName"]: {"number": row["number"], "url": row["url"]}
            for row in rows if row["headRefName"].startswith("codex/execution-")}


def build_branch(base, task, issue):
    branch = branch_name(task["id"])
    ref = f"refs/heads/{branch}"
    present = subprocess.run(("git", "show-ref", "--verify", "--quiet", ref), check=False)
    if present.returncode == 0:
        return branch
    path = f"{PLAN_DIR}/work/{task['id']}.md"
    blob = run("git", "hash-object", "-w", "--stdin", input_text=work_record(task, issue))
    with tempfile.TemporaryDirectory(prefix="nine65-index-") as directory:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(directory) / "index"))
        run("git", "read-tree", base, env=env)
        run("git", "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
        tree = run("git", "write-tree", env=env)
    commit = run("git", "commit-tree", tree, "-p", base, "-m", f"Start {task['id']}: {task['title']}")
    run("git", "update-ref", ref, commit)
    return branch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="validate and preview without mutation")
    args = parser.parse_args()
    tasks = topological(json.loads((PLAN_DIR / "tasks.json").read_text())["tasks"])
    base = run("git", "rev-parse", "HEAD")
    if run("git", "branch", "--show-current") != "main":
        raise RuntimeError("publication requires local main")
    if args.dry_run:
        print(json.dumps({"repo": REPO, "base": base, "tasks": len(tasks),
                          "first_issue": issue_body(tasks[0], {}, base),
                          "first_work_record": work_record(tasks[0], {"url": "https://github.com/example/issues/1"})}, indent=2))
        return 0
    if not MANIFEST.exists() and run("git", "status", "--porcelain"):
        raise RuntimeError("commit and push the plan before publishing the backlog")
    state = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {
        "schema": 1, "repo": REPO, "base_commit": base, "issues": {}, "branches": {}, "pull_requests": {}
    }
    if state["base_commit"] != base:
        raise RuntimeError("main moved since backlog publication started; reconcile before resuming")
    existing_issues = find_existing_issues()
    for task in tasks:
        task_id = task["id"]
        if task_id in state["issues"]:
            continue
        if task_id in existing_issues:
            state["issues"][task_id] = existing_issues[task_id]
        else:
            body_file = write_temp_body(issue_body(task, state["issues"], base))
            try:
                url = run("gh", "issue", "create", "--repo", REPO,
                          "--title", f"[{task_id}] {task['title']}", "--body-file", body_file)
            finally:
                Path(body_file).unlink(missing_ok=True)
            state["issues"][task_id] = {"number": int(url.rsplit("/", 1)[1]), "url": url}
        save(state)
        print(f"issue {task_id}: {state['issues'][task_id]['url']}", flush=True)

    for task in tasks:
        task_id = task["id"]
        if task_id not in state["branches"]:
            state["branches"][task_id] = build_branch(base, task, state["issues"][task_id])
            save(state)
    refs = [f"refs/heads/{state['branches'][task['id']]}:refs/heads/{state['branches'][task['id']]}"
            for task in tasks]
    run("git", "push", "origin", *refs)
    print(f"pushed {len(refs)} task branches", flush=True)

    existing_prs = find_existing_prs()
    for task in tasks:
        task_id = task["id"]
        if task_id in state["pull_requests"]:
            continue
        branch = state["branches"][task_id]
        if branch in existing_prs:
            state["pull_requests"][task_id] = existing_prs[branch]
        else:
            body_file = write_temp_body(pull_body(task, state["issues"][task_id], base))
            try:
                url = run("gh", "pr", "create", "--draft", "--repo", REPO,
                          "--base", "main", "--head", branch,
                          "--title", f"draft: [{task_id}] {task['title']}",
                          "--body-file", body_file)
            finally:
                Path(body_file).unlink(missing_ok=True)
            state["pull_requests"][task_id] = {"number": int(url.rsplit("/", 1)[1]), "url": url}
        save(state)
        print(f"draft PR {task_id}: {state['pull_requests'][task_id]['url']}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError) as error:
        print(f"publication stopped: {error}", file=sys.stderr)
        sys.exit(1)
