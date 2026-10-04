#!/usr/bin/env python3
"""Fetch all open issues for Skyelabz210/NINE65_v7 and dump title+body locally.

Read-only against GitHub (public repo, no token required). Output is stored in
docs/ISSUE_INTAKE_2026-10-04/ so later tooling can triage without network.
"""
import json
import os
import urllib.request

REPO = "Skyelabz210/NINE65_v7"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "ISSUE_INTAKE_2026-10-04")


def get(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "nine65-issue-triage",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    os.makedirs(OUT, exist_ok=True)
    issues = []
    page = 1
    while True:
        batch = get(f"https://api.github.com/repos/{REPO}/issues"
                    f"?state=open&per_page=100&page={page}")
        if not batch:
            break
        issues.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    real_issues = [i for i in issues if "pull_request" not in i]
    index = []
    for i in sorted(real_issues, key=lambda x: x["number"]):
        fn = f"issue_{i['number']}.md"
        with open(os.path.join(OUT, fn), "w") as f:
            f.write(f"# Issue #{i['number']}: {i['title']}\n\n")
            f.write(f"- state: {i['state']}\n")
            f.write(f"- labels: {', '.join(l['name'] for l in i['labels']) or '(none)'}\n")
            f.write(f"- created: {i['created_at']}  updated: {i['updated_at']}\n")
            f.write(f"- url: {i['html_url']}\n\n---\n\n")
            f.write(i["body"] or "(no body)\n")
        index.append({
            "number": i["number"],
            "title": i["title"],
            "labels": [l["name"] for l in i["labels"]],
            "url": i["html_url"],
        })

    with open(os.path.join(OUT, "INDEX.json"), "w") as f:
        json.dump(index, f, indent=2)
    print(f"wrote {len(index)} open issues to {OUT}")


if __name__ == "__main__":
    main()
