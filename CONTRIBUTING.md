# Contributing to stackpack-project-template

For people and agents. Read this whole file before your first change here.
Shared ARC rules (Plane, branches, PRs, secrets, release) are in the [ARC contribution handbook](https://github.com/arc-web/agent-config/blob/main/handbook/HANDBOOK.md). The repo standard that this file follows is [rules for every arc-web repo](https://github.com/arc-web/agent-config/blob/main/CONTRIBUTING.md#rules-for-every-arc-web-repo), and the full template set is in [STANDARD.md](https://github.com/arc-web/agent-config/blob/main/handbook/STANDARD.md).

## At a glance

| | |
|---|---|
| What this repo is | A starter template for StackPack projects: basic files and a security scan. |
| Owner and approver | Repo owner role; approves changes: ARC operations role |
| Runs live at | Nowhere. This is a library of files, not a service. |
| A merge reaches live by | Never automatically. Nothing is deployed from this repo. |
| Test command | `python3 tools/secret_scan.py --path .` |
| Plane project | AGENTS (todovibes workspace) |

## Quick start for agents

1. Read the Plane task and its comments. No task, no change. Ask a person to create one.
2. Claim the work so nobody else takes it.
3. Branch from the latest `main`: `<type>/<short-slug>`.
4. Make the smallest change that meets the task's acceptance.
5. Run `python3 tools/secret_scan.py --path .` from the repo root. Paste the result into the PR.
6. Open a PR with the template in `.github/pull_request_template.md` filled in. Link the Plane task.
7. After approval and merge: nothing to deploy.
8. Comment on the Plane task with the PR and what is left.

## Quick start for people

Ask an agent to make the change and to run the scan. You will get back a pull request with the scan result in it. Read the diff before you approve.

## What belongs here

| Change | Home |
|---|---|
| Basic files every StackPack project copies (README, CONTRIBUTING, AGENTS, CLAUDE, PR form, scan) | this repo |
| A project's own code, docs or rules | that project's repo |

## Layout

```
README.md                          what this is, in plain words
CONTRIBUTING.md                    this file
AGENTS.md                          rules for AI agents
CLAUDE.md                          loads AGENTS.md into Claude Code
docs/project_overview.md           the original README text, kept as reference
tools/secret_scan.py               the security scan
.github/pull_request_template.md   the PR form
.github/workflows/security.yml     the scan, on pushes and PRs (runs only if Actions is on)
ISSUE_TEMPLATE/fix.yml             the form for reporting something broken
```

## Set up and test

No install is needed. The scan uses Python 3 from the standard library.

```bash
cd <repo root>
python3 tools/secret_scan.py --path .
```

Exit `0` means no high finding. Exit `1` means at least one high finding; fix it before the PR. Exit `2` means a bad call. The scan reads local files only and makes no network calls, so it runs offline.

## Making a change

- Use `git mv` to move a file. Never copy and then delete.
- Stage named files only. Do not use `git add -A` or `git add .`.
- Do not bypass git hooks.
- Put the scan result in the PR's Checks section.

## The .github folder

- `.github/pull_request_template.md` is the PR form.
- `.github/workflows/security.yml` runs the same scan on pushes and pull requests. It runs only when GitHub Actions is on for this repo. To stop it, disable it with `gh workflow disable`. Do not delete the file.
- Never put a `README.md` inside `.github`. GitHub would show it on the repo front page in place of the root README.
- `ISSUE_TEMPLATE/` sits at the repo root, not inside `.github`. It holds the form for reporting something broken.

## Release and rollback

| Layer | Here |
|---|---|
| Dev | A branch in your own checkout |
| Test | `python3 tools/secret_scan.py --path .`, run locally, result in the PR |
| Staging | None yet |
| Production | `main`. Nothing is deployed from it. |

There is no deploy step. A merged PR is the release.

To roll back, revert the merge commit on a new branch and open a PR for the revert:

```bash
git switch -c revert/<short-slug>
git revert -m 1 <merge sha>
git push -u origin revert/<short-slug>
```

## Rules that are easy to break

- Run the scan before every push. A `.env` file or a token committed by mistake stays in git history even after it is deleted.
- Never put a `README.md` inside `.github`. The root README is the one people read.
- Do not turn the scan into a network call. It is meant to run offline.

## Secrets

This repo uses no secrets. Do not add a token, key, or `.env` file. If a project built from this template needs one, store it in OpenBao and name only its path in that project's docs.

## Getting help

Ask in the StackPack Discord. For work on this repo, the Plane project is AGENTS in the todovibes workspace.
