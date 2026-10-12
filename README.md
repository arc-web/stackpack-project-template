# stackpack-project-template

A starting point for a new StackPack project. It holds the basic files and a security scan that every ARC repo needs.

**In plain words:** When someone in the StackPack community starts a new project, they copy these files into it. The new project then already has a README, a contributing guide, notes for AI agents, a pull request form, and a scan that looks for passwords and keys before they get pushed. For example, running `python3 tools/secret_scan.py --path .` from a project folder prints `Scanned 3 files. Nothing found.` when no key shapes are in those files.

| | |
|---|---|
| Status | Reference only: a starter template. Nothing runs from it. |
| Owner | Repo owner role; approves changes: ARC operations role |
| Runs at | Nothing runs from this repo. |
| A change goes live by | Merging to `main`. Nothing is deployed. Details in [CONTRIBUTING.md](CONTRIBUTING.md#release-and-rollback) |
| Change something | Start with [CONTRIBUTING.md](CONTRIBUTING.md) |

## What is in this repo

Each file has one job. The table lists them in the order a newcomer usually needs them.

| Path | What it holds |
|---|---|
| `README.md` | This file. |
| `CONTRIBUTING.md` | How to change this repo, with the test command and the release path. |
| `AGENTS.md` | Short rules for AI agents. Read first by agents that load it. |
| `CLAUDE.md` | One line that loads `AGENTS.md` into Claude Code. |
| `tools/secret_scan.py` | The security scan. It reads local files only and sends nothing. |
| `.github/pull_request_template.md` | The form every pull request fills in. |
| `.github/workflows/security.yml` | A workflow that runs the same scan on pushes and pull requests. It runs only if GitHub Actions is on for the repo. |
| `ISSUE_TEMPLATE/fix.yml` | The form for reporting something that is broken. |
| `docs/project_overview.md` | The original README text, kept as reference. |

## What the scan checks

`tools/secret_scan.py` reads the files you point it at and reports:

- Key shapes from common services, such as GitHub, Slack, AWS, Stripe and Anthropic tokens, and private key blocks.
- Long random-looking strings in configuration files, such as `.env` files.
- Shell and code patterns that download and run code, open reverse shells, or write to `authorized_keys`.
- Files larger than 5 megabytes.

It is a gate, not a guarantee. A clean result does not prove a file is safe. Read the diff yourself before a push.

## What the scan skips

- Folders named `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.next` and `vendor`.
- The scan file itself, because it holds the patterns it looks for.
- Any path listed in a `.scanignore` file at the top of the folder you scan. Put one pattern per line. Lines starting with `#` are comments. Use this only for files that are known to be safe, and say why in the PR.

Files that are not text (for example images) are not read for patterns.

## Before you start

- Python 3. The scan uses only the Python standard library, so there is nothing to install.
- Git, to copy the files into a new project and to open pull requests.
- A terminal opened in the folder you want to scan.

## How to use it

1. Copy the files you need into the new project folder.
2. Open a terminal in that folder and run:

   ```bash
   python3 tools/secret_scan.py --path .
   ```

3. Read the result. The scan exits with `0` when it finds nothing high, and `1` when it finds something high. Each finding shows the severity, the rule, the file, and the line. The scan shows only the first four and last two characters of a match, never the whole value.
4. Replace every `<...>` placeholder in the new project's README and CONTRIBUTING.md with the real text.

## How a change reaches the repo

1. Make the change on a branch, not on `main`.
2. Run the scan and keep the result for the pull request.
3. Open a pull request and fill in the form in `.github/pull_request_template.md`.
4. A person reviews and merges it into `main`.
5. There is no deploy step. The merged files are the release.

If a merge needs to be undone, see the rollback steps in [CONTRIBUTING.md](CONTRIBUTING.md#release-and-rollback).

## Who uses it

| Who or where | What they use it for | How they get it |
|---|---|---|
| A StackPack member starting a project | A ready set of basic files and the scan | Copy the files listed in "What is in this repo" |
| A reviewer | Checking a pull request against the form | The PR form in `.github/pull_request_template.md` |
| An AI agent (Claude Code, Codex) | Its rules for this repo | `AGENTS.md`, loaded through `CLAUDE.md` for Claude Code |
| A person reporting a problem | Telling the owner what is broken | The form in `ISSUE_TEMPLATE/fix.yml` |

## Start here

| You want to | Go to |
|---|---|
| Start a new project from these files | The steps in "How to use it" above |
| Run the security scan | `python3 tools/secret_scan.py --path .` |
| Change this repo | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Read the original README | [docs/project_overview.md](docs/project_overview.md) |
| Report something broken | The form in `ISSUE_TEMPLATE/fix.yml` |

## How it fits

This repo is a starting point. It does not call other systems. The ARC standard that these files follow lives in the agent-config handbook: [repo-standard.md](https://github.com/arc-web/agent-config/blob/main/handbook/repo-standard.md) and [STANDARD.md](https://github.com/arc-web/agent-config/blob/main/handbook/STANDARD.md). Those files are the owners of the rules. This repo links to them and does not copy them.

## What to watch for

- The `.github` folder holds the pull request form and the scan workflow. Keep the `README.md` out of it. GitHub would show a README in `.github` on the front page in place of this one.
- The scan only looks at what you point it at. Run it on the whole project folder, not one file, before a push.
- A new project may need its own rules. Add them to that project's CONTRIBUTING.md, not here.

## Words we use

- **Secret:** a password, token, key, or any value that lets someone sign in as someone else.
- **Pull request (PR):** a proposed change to a repo. A person reviews it before it merges.
- **Merge:** adding an approved pull request to `main`.
- **Scan:** the check in `tools/secret_scan.py`. It reads files and reports suspicious content.
- **GitHub Actions:** GitHub's automation system. It runs workflow files, but only when it is turned on for the repo.
- **Issue:** a report of something broken, filed with the form in `ISSUE_TEMPLATE/fix.yml`.

## Help

Ask in the StackPack Discord. If something in these files is broken, open an issue with the fix form.

> [!NOTE]
> Working with an AI agent? Its instructions are in [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md).
