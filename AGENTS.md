# Agent instructions

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. It has the test command, the release path and the layout.

Rules agents break most here:

1. Run `python3 tools/secret_scan.py --path .` before every push and paste the result into the PR.
2. Never put a `README.md` inside `.github`.
3. Move files with `git mv`. Never copy a file and then delete the original.
4. Stage named files only. Do not use `git add -A` or `git add .`.
5. Never add a token, key, `.env` value, or client data to any file.
6. Do not bypass git hooks with `--no-verify` or by overriding `core.hooksPath`.
