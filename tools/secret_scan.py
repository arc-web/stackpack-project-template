#!/usr/bin/env python3
"""Security scan for a member repository.

Run before anything is admitted to a repo: on a pull request, on a push, or by
the assistant before handing over a member's push.

    python3 secret_scan.py --path .            # scan a directory
    python3 secret_scan.py --path . --json     # machine readable
    python3 secret_scan.py --path f1 f2 --json # scan named files

Exit 0 when nothing is found, 1 when something high is found, 2 on a bad call.

What it catches, and what it does not:
  catches  recognised key shapes, private key blocks, high entropy strings in
           configuration files, a short list of dangerous shell and code
           patterns, and oversized files.
  does not promise to catch everything. It is a gate, not a guarantee, and a
  pass is not a statement that a file is safe.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "vendor"}

# Recognised credential shapes. Each entry: name, severity, compiled pattern.
KEY_PATTERNS = [
    ("aws-access-key-id", "high", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    ("github-token", "high", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack-token", "high", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-key", "high", re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("stripe-secret", "high", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("sendgrid-key", "high", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("twilio-key", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("private-key-block", "high", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("basic-auth-url", "medium", re.compile(r"\bhttps?://[A-Za-z0-9._%+\-]+:[^\s/@:]{6,}@[A-Za-z0-9.\-]+")),
    ("password-assignment", "medium", re.compile(r"(?i)\b(?:password|passwd|pwd|pass|secret|api[_-]?key|access[_-]?token|auth[_-]?token|bot[_-]?token|token|client[_-]?secret|private[_-]?key|bearer)\b\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']")),
    ("named-secret-unquoted", "high", re.compile(r"(?i)\b(?:aws_secret_access_key|aws_access_key_id|secret[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|bot[_-]?token|client[_-]?secret|token)\b\s*[:=]\s*[A-Za-z0-9+/=_\-]{16,}\s*$")),
]

# Dangerous patterns. A member's repo is public code; these shapes need a human read.
DANGER_PATTERNS = [
    ("pipe-download-to-shell", "high", re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")),
    ("reverse-shell", "high", re.compile(r"(?i)(?:/dev/tcp/|bash\s+-i\s+>&|nc\s+-e\s+/bin/(?:ba)?sh|socat\s+.*exec:)")),
    ("decode-and-run", "high", re.compile(r"(?i)(?:base64\s+(?:-d|--decode)\s*\|\s*(?:ba|z)?sh|eval\s*\(\s*(?:base64|atob))")),
    (
        "remote-exec-in-code",
        "medium",
        re.compile(r"(?i)(?:python[0-9.]*|node|perl|ruby)\s+-[ce]\s+[\"'][^\"']*(?:socket|subprocess|child_process|exec\(|system\()"),
    ),
    ("ssh-key-write", "high", re.compile(r"(?i)>>?\s*[~/$][^\n]*authorized_keys")),
    ("destructive-root-delete", "high", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(?:\s|$)")),
    ("credential-exfil-endpoint", "medium", re.compile(r"(?i)\b(?:webhook\.site|requestbin|pipedream\.net|burpcollaborator|interact\.sh|ngrok\.io)\b")),
    ("obfuscated-blob", "low", re.compile(r"\b[A-Za-z0-9+/]{300,}={0,2}\b")),
]

TEXT_SUFFIXES = {
    "", ".md", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh", ".ps1", ".rb", ".go", ".rs", ".java", ".php",
    ".sql", ".html", ".css", ".xml", ".csv", ".tf", ".hcl", ".dockerfile", ".gitignore", ".example",
}
SENSITIVE_NAME_HINTS = (".env", "config", "secret", "credential", "settings", "key", "token", ".npmrc", ".pypirc", ".netrc")
ENTROPY_MIN_LEN = 24
ENTROPY_THRESHOLD = 4.2


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    detail: str


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def iter_files(paths: list[str]) -> list[Path]:
    self_path = Path(__file__).resolve()
    ignore = load_ignore(paths)
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if p.resolve() != self_path and not ignored(p, ignore):
                out.append(p)
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                f = Path(root) / name
                # The scanner carries the patterns it looks for, so it always
                # matches itself. Its own file is never scanned.
                if f.resolve() == self_path or ignored(f, ignore):
                    continue
                out.append(f)
    return sorted(out)


def load_ignore(paths: list[str]) -> list[str]:
    """Patterns from .scanignore, one per line, matched against the file path."""
    for raw in paths:
        root = Path(raw)
        candidate = (root if root.is_dir() else root.parent) / ".scanignore"
        if candidate.is_file():
            return [
                line.strip()
                for line in candidate.read_text(errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
    return []


def ignored(path: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False
    text = str(path)
    name = path.name
    for pat in patterns:
        if fnmatch.fnmatch(text, pat) or fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(text, f"*/{pat}"):
            return True
    return False


def is_texty(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name.lower() in {"dockerfile", "makefile", "procfile"}


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [Finding(str(path), 0, "unreadable", "low", str(exc))]

    if size > MAX_FILE_BYTES:
        return [Finding(str(path), 0, "file-too-large", "medium", f"{size} bytes, limit {MAX_FILE_BYTES}")]
    if not is_texty(path):
        return findings

    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        return [Finding(str(path), 0, "unreadable", "low", str(exc))]

    low_name = path.name.lower()
    sensitive_file = any(h in low_name for h in SENSITIVE_NAME_HINTS)

    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 20000:
            line = line[:20000]
        for name, severity, pattern in KEY_PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append(Finding(str(path), lineno, name, severity, redact(m.group(0))))
        for name, severity, pattern in DANGER_PATTERNS:
            m = pattern.search(line)
            if m and not (name == "obfuscated-blob" and not sensitive_file and len(line) < 400):
                findings.append(Finding(str(path), lineno, name, severity, redact(m.group(0))))

        if sensitive_file or path.suffix.lower() in {".env", ".ini", ".cfg", ".conf"}:
            for token in re.findall(r"[\"']([A-Za-z0-9+/=_\-\.]{24,})[\"']", line):
                if shannon_entropy(token) >= ENTROPY_THRESHOLD:
                    findings.append(Finding(str(path), lineno, "high-entropy-string", "medium", redact(token)))
            for raw in re.findall(r"(?i)[A-Z0-9_]{3,}\s*=\s*([A-Za-z0-9+/=_\-\.]{24,})\s*$", line):
                if shannon_entropy(raw) >= ENTROPY_THRESHOLD:
                    findings.append(Finding(str(path), lineno, "high-entropy-string", "medium", redact(raw)))
    return findings


def redact(value: str, keep: int = 4) -> str:
    """Never echo a match in full: show the shape, not the value."""
    value = value.strip()
    if len(value) <= keep * 2:
        return value[:keep] + "\u2026"
    return f"{value[:keep]}\u2026{value[-2:]}({len(value)} chars)"


def main() -> int:
    ap = argparse.ArgumentParser(description="Security scan for a member repository.")
    ap.add_argument("--path", nargs="+", default=["."], help="files or directories to scan")
    ap.add_argument("--json", action="store_true", help="print machine readable output")
    ap.add_argument("--quiet", action="store_true", help="print nothing when clean")
    args = ap.parse_args()

    files = iter_files(args.path)
    findings: list[Finding] = []
    for f in files:
        findings.extend(scan_file(f))

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 3), f.path, f.line))
    highs = [f for f in findings if f.severity == "high"]

    if args.json:
        print(json.dumps({"files_scanned": len(files), "findings": [asdict(f) for f in findings]}, indent=2))
    elif findings:
        print(f"Scanned {len(files)} files. {len(findings)} finding(s).")
        for f in findings:
            print(f"  {f.severity.upper():6} {f.rule:28} {f.path}:{f.line}  {f.detail}")
    elif not args.quiet:
        print(f"Scanned {len(files)} files. Nothing found.")

    return 1 if highs else 0


if __name__ == "__main__":
    sys.exit(main())
