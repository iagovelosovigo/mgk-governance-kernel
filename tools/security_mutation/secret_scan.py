#!/usr/bin/env python3
"""Deterministic secret scan for the MGK v0.3.0 candidate tree.

Replicates the v0.2.0 phase-11 secret-scan methodology against the current
working tree. Scans git-tracked files only, excluding campaign-artifact
directories (evidence/, redteam/, independent_exam/), and reports counts per
category. Exits non-zero (FAIL_CLOSED) if any category is non-zero.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXCLUDED_DIRS = {"evidence", "redteam", "independent_exam"}

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)
AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
OPENAI_STYLE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][^'\"\n]{4,}['\"]",
    re.IGNORECASE,
)
KEYLIKE_SUFFIX = re.compile(r"\.(?:pem|key|p12|pfx|keystore|env|jks)$", re.IGNORECASE)


def tracked_files() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    ).stdout
    files = []
    for raw in listing.split(b"\0"):
        if not raw:
            continue
        path = Path(raw.decode("utf-8", errors="replace"))
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        files.append(path)
    return files


def scan() -> dict:
    files = tracked_files()
    counts = {
        "private_key_blocks": 0,
        "aws_keys": 0,
        "github_tokens": 0,
        "openai_style": 0,
        "slack_tokens": 0,
        "google_api_keys": 0,
        "credential_assignments_in_source": 0,
        "secret_like_files": 0,
        "git_tracked_keylike_files": 0,
        "git_tracked_private_key_blocks": 0,
    }
    hits = {key: [] for key in counts}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for label, pattern in (
            ("private_key_blocks", PRIVATE_KEY_BLOCK),
            ("aws_keys", AWS_KEY),
            ("github_tokens", GITHUB_TOKEN),
            ("openai_style", OPENAI_STYLE),
            ("slack_tokens", SLACK_TOKEN),
            ("google_api_keys", GOOGLE_API_KEY),
            ("credential_assignments_in_source", CREDENTIAL_ASSIGNMENT),
        ):
            for match in pattern.finditer(text):
                counts[label] += 1
                hits[label].append(f"{path}:{match.start()}")
        if KEYLIKE_SUFFIX.search(str(path)):
            counts["secret_like_files"] += 1
            counts["git_tracked_keylike_files"] += 1
            hits["secret_like_files"].append(str(path))
            hits["git_tracked_keylike_files"].append(str(path))
    keylike_files = [p for p in files if KEYLIKE_SUFFIX.search(str(p))]
    counts["git_tracked_keylike_files"] = len(keylike_files)
    hits["git_tracked_keylike_files"] = [str(p) for p in keylike_files]
    git_grep = subprocess.run(
        ["git", "grep", "-I", "-l", "-E", "BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY"],
        capture_output=True,
        text=True,
    )
    if git_grep.returncode == 0:
        matches = [
            line
            for line in git_grep.stdout.splitlines()
            if not any(part in EXCLUDED_DIRS for part in Path(line).parts)
        ]
        counts["git_tracked_private_key_blocks"] = len(matches)
        hits["git_tracked_private_key_blocks"] = matches
    return {"counts": counts, "files_scanned": len(files), "hits": hits}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="output JSON path")
    parser.add_argument("--out-md", type=Path, help="optional Markdown report path")
    args = parser.parse_args()

    result = scan()
    counts = result["counts"]
    nonzero = {key: value for key, value in counts.items() if value != 0}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1) + "\n")

    if args.out_md:
        lines = [
            "# Phase 9 - Secret Scan (v0.3.0)",
            "",
            "Methodology: git-tracked files only, excluding evidence/, redteam/,",
            "independent_exam/. Patterns: PEM/OpenSSH/EC/DSA private-key blocks,",
            "AWS `AKIA...`, GitHub `ghp_...`, OpenAI-style `sk-...`, Slack `xox...`,",
            "Google `AIza...`, credential-assignment regexes, key-like file suffixes.",
            "",
            "| Category | Count |",
            "|---|---|",
        ]
        for label, value in counts.items():
            lines.append(f"| {label} | {value} |")
        lines.extend(["", "Result: " + ("CLEAN" if not nonzero else f"NONZERO {nonzero}"), ""])
        if nonzero:
            for label, matches in result["hits"].items():
                if matches:
                    lines.append(f"## {label}")
                    lines.extend(f"- `{match}`" for match in matches[:40])
        args.out_md.write_text("\n".join(lines) + "\n")

    if nonzero:
        print(json.dumps(nonzero, indent=1))
        print("FAIL_CLOSED: secret scan found non-zero categories")
        return 1
    print("SECRET_SCAN=CLEAN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())