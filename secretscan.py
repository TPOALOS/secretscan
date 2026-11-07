#!/usr/bin/env python3
"""secretscan - find leaked secrets in files or staged git changes.

Standard library only. Exit code 0 = clean, 1 = findings, 2 = usage error.
Matches are always redacted in the output.
"""
import argparse
import json
import math
import os
import re
import subprocess
import sys

__version__ = "1.0.0"

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
MAX_BYTES = 1_000_000
IGNORE_MARK = "secretscan:ignore"

PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    ("generic-assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]
QUOTED = re.compile(r"['\"]([A-Za-z0-9+/=_-]{24,})['\"]")
ENTROPY_THRESHOLD = 4.5
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxxx|<.*>|\$\{|dummy")


def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(s):
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * 6 + s[-2:]


def scan_text(text, path="<text>"):
    """Return a list of finding dicts for the given text."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        hit_spans = []
        for name, rx in PATTERNS:
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if name == "generic-assignment" and PLACEHOLDER.search(value):
                    continue
                findings.append({"file": path, "line": lineno, "rule": name,
                                 "match": redact(value)})
                hit_spans.append(m.span())
        for m in QUOTED.finditer(line):
            if any(a <= m.start() < b for a, b in hit_spans):
                continue
            value = m.group(1)
            if PLACEHOLDER.search(value):
                continue
            if entropy(value) >= ENTROPY_THRESHOLD:
                findings.append({"file": path, "line": lineno, "rule": "high-entropy",
                                 "match": redact(value)})
    return findings


def is_binary(data):
    return b"\x00" in data[:4096]


def scan_file(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    if is_binary(data):
        return []
    return scan_text(data.decode("utf-8", errors="replace"), path)


def walk(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                yield os.path.join(root, f)


def staged_findings():
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
                         capture_output=True, check=True).stdout
    findings = []
    for name in filter(None, out.decode().split("\0")):
        blob = subprocess.run(["git", "show", ":" + name], capture_output=True)
        if blob.returncode != 0 or len(blob.stdout) > MAX_BYTES or is_binary(blob.stdout):
            continue
        findings += scan_text(blob.stdout.decode("utf-8", errors="replace"), name)
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan for leaked secrets (values are redacted).")
    ap.add_argument("paths", nargs="*", help="files or directories (default: .)")
    ap.add_argument("--staged", action="store_true", help="scan staged git changes")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        if args.staged:
            findings = staged_findings()
        else:
            findings = []
            for f in walk(args.paths or ["."]):
                findings += scan_file(f)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print("secretscan: error: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print("%s:%d: [%s] %s" % (f["file"], f["line"], f["rule"], f["match"]))
        print("secretscan: %d finding(s)" % len(findings), file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
