#!/usr/bin/env python3
"""secretscan - find leaked secrets in files or staged git changes.

Standard library only. Exit code 0 = clean, 1 = findings, 2 = usage error.
Matches are always redacted in the output.
"""
import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys

__version__ = "1.1.0"

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
             ".ruff_cache", "dist", "build", ".eggs"}
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
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}")),
    ("discord-webhook", re.compile(
        r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{50,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@'\"/]{6,})@[^\s'\"]+")),
    ("generic-assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]
QUOTED = re.compile(r"['\"]([A-Za-z0-9+/=_-]{24,})['\"]")
ENTROPY_THRESHOLD = 4.5
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxxx|<.*>|\$\{|dummy|^(?:pass(?:word)?|secret|\*+)$")
WEAK_CHECKED = ("generic-assignment", "url-credentials")


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
                if name in WEAK_CHECKED and PLACEHOLDER.search(value):
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


def fingerprint(path, rule, match, index):
    """Stable id for a finding. Built from the redacted match, never the secret itself,
    and independent of line numbers so unrelated edits do not resurface old findings."""
    key = "%s|%s|%s|%d" % (os.path.normpath(path).replace(os.sep, "/"), rule, match, index)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def assign_fingerprints(findings):
    seen = {}
    for f in findings:
        k = (f["file"], f["rule"], f["match"])
        seen[k] = seen.get(k, 0) + 1
        f["fingerprint"] = fingerprint(f["file"], f["rule"], f["match"], seen[k])
    return findings


def load_baseline(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("fingerprints", []) if isinstance(data, dict) else data
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("baseline must be a JSON list of fingerprints")
    return set(items)


def excluded(path, patterns):
    norm = os.path.normpath(path).replace(os.sep, "/")
    base = os.path.basename(norm)
    return any(fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(base, p) for p in patterns)


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
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip files matching this glob (repeatable), e.g. 'tests/*' or '*.lock'")
    ap.add_argument("--baseline", metavar="FILE", help="ignore findings already listed in this baseline")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="record all current findings as the baseline and exit 0")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        if args.staged:
            findings = [f for f in staged_findings() if not excluded(f["file"], args.exclude)]
        else:
            findings = []
            for f in walk(args.paths or ["."]):
                if not excluded(f, args.exclude):
                    findings += scan_file(f)
        baseline = load_baseline(args.baseline) if args.baseline else set()
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError, OSError) as exc:
        print("secretscan: error: %s" % exc, file=sys.stderr)
        return 2

    assign_fingerprints(findings)
    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"fingerprints": sorted(f["fingerprint"] for f in findings)}, fh, indent=2)
            fh.write("\n")
        print("secretscan: baseline of %d finding(s) written to %s" % (len(findings), args.write_baseline),
              file=sys.stderr)
        return 0
    suppressed = [f for f in findings if f["fingerprint"] in baseline]
    findings = [f for f in findings if f["fingerprint"] not in baseline]

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print("%s:%d: [%s] %s" % (f["file"], f["line"], f["rule"], f["match"]))
        note = " (%d suppressed by baseline)" % len(suppressed) if suppressed else ""
        print("secretscan: %d finding(s)%s" % (len(findings), note), file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
