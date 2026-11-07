# secretscan

A small, dependency-free (standard library only) scanner that finds leaked secrets
in files or staged git changes. Defensive tool: it only reads, and it never prints
full secret values.

## Usage

```bash
python3 secretscan.py [paths ...]     # default: current directory
python3 secretscan.py --staged        # scan what is staged for commit
python3 secretscan.py --json src/     # machine-readable output
```

Exit codes: `0` clean, `1` findings, `2` usage/git error.

Use as a pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
python3 /path/to/secretscan.py --staged
```

## What it detects

AWS access key IDs, GitHub tokens, Slack tokens, Google API keys, Stripe live keys,
PEM private key headers, `password/secret/token/api_key = "..."` assignments, and
high-entropy quoted strings. Matches are redacted (`AKIA******OP`).

Add `secretscan:ignore` in a comment on a line to suppress a known false positive.
Binary files, files over 1 MB, and `.git`, `node_modules`, virtualenv dirs are skipped.

## Tests

```bash
python3 -m unittest -v
```

## Limits

Heuristic scanner: it can miss secrets and can raise false positives. Treat it as
one layer, and rotate any credential that was ever committed.

## License

MIT (c) TPOALOS
