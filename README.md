# secretscan

A small, dependency-free (standard library only) scanner that finds leaked secrets in files or staged git
changes. Defensive tool: it only reads, and it never prints full secret values.

```
$ secretscan src/
src/settings.py:12: [aws-access-key-id] AKIA******OP
src/deploy.sh:4: [url-credentials] S3cr******rd
src/client.py:31: [high-entropy] q8Zk******4u
secretscan: 3 finding(s)
```

## Install and usage

```bash
pip install git+https://github.com/TPOALOS/secretscan     # or just copy secretscan.py
secretscan [paths ...]            # default: current directory
secretscan --staged               # scan what is staged for commit
secretscan --json src/            # machine-readable output
secretscan --exclude 'tests/*' --exclude '*.lock' .
```

Exit codes: `0` clean, `1` findings, `2` usage/git error.

### Pre-commit hook

```bash
#!/bin/sh
secretscan --staged
```

### Adopt it on an existing project (baselines)

An old repository will have findings you cannot fix today. Record them once, then fail only on **new** ones:

```bash
secretscan --write-baseline .secretscan-baseline.json .
secretscan --baseline .secretscan-baseline.json .      # exits 0 until something new appears
```

A baseline stores only a fingerprint per finding (a hash of the file, the rule, the *redacted* match and
its occurrence number). It contains no secret and does not depend on line numbers, so unrelated edits do not
bring old findings back. Rotate the credentials you baselined anyway.

## What it detects

AWS access key IDs, GitHub tokens (classic and fine-grained), GitLab tokens, Slack tokens and webhooks,
Discord webhooks, Google API keys, Stripe live keys, npm and PyPI tokens, SendGrid keys, Anthropic and
OpenAI-style API keys, JWTs, PEM private key headers, credentials inside URLs
(`postgres://user:pass@host`), `password/secret/token/api_key = "..."` assignments, and high-entropy quoted
strings. Matches are redacted (`AKIA******OP`). Obvious placeholders (`changeme`, `${VAR}`, `<your-key>`) are ignored.

Add `secretscan:ignore` in a comment on a line to suppress a known false positive.
Binary files, files over 1 MB, and `.git`, `node_modules`, virtualenv and build directories are skipped.

## Tests

```bash
python3 -m unittest -v
```

## Limits

Heuristic scanner: it can miss secrets and can raise false positives. Treat it as one layer, and rotate any
credential that was ever committed.

## License

MIT (c) TPOALOS
