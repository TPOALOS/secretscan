# Changelog

## 1.1.0

- New detectors: GitLab, npm, PyPI, SendGrid, Anthropic and OpenAI-style keys, Slack and Discord webhooks, JWTs,
  credentials in URLs
- `--baseline` / `--write-baseline` to adopt on existing projects (fingerprints contain no secrets)
- `--exclude GLOB` (repeatable)
- Findings in JSON now carry a `fingerprint`
- Installable (`pip install`, `secretscan` command), CI on Linux and macOS, Python 3.9 to 3.13

## 1.0.0

Initial release.
