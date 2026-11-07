import contextlib
import io
import json
import os
import tempfile
import unittest

import secretscan

# Fake secrets are assembled at runtime so this file itself stays clean.
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # secretscan:ignore
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


class ScanTextTests(unittest.TestCase):
    def rules(self, text):
        return {f["rule"] for f in secretscan.scan_text(text)}

    def test_aws(self):
        self.assertIn("aws-access-key-id", self.rules("key = %s" % AWS))

    def test_github(self):
        self.assertIn("github-token", self.rules("t=%s" % GH))

    def test_private_key(self):
        self.assertIn("private-key", self.rules(PEM))

    def test_generic_assignment(self):
        self.assertIn("generic-assignment", self.rules('password = "hunter2hunter2"'))  # secretscan:ignore

    def test_placeholder_ignored(self):
        self.assertEqual(self.rules('password = "your_password_here"'), set())

    def test_high_entropy(self):
        s = "q8Zk3vXp9LmW2tYbN7cRfH5jD1aGsE4u"  # secretscan:ignore
        self.assertIn("high-entropy", self.rules('x = "%s"' % s))

    def test_low_entropy_not_flagged(self):
        self.assertEqual(self.rules('x = "%s"' % ("a" * 30)), set())

    def test_ignore_marker(self):
        self.assertEqual(self.rules("k = %s  # secretscan:ignore" % AWS), set())

    def test_redaction(self):
        f = secretscan.scan_text("k = %s" % AWS)[0]
        self.assertNotIn(AWS, f["match"])
        self.assertTrue(f["match"].startswith("AKIA"))

    def test_clean(self):
        self.assertEqual(secretscan.scan_text("print('hello world')"), [])


class FileTests(unittest.TestCase):
    def test_walk_skips_git_and_binary(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "c"), "w") as fh:
                fh.write(AWS)
            with open(os.path.join(d, "bin"), "wb") as fh:
                fh.write(b"\x00" + AWS.encode())
            with open(os.path.join(d, "a.txt"), "w") as fh:
                fh.write("x\n" + AWS + "\n")
            found = [f for p in secretscan.walk([d]) for f in secretscan.scan_file(p)]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["line"], 2)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w") as fh:
                fh.write("hello")
            self.assertEqual(secretscan.main([p]), 0)
            with open(p, "w") as fh:
                fh.write(AWS)
            self.assertEqual(secretscan.main([p]), 1)


def tok(*parts):
    return "".join(parts)


NEW_TOKENS = {
    "gitlab-token": tok("glpat-", "abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "npm-token": tok("npm_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),  # secretscan:ignore
    "sendgrid-key": tok("SG.", "a" * 22, ".", "b" * 43),
    "anthropic-key": tok("sk-ant-", "api03-abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "openai-key": tok("sk-", "proj-", "abcdEFGH1234ijklMNOP5678qrstUVWX"),  # secretscan:ignore
    "slack-webhook": tok("https://hooks.slack", ".com/services/T01ABCDEF/B02GHIJKL/", "x" * 24),
    "discord-webhook": tok("https://discord", ".com/api/webhooks/", "1" * 18, "/", "a" * 60),
    "jwt": tok("eyJ", "hbGciOiJIUzI1NiJ9", ".eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".", "abcdEFGH1234ijkl"),
    "url-credentials": tok("postgres://", "admin:", "S3cr3tPassw0rd", "@db.internal:5432/app"),
}


class NewDetectorTests(unittest.TestCase):
    def test_each_new_detector(self):
        for rule, value in NEW_TOKENS.items():
            with self.subTest(rule=rule):
                rules = {f["rule"] for f in secretscan.scan_text("x = %s" % value)}
                self.assertIn(rule, rules)

    def test_anthropic_key_not_also_reported_as_openai(self):
        rules = [f["rule"] for f in secretscan.scan_text(NEW_TOKENS["anthropic-key"])]
        self.assertIn("anthropic-key", rules)
        self.assertNotIn("openai-key", rules)

    def test_none_of_the_new_values_leak_in_output(self):
        for rule, value in NEW_TOKENS.items():
            for f in secretscan.scan_text(value):
                self.assertNotIn(value, json.dumps(f))

    def test_url_without_password_or_with_placeholder_is_fine(self):
        for text in ("https://example.com/path", "git://host/repo", "postgres://user:password@localhost/db",
                     "postgres://user:${DB_PASS}@localhost/db", "https://user@host.com/x"):
            self.assertEqual(secretscan.scan_text(text), [], text)

    def test_short_look_alikes_not_flagged(self):
        for text in ("sk-short", "glpat-abc", "npm_abc", "eyJabc.eyJdef.ghi"):
            self.assertEqual(secretscan.scan_text(text), [], text)


class FingerprintTests(unittest.TestCase):
    def test_stable_and_line_independent(self):
        a = secretscan.assign_fingerprints(secretscan.scan_text("k = %s" % AWS, "f.py"))
        b = secretscan.assign_fingerprints(secretscan.scan_text("\n\n# moved\nk = %s" % AWS, "f.py"))
        self.assertEqual(a[0]["fingerprint"], b[0]["fingerprint"])

    def test_same_secret_twice_gets_distinct_ids(self):
        f = secretscan.assign_fingerprints(secretscan.scan_text("%s\n%s" % (AWS, AWS), "f.py"))
        self.assertEqual(len({x["fingerprint"] for x in f}), 2)

    def test_fingerprint_depends_on_file_and_rule(self):
        a = secretscan.assign_fingerprints(secretscan.scan_text(AWS, "a.py"))[0]["fingerprint"]
        b = secretscan.assign_fingerprints(secretscan.scan_text(AWS, "b.py"))[0]["fingerprint"]
        self.assertNotEqual(a, b)

    def test_fingerprint_never_contains_the_secret(self):
        f = secretscan.assign_fingerprints(secretscan.scan_text(AWS, "a.py"))[0]
        self.assertNotIn(AWS, json.dumps(f))
        self.assertEqual(len(f["fingerprint"]), 16)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = secretscan.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class BaselineAndExcludeTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = self._t.name
        self.f = os.path.join(self.d, "a.txt")
        with open(self.f, "w") as fh:
            fh.write("key = %s\n" % AWS)
        self.base = os.path.join(self.d, "base.json")

    def tearDown(self):
        self._t.cleanup()

    def test_write_then_use_baseline(self):
        code, _, err = run_main(self.f, "--write-baseline", self.base)
        self.assertEqual(code, 0)
        self.assertIn("1 finding", err)
        self.assertEqual(run_main(self.f)[0], 1)
        code, _, err = run_main(self.f, "--baseline", self.base)
        self.assertEqual(code, 0)
        self.assertIn("1 suppressed", err)

    def test_baseline_does_not_hide_new_secrets(self):
        run_main(self.f, "--write-baseline", self.base)
        with open(self.f, "a") as fh:
            fh.write("other = %s\n" % tok("AKIA", "QRSTUVWXYZ012345"))
        code, out, _ = run_main(self.f, "--baseline", self.base)
        self.assertEqual(code, 1)
        self.assertEqual(len(out.strip().splitlines()), 1)

    def test_baseline_file_holds_no_secret(self):
        run_main(self.f, "--write-baseline", self.base)
        with open(self.base) as fh:
            self.assertNotIn(AWS, fh.read())

    def test_bad_baseline_is_a_usage_error(self):
        with open(self.base, "w") as fh:
            fh.write('{"fingerprints": [1, 2]}')
        self.assertEqual(run_main(self.f, "--baseline", self.base)[0], 2)
        self.assertEqual(run_main(self.f, "--baseline", os.path.join(self.d, "missing.json"))[0], 2)

    def test_exclude_by_glob_and_basename(self):
        self.assertEqual(run_main(self.d, "--exclude", "*.txt")[0], 0)
        self.assertEqual(run_main(self.d, "--exclude", "a.txt")[0], 0)
        self.assertEqual(run_main(self.d, "--exclude", "*.md")[0], 1)

    def test_json_output_includes_fingerprint(self):
        _, out, _ = run_main(self.f, "--json")
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertIn("fingerprint", data[0])


if __name__ == "__main__":
    unittest.main()
