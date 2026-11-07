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


if __name__ == "__main__":
    unittest.main()
