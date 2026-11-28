"""Contract tests for qualification-only bootstrap preparation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_h4_isolated_bootstrap import ANCHOR, LOADER, MARKER, strip_startup


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.source = (Path(__file__).resolve().parents[2] /
                       "frontend/web/flutter_bootstrap.js").read_text(encoding="utf-8")
        self.suffix = self.source[self.source.index(ANCHOR):]
        self.prefix = "// generated Flutter code\n" + LOADER + "\n\n"
        self.compiled = self.prefix + self.suffix

    def test_preserve_prefix_remove_only_custom_suffix(self):
        self.assertEqual(strip_startup(self.compiled, self.source),
                         self.prefix + MARKER + "\n")

    def test_reject_compiled_drift(self):
        with self.assertRaises(AssertionError):
            strip_startup(self.compiled.replace("registerIaminaServiceWorker", "different"), self.source)

    def test_reject_duplicate_anchor(self):
        with self.assertRaises(AssertionError):
            strip_startup(self.compiled + self.suffix, self.source)

    def test_reject_missing_loader(self):
        with self.assertRaises(AssertionError):
            strip_startup(self.compiled.replace(LOADER, "other();"), self.source)

    def test_reject_unexpected_prefix_tail(self):
        with self.assertRaises(AssertionError):
            strip_startup(self.prefix + "unexpected();\n" + self.suffix, self.source)

    def test_reject_already_transformed(self):
        with self.assertRaises(AssertionError):
            strip_startup(strip_startup(self.compiled,self.source), self.source)


if __name__ == "__main__":
    unittest.main()
