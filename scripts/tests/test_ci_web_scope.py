import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "ci_web_scope", Path(__file__).resolve().parents[1] / "ci_web_scope.py"
)
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


def full(diff, draft=True, force=False):
    return scope.requires_full(diff, is_draft=draft, force_full=force)


class WebScopeTests(unittest.TestCase):
    def test_draft_docs_and_backend_tests_only(self):
        self.assertFalse(full(b"M\0docs/README.md\0A\0backend/core/tests/test_example.py\0"))

    def test_non_draft_and_forced_never_defer(self):
        diff = b"M\0docs/README.md\0"
        self.assertTrue(full(diff, draft=False))
        self.assertTrue(full(diff, force=True))

    def test_product_and_unknown_paths_full_even_with_docs(self):
        for path in (
            b"frontend/lib/main.dart", b"frontend/test/widget_test.dart",
            b"frontend/web/index.html", b"frontend/pubspec.lock",
            b"backend/core/api/v1/auth.py", b"backend/core/migrations/0001.py",
            b"backend/core/tests/conftest.py", b"backend/requirements.txt",
            b".github/workflows/rehome-smoke.yml", b"scripts/ci_web_scope.py",
            b"vercel.json", b"docs/unknown.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(full(b"M\0docs/README.md\0M\0" + path + b"\0"))

    def test_empty_malformed_or_ambiguous_diff_is_full(self):
        for diff in (
            b"", b"M\0", b"M\0docs/README.md", b"D\0docs/README.md\0",
            b"T\0docs/README.md\0", b"R100\0docs/a.md\0docs/b.md\0",
            b"M\0docs/../secret.md\0", b"M\0docs/\xff.md\0",
        ):
            with self.subTest(diff=diff):
                self.assertTrue(full(diff))
