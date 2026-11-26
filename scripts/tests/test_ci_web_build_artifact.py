import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location(
    "ci_web_build_artifact", Path(__file__).resolve().parents[1] / "ci_web_build_artifact.py"
)
artifact = importlib.util.module_from_spec(s)
s.loader.exec_module(artifact)
SHA = "1" * 40
BRANCH = "phase1/ci-opt1-benchmark"


class WebBuildArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = self.root / "app-src"
        self.runtime = self.root / "runtime-src"
        self.bundle = self.root / "bundle.tar.gz"
        self.output = self.root / "github-output"
        for target in (self.app, self.runtime):
            target.mkdir()
            (target / "main.dart.js").write_bytes(b"a" * 1001)
        (self.runtime / "sqlite3.wasm").write_bytes(b"synthetic")
        (self.app / ".hidden").write_text("synthetic")
        with patch.object(artifact.subprocess, "check_output", return_value=SHA):
            self.spec = artifact.expected(SHA, BRANCH)
        with patch.object(artifact, "APP", self.app), patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.output)}):
            artifact.pack(self.bundle, self.spec, self.runtime)
        self.sha = artifact.digest(self.bundle)

    def unpack(self, spec=None, digest=None):
        dest_app = self.root / "app-dest"
        dest_runtime = self.root / "runtime-dest"
        with patch.object(artifact, "APP", dest_app):
            artifact.unpack(self.bundle, spec or self.spec, digest or self.sha, dest_runtime)
        return dest_app, dest_runtime

    def test_round_trip_and_hidden_file(self):
        app, runtime = self.unpack()
        self.assertEqual(artifact.inventory(app), artifact.inventory(self.app))
        self.assertEqual(artifact.inventory(runtime), artifact.inventory(self.runtime))
        self.assertEqual(self.output.read_text(), f"bundle_sha={self.sha}\n")

    def test_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.unpack(digest="0" * 64)

    def test_wrong_source_or_flags(self):
        for spec in ({**self.spec, "source": "2" * 40}, {**self.spec, "app": ["wrong"]}):
            with self.assertRaisesRegex(ValueError, "manifest mismatch"):
                self.unpack(spec=spec)

    def test_no_overwrite(self):
        self.unpack()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.unpack()

    def test_reject_path_traversal_even_with_matching_digest(self):
        with tarfile.open(self.bundle, "w:gz") as tar:
            data = b"bad"
            member = tarfile.TarInfo("../escaped")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "unsafe artifact"):
            self.unpack(digest=artifact.digest(self.bundle))

    def test_unknown_branch_and_wrong_checkout(self):
        with patch.object(artifact.subprocess, "check_output", return_value="2" * 40):
            with self.assertRaisesRegex(ValueError, "checkout SHA"):
                artifact.expected(SHA, BRANCH)
            with self.assertRaisesRegex(ValueError, "invalid source"):
                artifact.expected(SHA, "untrusted")
