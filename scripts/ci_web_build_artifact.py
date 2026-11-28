"""Same-run synthetic Web artifact. No secrets, no patient data, no cache of builds."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

SDK = "cc0734ac716fbb8b90f3f9db8020958b1553afa7"
INTEGRATION = {"phase1/integration-web", "phase1/ci-opt1-benchmark", "phase2/d1-d5-convergence"}
GUEST = "phase1/d2-guest"
APP = Path("frontend/build/web")
COMMON = ["--release", "--no-pub", "--no-web-resources-cdn"]
CUTOVER = "--dart-define=IAMINA_D1_CUTOVER_CANDIDATE=true --dart-define=IAMINA_D2_GUEST_CANDIDATE=false --dart-define=IAMINA_REMOTE_ACCOUNT_SIGN_IN=true --dart-define=IAMINA_REMOTE_ACCOUNT_ENROLLMENT=true --dart-define=API_BASE_URL=http://127.0.0.1:8000".split()
GUEST_FLAGS = "--dart-define=IAMINA_D2_GUEST_CANDIDATE=true --dart-define=API_BASE_URL=http://127.0.0.1:8000".split()

def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def expected(sha, branch):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or branch not in INTEGRATION | {GUEST}:
        raise ValueError("invalid source or branch")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != sha:
        raise ValueError("checkout SHA mismatch")
    return {"source": sha, "sdk": SDK, "branch": branch,
            "app": COMMON + (CUTOVER if branch in INTEGRATION else GUEST_FLAGS),
            "runtime": COMMON + ["--target=tool/d1_runtime_probe.dart"] if branch in INTEGRATION else None}

def inventory(root):
    result = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            raise ValueError("non-regular artifact entry")
        if p.is_file():
            result[p.relative_to(root).as_posix()] = digest(p)
    return result

def validate(root, spec):
    for target in ("app", "runtime") if spec["runtime"] else ("app",):
        p = root / target
        if (p / "main.dart.js").stat().st_size <= 1000:
            raise ValueError("missing build")
        if target == "runtime" and not (p / "sqlite3.wasm").is_file():
            raise ValueError("missing runtime wasm")
    if not spec["runtime"] and (root / "runtime").exists():
        raise ValueError("unexpected runtime")

def pack(bundle, spec, runtime):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copytree(APP, root / "app", symlinks=True)
        if spec["runtime"]:
            shutil.copytree(runtime, root / "runtime", symlinks=True)
        validate(root, spec)
        manifest = {"spec": spec, "files": inventory(root)}
        (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
        with tarfile.open(bundle, "w:gz", compresslevel=3) as tar:
            for p in sorted(root.iterdir()):
                tar.add(p, arcname=p.name)
    sha = digest(bundle)
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"bundle_sha={sha}\n")
    print(f"CI_WEB_BUILD_PACKED source={spec['source']} digest={sha} bytes={bundle.stat().st_size}")

def unpack(bundle, spec, sha, runtime):
    if not re.fullmatch(r"[0-9a-f]{64}", sha) or digest(bundle) != sha:
        raise ValueError("artifact digest mismatch")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with tarfile.open(bundle, "r:gz") as tar:
            seen = set()
            for m in tar.getmembers():
                p = PurePosixPath(m.name)
                if (p.is_absolute() or ".." in p.parts or m.name in seen
                    or not (m.isfile() or m.isdir()) or not p.parts
                    or p.parts[0] not in {"app", "runtime", "manifest.json"}):
                    raise ValueError("unsafe artifact member")
                seen.add(m.name)
            tar.extractall(root, filter="data")
        manifest = json.loads((root / "manifest.json").read_text())
        (root / "manifest.json").unlink()
        if manifest != {"spec": spec, "files": inventory(root)}:
            raise ValueError("artifact manifest mismatch")
        validate(root, spec)
        if APP.exists() or runtime.exists():
            raise ValueError("refusing to overwrite a local build")
        APP.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(root / "app", APP)
        if spec["runtime"]:
            shutil.copytree(root / "runtime", runtime)
    print(f"CI_WEB_BUILD_VERIFIED source={spec['source']} digest={sha}")

if __name__ == "__main__":
    mode, bundle, sha, branch, *args = sys.argv[1:]
    spec = expected(sha, branch)
    if mode == "pack" and len(args) == 1:
        pack(Path(bundle), spec, Path(args[0]))
    elif mode == "unpack" and len(args) == 2:
        unpack(Path(bundle), spec, args[0], Path(args[1]))
    else:
        raise ValueError("invalid arguments")
