"""Conservative draft-only CI scheduling; never evidence of WebKit PASS."""
import os
import re
import subprocess


def requires_full(diff: bytes, *, is_draft: bool, force_full: bool) -> bool:
    if not is_draft or force_full:
        return True
    # git diff --name-status -z --no-renames yields status/path pairs.
    if not diff or not diff.endswith(b"\0"):
        return True
    fields = diff[:-1].split(b"\0")
    if len(fields) % 2:
        return True
    for status, raw_path in zip(fields[::2], fields[1::2]):
        if status not in (b"A", b"M"):
            return True
        try:
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeError:
            return True
        parts = path.split("/")
        if any(part in ("", ".", "..") for part in parts):
            return True
        # Only documentation and backend test cases can be deferred.
        # No product code, frontend assets/tests, fixtures, test tooling,
        # migrations, workflows, dependencies, or unknown files.
        docs = (
            len(parts) >= 2 and parts[0] == "docs"
            and parts[-1].endswith(".md")
        )
        backend_test = (
            len(parts) >= 4 and parts[0] == "backend"
            and parts[-2] == "tests"
            and re.fullmatch(r"test_[a-zA-Z0-9_]+\.py", parts[-1]) is not None
        )
        if not (docs or backend_test):
            return True
    return False


def main() -> None:
    full = True
    try:
        base, head = os.environ["BASE_SHA"], os.environ["EXPECTED_SHA"]
        if not all(re.fullmatch(r"[0-9a-f]{40}", v) for v in (base, head)):
            raise ValueError("Invalid commit SHA")
        diff = subprocess.check_output(
            ["git", "diff", "--name-status", "-z", "--no-renames",
             f"{base}...{head}", "--"], timeout=30,
        )
        full = requires_full(
            diff, is_draft=os.environ.get("IS_DRAFT") == "true",
            force_full=os.environ.get("FORCE_FULL") != "false",
        )
    except (KeyError, ValueError, OSError, subprocess.SubprocessError):
        # Missing history, malformed SHA or unknown scope cannot defer proof.
        full = True
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write(f"full={str(full).lower()}\n")
    print("WEB_SCOPE_FULL" if full else "WEB_SCOPE_DRAFT_FAST_MACOS_NOT_RUN")


if __name__ == "__main__":
    main()
