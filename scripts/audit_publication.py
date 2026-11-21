#!/usr/bin/env python3
"""Audit the explicit public inventory; never open ignored private directories."""
import re
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"private", "vendor", "outputs", "work", "logs", "tmp", "temp",
             ".git", "__pycache__", ".venv", "venv", ".pytest_cache", ".idea", ".vscode"}


def inspect_publication(root):
    entries = (root / "PUBLISH_FILES").read_text(encoding="utf-8").splitlines()
    if not entries or len(entries) != len(set(entries)):
        return ["Invalid publication inventory."]
    problems = []
    for name in entries:
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name
                or ":" in name or any(part in SKIP_DIRS for part in relative.parts)):
            problems.append("Unsafe publication inventory entry.")
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            problems.append(f"Missing or unsafe public file: {name}")
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"Non-text public file: {name}")
            continue
        if b"\0" in raw or raw.startswith((b"MZ", b"PK\x03\x04", b"\x7fELF")):
            problems.append(f"Possible binary payload: {name}")
        path_patterns = [r"(?<![A-Za-z0-9])[A-Za-z]:" + r"[\\/]",
                         re.escape(chr(92)*2) + r"[A-Za-z0-9_.-]+" + re.escape(chr(92)),
                         "/" + r"(?:Users|home)/"]
        if any(re.search(pattern, text) for pattern in path_patterns):
            problems.append(f"Possible absolute personal path: {name}")
        if re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
            problems.append(f"Review email-like text: {name}")
        credential_patterns = [r"gh[pousr]_[A-Za-z0-9]{20,}",
                               r"github_pat_[A-Za-z0-9_]{20,}",
                               "-----" + r"BEGIN [A-Z ]*PRIVATE KEY-----"]
        if any(re.search(pattern, text) for pattern in credential_patterns):
            problems.append(f"Possible credential: {name}")
    # Inspect filenames only outside the public inventory; never read private data.
    def walk(folder):
        for item in folder.iterdir():
            if item.is_symlink():
                problems.append("Unexpected symbolic link.")
            elif item.is_dir():
                if item.name not in SKIP_DIRS:
                    walk(item)
            elif item.relative_to(root).as_posix() not in entries:
                problems.append("Unexpected file outside publication inventory.")
    walk(root)
    # Do not inspect an enclosing workspace's repository by accident.
    if (root / ".git").exists():
        try:
            env = os.environ.copy()
            for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
                env.pop(key, None)
            tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                     check=True, capture_output=True, env=env).stdout.decode("utf-8").split("\0")
            if any(name and name not in entries for name in tracked):
                problems.append("Git tracks files outside the public inventory.")
        except (OSError, subprocess.CalledProcessError, UnicodeError):
            problems.append("Could not inspect local Git index.")
    return problems


def main():
    try:
        problems = inspect_publication(ROOT)
    except OSError:
        print("Publication audit could not read the public inventory.")
        return 2
    if problems:
        for problem in problems:
            print(problem)
        return 1
    print("PASS: explicit public inventory contains text files only; automated path, credential and inventory checks passed.")
    print("Manual review is still required for device identifiers and secrets in arbitrary text; Git history is not audited.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
