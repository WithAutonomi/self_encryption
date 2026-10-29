#!/usr/bin/env python3
"""Repository-local ADR governance checks.

Enforces:
- ADR files live under docs/adr/ and use ADR-NNNN-short-title.md.
- Required sections exist.
- Status is present and from the allowed lifecycle.
- Accepted ADRs are immutable after acceptance. If a decision changes, create a
  new ADR and supersede by reference rather than editing the Accepted ADR.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ADR_DIR = Path("docs/adr")
ALLOWED_STATUSES = {"Proposed", "Accepted", "Superseded", "Deprecated", "Rejected"}
REQUIRED_SECTIONS = ["Context", "Decision", "Consequences", "Validation"]
FILENAME_RE = re.compile(r"^ADR-\d{4}-[a-z0-9][a-z0-9-]*\.md$")
STATUS_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?.*?Status.*?:\s*(.+?)\s*$")


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()


def status_of(text: str) -> str | None:
    m = STATUS_RE.search(text)
    return m.group(1).strip().strip("*").strip() if m else None


def base_ref() -> str | None:
    ref = os.environ.get("GITHUB_BASE_REF")
    if ref:
        return f"origin/{ref}"
    # On push, compare against first parent where available.
    try:
        return run(["git", "rev-parse", "HEAD^1"])
    except Exception:
        return None


def changed_files_against_base(base: str) -> list[str]:
    try:
        return run(["git", "diff", "--name-only", f"{base}...HEAD"]).splitlines()
    except Exception:
        try:
            return run(["git", "diff", "--name-only", f"{base}", "HEAD"]).splitlines()
        except Exception:
            return []


def file_at(ref: str, path: str) -> str | None:
    try:
        return run(["git", "show", f"{ref}:{path}"])
    except Exception:
        return None


def main() -> int:
    errors: list[str] = []
    if not ADR_DIR.exists():
        print("No docs/adr directory; nothing to validate.")
        return 0

    adr_files = sorted(p for p in ADR_DIR.glob("ADR-*.md") if p.is_file())
    base = base_ref()
    changed = changed_files_against_base(base) if base else []
    changed_adr_paths = {Path(name) for name in changed if name.startswith("docs/adr/ADR-") and name.endswith(".md")}

    # Grandfather legacy ADRs when first installing governance. Enforce full
    # structure on ADRs touched by this PR, while still checking duplicate
    # numbers across the full directory.
    files_to_validate = sorted((Path(p) for p in changed_adr_paths if Path(p).exists()), key=str) if base else adr_files

    seen_numbers: dict[str, Path] = {}
    for path in adr_files:
        number = path.name.split("-", 2)[1] if "-" in path.name else path.name
        if number in seen_numbers:
            errors.append(f"{path}: duplicate ADR number also used by {seen_numbers[number]}")
        seen_numbers[number] = path

    for path in files_to_validate:
        if not FILENAME_RE.match(path.name):
            errors.append(f"{path}: filename must match ADR-NNNN-short-title.md")
        text = path.read_text(encoding="utf-8")
        st = status_of(text)
        if not st:
            errors.append(f"{path}: missing Status")
        elif st not in ALLOWED_STATUSES:
            errors.append(f"{path}: invalid Status '{st}' (allowed: {', '.join(sorted(ALLOWED_STATUSES))})")
        for section in REQUIRED_SECTIONS:
            if not re.search(rf"(?im)^##\s+{re.escape(section)}\b", text):
                errors.append(f"{path}: missing required section '## {section}'")

    if base:
        for name in changed:
            if not (name.startswith("docs/adr/ADR-") and name.endswith(".md")):
                continue
            old = file_at(base, name)
            if old is None:
                continue
            old_status = status_of(old)
            if old_status == "Accepted":
                errors.append(
                    f"{name}: Accepted ADRs are immutable. Create a new superseding ADR instead of editing this file."
                )

    if errors:
        print("ADR governance failed:")
        for e in errors:
            print(f"- {e}")
        return 1
    print(f"ADR governance passed ({len(adr_files)} ADR file(s) checked).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
