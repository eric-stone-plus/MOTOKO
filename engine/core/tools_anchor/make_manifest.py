#!/usr/bin/env python3
"""make_manifest.py — anchor the tools/ tree so any host can rebuild it.

The toolbox is deliberately unversioned in git (200k files, upstream
checkouts). Reproducibility therefore hangs on this manifest:

* git-type entries are anchored by (origin remote, branch, HEAD commit,
  dirty-file names) — `provision.sh restore` can rebuild them exactly;
* binary anchors are sha256 + size — drift is detectable, restoration is
  a restore-from-backup or a re-download through install.sh;
* big source trees (web/) record git anchors where present and metadata
  otherwise. NO file contents are hashed there: the manifest must stay
  cheap and shareable.

Usage:  python3 make_manifest.py           # (re)generate manifest.json
        python3 make_manifest.py --verify  # check tree against manifest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent / "manifest.json"
SCHEMA = "motoko-tools-manifest/1"


def _git(path: Path) -> dict | None:
    """Anchor a git checkout: origin, branch, HEAD, dirty-file NAMES only."""
    if not (path / ".git").exists():
        return None

    def g(*args: str) -> str:
        r = subprocess.run(["git", "-C", str(path), *args],
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip()

    origin = g("remote", "get-url", "origin") or None
    branch = g("branch", "--show-current") or None
    head = g("rev-parse", "HEAD") or None
    dirty = [line.split(maxsplit=1)[-1]
             for line in g("status", "--porcelain").splitlines()]
    return {"type": "git", "origin": origin, "branch": branch,
            "head": head, "dirty_files": dirty,
            "no_remote_note": None if origin else
            "local-only checkout — migrate manually"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _bin_dir(path: Path) -> dict:
    binaries = {}
    for p in sorted(path.iterdir()):
        if p.is_file() and os.access(p, os.X_OK) and not p.name.endswith((".sh", ".md")):
            binaries[p.name] = {"sha256": _sha256(p),
                                "bytes": p.stat().st_size}
    return {"type": "bin-dir", "binaries": binaries,
            "helpers": sorted(p.name for p in path.iterdir()
                              if p.name.endswith((".sh", ".md")))}


def _dir_stats(path: Path) -> dict:
    files = 0
    total = 0
    for root, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.stat(os.path.join(root, n)).st_size
                files += 1
            except OSError:
                pass
    return {"files": files, "bytes": total}


def scan_entry(path: Path) -> dict:
    git = _git(path)
    if git:
        return git
    if path.name == "bin":
        return _bin_dir(path)
    if path.name == "kali":
        return {"type": "containerfile",
                "files": {p.name: _sha256(p) for p in sorted(path.iterdir())
                          if p.is_file()}}
    if path.name == "nuclei":
        binary = path / "nuclei"
        tdir = path / "templates"
        out: dict = {"type": "nuclei",
                     "nuclei_sha256": _sha256(binary) if binary.exists() else None}
        if tdir.is_dir():
            n = sum(1 for _ in tdir.rglob("*.yaml"))
            out["template_yaml_count"] = n
        return out
    if path.name == "sliver":
        return {"type": "binaries",
                "files": {p.name: {"sha256": _sha256(p), "bytes": p.stat().st_size}
                          for p in sorted(path.iterdir()) if p.is_file()}}
    # web/ and anything else: one level down, git anchors + dir stats only
    children = {}
    for sub in sorted(path.iterdir()):
        if sub.is_dir():
            g = _git(sub)
            children[sub.name] = g if g else {"type": "dir", **_dir_stats(sub)}
        else:
            children[sub.name] = {"type": "file", "bytes": sub.stat().st_size}
    return {"type": "tree", "children": children}


def generate() -> dict:
    root = Path(os.environ.get("TOOLS_DIR", Path(__file__).resolve().parent.parent.parent.parent / "tools"))
    entries = {}
    for p in sorted(root.iterdir()):
        if p.name in ("manifest.json", "make_manifest.py", "provision.sh",
                      "README.md") or p.name.startswith("."):
            continue
        if p.is_dir():
            entries[p.name] = scan_entry(p)
    return {"schema": SCHEMA,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "entries": entries}


def verify(manifest: dict) -> list[str]:
    """Re-scan and diff against the manifest. Cheap checks only: git heads
    and bin-dir hashes are re-computed; trees are presence-checked."""
    problems: list[str] = []
    current = generate()
    for name, old in manifest["entries"].items():
        new = current["entries"].get(name)
        if new is None:
            problems.append(f"{name}: MISSING from tools/")
            continue
        if old.get("type") == "git":
            if old.get("head") != new.get("head"):
                problems.append(f"{name}: HEAD moved {old.get('head', '?')[:9]} "
                                f"-> {new.get('head', '?')[:9]}")
            if old.get("dirty_files") != new.get("dirty_files"):
                problems.append(f"{name}: dirty-file set changed: "
                                f"{new.get('dirty_files')}")
        elif old.get("type") == "bin-dir":
            for b, anchor in old.get("binaries", {}).items():
                nb = new["binaries"].get(b)
                if nb is None:
                    problems.append(f"bin/{b}: MISSING")
                elif nb["sha256"] != anchor["sha256"]:
                    problems.append(f"bin/{b}: sha256 drift")
        elif old.get("type") in ("binaries", "containerfile"):
            for f, anchor in old.get("files", {}).items():
                p = Path(__file__).parent / name / f
                if not p.exists():
                    problems.append(f"{name}/{f}: MISSING")
    for name in current["entries"]:
        if name not in manifest["entries"]:
            problems.append(f"{name}: NEW entry not in manifest")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true",
                    help="check the tree against the existing manifest")
    args = ap.parse_args()
    if args.verify:
        if not MANIFEST.exists():
            print("no manifest.json — run make_manifest.py first",
                  file=sys.stderr)
            return 2
        problems = verify(json.loads(MANIFEST.read_text()))
        if problems:
            print("TOOLS DRIFT DETECTED:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("tools/ matches manifest.json")
        return 0
    manifest = generate()
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2,
                                   sort_keys=True) + "\n")
    n = len(manifest["entries"])
    print(f"manifest.json written: {n} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
