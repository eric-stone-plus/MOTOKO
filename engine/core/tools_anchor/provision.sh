#!/usr/bin/env bash
# provision.sh — rebuild / verify the tools/ tree from manifest.json.
#
#   ./provision.sh verify    # drift check (git heads, binary hashes,
#                            #   ~/.local/bin wrapper targets)
#   ./provision.sh verify-wrappers   # just the wrapper half of verify
#   ./provision.sh restore   # rebuild what is rebuildable (git anchors),
#                            # print a checklist for what is not
#   ./provision.sh strix-verify    # fail-closed: deploy-site anonymity
#                                  # patches in place? (a recorded pitfall ③)
#   ./provision.sh strix-upgrade   # backup → uv tool upgrade → replay
#                                  # anchored patches → verify + flag smoke
#
# strix-upgrade is the MANDATORY way to upgrade strix-agent: a bare
# `uv tool upgrade` can silently wipe the three deploy-site patch files
# (caido_upstream.py / caido_bootstrap.py wiring / docker_client.py
# publish-ports) and strix then launches with NO caido upstream — a the internal doctrine
# anonymity violation that still "works". Anchored patch sources live
# in strix-patches/<version>/ next to this script.
#
# The toolbox is NOT in git (200k files, upstream checkouts). What makes it
# reproducible: git entries are pinned by (origin, branch, HEAD); binaries
# carry sha256 anchors. Anything without a remote needs one manual restore
# from the operator's backup — the script says exactly which.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# The toolbox is deploy-host data and never ships with the tree. A bare
# `cd $(…tools && pwd)` died silently under set -e on a fresh checkout
# (a recorded pitfall), so resolve without entering it and fail with a remedy instead;
# `restore` is the one verb that may create the directory.
TOOLS_DIR="${TOOLS_DIR:-$SCRIPT_DIR/../../../tools}"
if [ "${1:-}" = "restore" ]; then
  mkdir -p "$TOOLS_DIR"
fi
if [ ! -d "$TOOLS_DIR" ]; then
  echo "[FAIL] toolbox dir not found: $TOOLS_DIR" >&2
  echo "       set TOOLS_DIR, or run: $0 restore   (clones the git anchors)" >&2
  exit 2
fi
cd "$TOOLS_DIR"

MANIFEST="${MANIFEST:-$SCRIPT_DIR/manifest.json}"

ENGINE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# a recorded pitfall's structural fix: the manifest anchors the TOOLBOX (git heads, binary
# sha256, template count) and nothing anchored the ~/.local/bin wrappers that
# point INTO it, so the 2026-09-13 tree move broke twenty of them silently --
# three corpus-driven (jwt_tool/graphw00f/tplmap) kept resolving, kept being
# spawned, and kept exiting 127 before a line of the tool ran. The probe is
# doctor's, shared so the gate and the runtime report cannot drift apart.
# Static: reads wrapper heads, executes nothing.
verify_wrappers() {
  BIN_DIR="${MOTOKO_WRAPPER_BIN:-$HOME/.local/bin}"
  PYTHONPATH="$ENGINE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$BIN_DIR" <<'PYEOF'
import sys
from pathlib import Path

from core import doctor

found = doctor.broken_wrappers(Path(sys.argv[1]))
for name, path, why in found["other"]:
    print(f"[warn] wrapper {name} ({path}) {why} — no rule drives it")
for name, path, why in found["corpus"]:
    print(f"[FAIL] corpus tool {name} ({path}) {why} — every rule using it "
          f"fails as a deployment defect")
if not found["corpus"] and not found["other"]:
    print(f"[ok] wrappers in {sys.argv[1]}: none broken")
sys.exit(1 if found["corpus"] else 0)
PYEOF
}

verify() {
  # Both halves run even if the first fails: a deployment gate that stops at
  # the first drift makes the operator fix-and-rerun once per defect.
  local rc=0
  TOOLS_DIR="$TOOLS_DIR" python3 "$SCRIPT_DIR/make_manifest.py" --verify || rc=1
  verify_wrappers || rc=1
  return "$rc"
}

restore() {
  if [ ! -f "$MANIFEST" ]; then
    echo "[FAIL] no manifest.json next to this script — nothing to restore from." >&2
    echo "       the manifest is deploy-host data (it anchors the operator's own" >&2
    echo "       toolbox, private origins included) and does not ship; generate it" >&2
    echo "       on a provisioned host (python3 $SCRIPT_DIR/make_manifest.py) or" >&2
    echo "       copy one here." >&2
    exit 2
  fi
  python3 - "$MANIFEST" <<'EOF'
import json, subprocess, sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
todo = []
for name, entry in manifest["entries"].items():
    if entry.get("type") == "git" and entry.get("origin"):
        dest = Path(name)
        if dest.exists():
            print(f"[skip] {name}: already present (drift check via verify)")
            continue
        print(f"[git ] {name}: clone {entry['origin']} @ {entry['head'][:9]}")
        subprocess.run(["git", "clone", entry["origin"], name], check=True)
        subprocess.run(["git", "-C", name, "checkout", entry["head"]], check=True)
    elif entry.get("type") == "git":
        todo.append(f"{name}: local-only git checkout (no remote) — "
                    f"restore from backup, HEAD {entry.get('head', '?')[:9]}")
    elif entry.get("type") == "bin-dir":
        todo.append(f"{name}: Go binaries with sha256 anchors in manifest — "
                    f"re-run install.sh or restore from backup, then verify")
    elif entry.get("type") == "nuclei":
        todo.append(f"{name}: nuclei binary (sha256 in manifest) + "
                    f"{entry.get('template_yaml_count', '?')} templates — "
                    f"nuclei -update-templates then spot-check count")
    elif entry.get("type") == "binaries":
        todo.append(f"{name}: raw binaries (sha256 in manifest) — "
                    f"restore from backup")
    else:
        todo.append(f"{name}: {entry.get('type')} — restore from backup, "
                    f"verify presence")
print("\nManual checklist (not machine-rebuildable):")
for t in todo:
    print(f"  [ ] {t}")
EOF
  echo
  echo "after restore: ./provision.sh verify  (must pass before engine runs)"
}

STRIX_PATCH_DIR="$SCRIPT_DIR/strix-patches"

strix_site_default() {
  # The deploy site is the bytes that actually run (a recorded pitfall: readlink -f
  # $(which strix)), NOT the tools/strix source checkout.
  local d
  for d in "$HOME"/.local/share/uv/tools/strix-agent/lib/python3.*/site-packages/strix; do
    [ -d "$d" ] && { echo "$d"; return 0; }
  done
  local bin venv
  bin="$(readlink -f "$(command -v strix 2>/dev/null || echo "$HOME/.local/bin/strix")")"
  venv="$(dirname "$(dirname "$bin")")"
  for d in "$venv"/lib/python3.*/site-packages/strix; do
    [ -d "$d" ] && { echo "$d"; return 0; }
  done
  return 1
}

strix_verify() {
  local site="${STRIX_SITE:-$(strix_site_default)}"
  STRIX_SITE="$site" python3 - <<'EOF'
import ast, os, sys
site = os.environ["STRIX_SITE"]
rt = os.path.join(site, "runtime")
# markers = the patch hunks; presence proves the patch, absence proves the wipe
checks = [
    ("caido_upstream.py", ["MOTOKO_CAIDO_UPSTREAM"]),
    ("caido_bootstrap.py", ["MOTOKO_CAIDO_UPSTREAM"]),
    ("docker_client.py", ["STRIX_SANDBOX_PUBLISH_PORTS", "_resolve_exposed_port"]),
]
fail = False
if not os.path.isdir(rt):
    print(f"[FAIL] no such runtime dir: {rt}")
    sys.exit(1)
for name, markers in checks:
    p = os.path.join(rt, name)
    if not os.path.exists(p):
        print(f"[FAIL] missing {p}")
        fail = True
        continue
    src = open(p).read()
    try:
        ast.parse(src)
    except SyntaxError as e:
        print(f"[FAIL] {name}: syntax error {e}")
        fail = True
        continue
    miss = [m for m in markers if m not in src]
    if miss:
        print(f"[FAIL] {name}: patch markers absent {miss}")
        fail = True
    else:
        print(f"[ok  ] {name}")
sys.exit(1 if fail else 0)
EOF
}

strix_upgrade() {
  local site ver_before ver_after bk pd helpout
  site="${STRIX_SITE:-$(strix_site_default)}" || {
    echo "[FAIL] strix deploy site not found" >&2; exit 1; }
  bk="/var/tmp/tmp-persisted/strix-patch-backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$bk"
  cp "$site"/runtime/caido_upstream.py "$site"/runtime/caido_bootstrap.py \
     "$site"/runtime/docker_client.py "$bk"/ 2>/dev/null || {
    echo "[FAIL] pre-upgrade backup incomplete — deploy site already broken;
    restore from $STRIX_PATCH_DIR/<version>/ first" >&2; exit 1; }
  echo "[bk  ] patched runtime files -> $bk"
  ver_before="$(strix --version 2>/dev/null || echo '?')"
  echo "[up  ] uv tool upgrade strix-agent (was: $ver_before)"
  uv tool upgrade strix-agent
  ver_after="$(strix --version 2>/dev/null || echo '?')"
  echo "[up  ] now: $ver_after"
  if STRIX_SITE="$site" strix_verify; then
    echo "[ok  ] patches intact after upgrade — nothing to replay"
  else
    pd="$STRIX_PATCH_DIR/${ver_after##* }"
    if [ -d "$pd" ]; then
      echo "[repl] replaying anchored patches from $pd"
      cp "$pd"/caido_upstream.py "$pd"/caido_bootstrap.py "$pd"/docker_client.py \
         "$site"/runtime/
      STRIX_SITE="$site" strix_verify || {
        echo "[FAIL] replay did not restore markers — port manually from $bk" >&2
        exit 1; }
      echo "[ok  ] replay complete"
    else
      cat >&2 <<MSG
[FAIL] upgrade overwrote the deploy-site patches and no anchor exists for
$ver_after. Manual port (fail-closed — do NOT launch strix until
strix-verify passes):
  1. diff $bk/*.py against the new $site/runtime/*.py
  2. port the patch hunks (markers: MOTOKO_CAIDO_UPSTREAM /
     STRIX_SANDBOX_PUBLISH_PORTS / _resolve_exposed_port)
  3. anchor: mkdir $STRIX_PATCH_DIR/${ver_after##* } && cp the three patched
     files there, update its README.md
  4. git commit the anchor; re-run: $0 strix-verify
MSG
      exit 1
    fi
  fi
  # flag smoke: the flags cmd_strix / launch-strix.sh rely on must survive
  # the upgrade (a recorded pitfall: strix 1.6.x dropped -p and argparse exits 0 on usage)
  helpout="$(strix --help 2>&1)"
  local f
  for f in "--instruction" "--instruction-file" "--target" "--scan-mode" "--non-interactive"; do
    printf '%s' "$helpout" | grep -qF -- "$f" || {
      echo "[FAIL] strix --help lost $f — engine cmd_strix / launch-strix.sh need updating" >&2
      exit 1; }
  done
  echo "[ok  ] flag smoke: --instruction{,-file} --target --scan-mode --non-interactive"
}

case "${1:-}" in
  verify) verify ;;
  verify-wrappers) verify_wrappers ;;
  restore) restore ;;
  strix-verify) strix_verify ;;
  strix-upgrade) strix_upgrade ;;
  *) echo "usage: $0 {verify|verify-wrappers|restore|strix-verify|strix-upgrade}" >&2; exit 2 ;;
esac
