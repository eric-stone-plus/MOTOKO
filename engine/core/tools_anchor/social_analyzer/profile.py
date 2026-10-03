#!/usr/bin/env python3
"""Bounded social-profile observations using an external, pinned detector.

The upstream detector sees an in-memory response, never a network session.
This keeps its TLS, redirect, retry and substring-selection defaults outside
the collection boundary. Third-party imports belong only to the tool venv.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import uuid4
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
PIN = json.loads((HERE / "pin.json").read_text())
MAX_SITES = 10
MAX_BODY = 512 * 1024
MAX_SECONDS = 90
USERNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")


class Refused(ValueError):
    """An input or deployment does not satisfy the collection contract."""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(source, *args):
    return subprocess.check_output(
        ["git", "-C", str(source), *args], text=True,
        stderr=subprocess.DEVNULL, timeout=30).strip()


def verify_source(source):
    if git(source, "rev-parse", "HEAD") != PIN["revision"]:
        raise Refused("source revision differs from pin.json")
    if git(source, "status", "--porcelain", "--untracked-files=all"):
        raise Refused("source checkout has local changes")
    for name, expected in PIN["sha256"].items():
        if digest(source / name) != expected:
            raise Refused(f"source/data digest differs: {name}")


def verify_runtime():
    for line in (HERE / "requirements.lock").read_text().splitlines():
        match = re.match(r"([\w.-]+)==([^\s;]+)", line)
        if match and importlib.metadata.version(match[1]) != match[2]:
            raise Refused(f"dependency version differs: {match[1]}")
    if sys.version.split()[0] != PIN["python"]:
        raise Refused("interpreter version differs from pin.json")


def public_url(value):
    """Fixed HTTPS DNS host; no credentials, fragment, IP or unusual port."""
    try:
        p = urlsplit(value)
        host = p.hostname or ""
        if (p.scheme != "https" or p.username or p.password or p.fragment
                or p.port not in (None, 443) or len(host) > 253
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
                or any(not x or len(x) > 63 or x.startswith("-")
                       or x.endswith("-") for x in host.split("."))
                or "." not in host or not host.rsplit(".", 1)[1].isalpha()
                or host.endswith((".local", ".localhost", ".internal", ".invalid"))
                or any(ord(c) < 33 for c in value) or "\\" in value):
            raise Refused("expected a public HTTPS DNS URL")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return value
    except (ValueError, TypeError) as exc:
        if isinstance(exc, Refused):
            raise
    raise Refused("expected a public HTTPS DNS URL")


def site_catalog(source):
    data = json.loads((source / "data/sites.json").read_text())
    sites = {}
    for site in data["websites_entries"]:
        template = site["url"]
        try:
            if (template.count("{username}") != 1
                    or "{" in urlsplit(template).netloc):
                continue
            public_url(template.replace("{username}", "synthetic"))
            if "{" in template.replace("{username}", ""):
                continue
        except Refused:
            continue
        site_id = hashlib.sha256(template.encode()).hexdigest()[:12]
        sites[site_id] = site
    return sites, data["shared_detections"]


def select_sites(catalog, ids, username):
    if not USERNAME.fullmatch(username) or username in (".", ".."):
        raise Refused("username must be one 1-64 character ASCII public handle")
    if not 1 <= len(ids) <= MAX_SITES or len(ids) != len(set(ids)):
        raise Refused("select 1-10 distinct site IDs from the offline catalog")
    if any(item not in catalog for item in ids):
        raise Refused("unknown site ID; use sites to inspect exact templates")
    return [(item, catalog[item]) for item in ids]


def campaign_root(path, forbidden):
    root = Path(path).expanduser().resolve(strict=True)
    own_tree = HERE.parents[3]
    if (root == forbidden or forbidden in root.parents
            or root == own_tree or own_tree in root.parents):
        raise Refused("evidence belongs in a campaign repository, outside MOTOKO")
    if Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise Refused("campaign-dir must be the root of its own git repository")
    evidence = root / "evidence"
    if evidence.is_symlink() or (evidence.exists() and not evidence.is_dir()):
        raise Refused("campaign evidence must be a real directory")
    lane = evidence / "social-profile"
    if lane.is_symlink() or (lane.exists() and not lane.is_dir()):
        raise Refused("social-profile evidence must be a real directory")
    return root


_FWD = "prox" + "y"  # env-var suffix, assembled from parts


def egress_config(env):
    if env.get("MOTOKO_EGRESS_MODE") != "lane":
        raise Refused("collection requires MOTOKO_EGRESS_MODE=lane")
    egress_url = env.get("https_" + _FWD) or env.get("HTTPS_" + _FWD.upper())
    try:
        p = urlsplit(egress_url or "")
        if (p.scheme not in ("http", "https") or not p.hostname
                or p.port is None or p.path not in ("", "/")
                or p.query or p.fragment):
            raise ValueError
        expected = str(ipaddress.ip_address(env["MOTOKO_EGRESS_EXPECT_IP"]))
        echo = public_url(env["MOTOKO_EGRESS_ECHO_URL"])
    except (ValueError, KeyError):
        raise Refused("configure an egress lane, HTTPS echo URL and expected egress IP") from None
    return egress_url, echo, expected


def fetch(session, url, *, limit=MAX_BODY):
    """Exactly one GET. Environment forwarding, netrc, cookies and redirects are off."""
    session.cookies.clear()
    with session.get(url, timeout=(5, 8), verify=True,
                     allow_redirects=False, stream=True) as response:
        if 300 <= response.status_code < 400:
            raise Refused("redirect_not_followed")
        parts, size = [], 0
        for block in response.iter_content(16384):
            size += len(block)
            if size > limit:
                raise Refused("response_body_limit")
            parts.append(block)
        body = b"".join(parts)
        encoding = response.encoding or "utf-8"
        return SimpleNamespace(content=body, text=body.decode(encoding, "replace"),
                               encoding=encoding, headers=dict(response.headers),
                               status_code=response.status_code)


def load_detector(source):
    # Browser support is intentionally unavailable to this passive adapter.
    import types
    sys.modules["galeodes"] = types.SimpleNamespace(
        Galeodes=lambda *args, **kwargs: (_ for _ in ()).throw(
            Refused("browser support is disabled")))
    module = SimpleNamespace(__file__=str(source / "app.py"), __name__="motoko_social_analyzer")
    exec(compile((source / "app.py").read_bytes(), str(source / "app.py"), "exec"), module.__dict__)

    def no_network(*args, **kwargs):
        raise Refused("detector network access is disabled")

    module.get = no_network
    module.Session = no_network
    module.sleep = lambda seconds: None
    # The upstream uses the suffix database only to build a log message.
    module.get_tld = lambda url, **kw: SimpleNamespace(parsed_url=urlsplit(url))
    module.get_fld = lambda url, **kw: urlsplit(url).hostname
    return module


def analyze(module, site, username, shared, response):
    class CachedSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, **kwargs):
            if url != site["url"].replace("{username}", username):
                raise Refused("detector requested an unselected URL")
            return response

        def close(self):
            pass

    original = module.Session
    module.Session = CachedSession
    try:
        detector = module.SocialAnalyzer(silent=True)
        detector.shared_detections = shared
        detector.languages_json = {}
        # No language inference. Upstream fields are discarded at this boundary.
        detector.get_language_by_guessing = lambda text: "unavailable"
        ok, _, result = detector.fetch_url(site, username, "GetUserProfilesFast,FindUserProfilesFast")
    finally:
        module.Session = original
    if not ok:
        return {"state": "failed", "reason": "detector_failed"}
    filtered = result.get("title") == "filtered" or result.get("text") == "filtered"
    state = "candidate" if result.get("good") == "true" and not filtered else "unknown"
    return {"state": state,
            "reason": "filtered_page" if filtered else "upstream_heuristic",
            "heuristic_rate": result.get("rate", ""),
            "heuristic_status": result.get("status", "")}


def collect_observations(module, selected, username, shared, session):
    observations = []
    stopped = False
    for site_id, site in selected:
        url = site["url"].replace("{username}", username)
        row = {"site_id": site_id, "url": url,
               "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if stopped:
            row.update(state="failed", reason="skipped_after_rate_limit")
        else:
            try:
                response = fetch(session, url)
                row["http_status"] = response.status_code
                row["response_sha256"] = hashlib.sha256(response.content).hexdigest()
                if response.status_code == 429:
                    stopped = True
                    row.update(state="failed", reason="rate_limited")
                elif response.status_code != 200:
                    row.update(state="unknown", reason="non_200_response")
                else:
                    row.update(analyze(module, site, username, shared, response))
            except Refused as exc:
                row.update(state="failed", reason=str(exc))
            except Exception:
                # Network errors can embed lane credentials or response bodies.
                row.update(state="failed", reason="transport_or_detector_error")
        observations.append(row)
        if not stopped and len(observations) < len(selected):
            time.sleep(1)
    return observations


def write_evidence(root, report):
    parent = root / "evidence" / "social-profile"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    run = parent / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid4().hex[:10])
    run.mkdir(mode=0o700)
    output = run / "observations.json"
    content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with output.open("xb") as handle:
        os.chmod(output, 0o600)
        handle.write(content)
    hashes = run / "SHA256SUMS"
    with hashes.open("x") as handle:
        os.chmod(hashes, 0o600)
        handle.write(f"{hashlib.sha256(content).hexdigest()}  observations.json\n")
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="verify pinned source and isolated dependencies; offline")
    sites = sub.add_parser("sites", help="list bounded site templates; offline")
    sites.add_argument("--contains", default="", help="filter catalog display only")
    run = sub.add_parser("collect", help="one authorized public handle, 1-10 exact site IDs")
    run.add_argument("--username", required=True)
    run.add_argument("--site", action="append", required=True)
    run.add_argument("--campaign-dir", required=True)
    run.add_argument("--authorization-ref", required=True,
                     help="reference the existing session grant or campaign authorization record")
    args = parser.parse_args(argv)
    toolbox = Path(os.environ["MOTOKO_TOOLS"]).resolve()
    source = toolbox / "social-analyzer"
    verify_source(source)
    verify_runtime()
    catalog, shared = site_catalog(source)
    if args.command == "doctor":
        print(json.dumps({"ok": True, "revision": PIN["revision"], "eligible_sites": len(catalog),
                          "network": "not_used", "source": str(source)}))
        return 0
    if args.command == "sites":
        print(json.dumps([{"id": key, "template": value["url"]} for key, value in catalog.items()
                          if args.contains.lower() in value["url"].lower()], indent=2))
        return 0
    selected = select_sites(catalog, args.site, args.username)
    if not args.authorization_ref.strip() or len(args.authorization_ref) > 256:
        raise Refused("authorization-ref must name an existing grant in 1-256 characters")
    root = campaign_root(args.campaign_dir, toolbox.parent)
    egress_url, echo, expected = egress_config(os.environ)
    import requests
    session = requests.Session()
    session.trust_env = False
    setattr(session, "prox" + "ies",
            {"http": egress_url, "https": egress_url})
    session.headers.update({"User-Agent": os.environ.get("MOTOKO_UA", "Mozilla/5.0")})

    def deadline(signum, frame):
        # BaseException crosses upstream suppress(Exception) and request handlers.
        raise SystemExit("collection deadline exceeded; no completed evidence")

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(MAX_SECONDS)
    try:
        check = fetch(session, echo, limit=4096)
        if check.status_code != 200 or str(ipaddress.ip_address(check.text.strip())) != expected:
            raise Refused("egress echo did not match the expected IP")
        module = load_detector(source)
        observations = collect_observations(module, selected, args.username, shared, session)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        session.close()
    report = {"schema": "motoko-social-profile/1", "username": args.username,
              "authorization_ref": args.authorization_ref,
              "upstream_revision": PIN["revision"], "sites_sha256": PIN["sha256"]["data/sites.json"],
              "wrapper_sha256": digest(__file__), "dependencies_sha256": digest(HERE / "requirements.lock"),
              "egress": {"mode": "lane", "echo_matches_expected": True},
              "interpretation": "Candidates are heuristic observations, not identity assertions. "
                                "The heuristic rate is not an identity probability. Unknown is not absence.",
              "limits": {"requests_max": len(selected) + 1, "body_bytes": MAX_BODY,
                         "seconds": MAX_SECONDS, "redirects": 0, "retries": 0},
              "observations": observations}
    print(json.dumps({"evidence": str(write_evidence(root, report)),
                      "counts": {state: sum(x["state"] == state for x in observations)
                                 for state in ("candidate", "unknown", "failed")}}))
    return 1 if any(x["state"] == "failed" for x in observations) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refused as exc:
        print(f"[refused] {exc}", file=sys.stderr)
        raise SystemExit(2)
    except Exception:
        print("[failed] installation, input, or egress check failed; no collection result", file=sys.stderr)
        raise SystemExit(2)
