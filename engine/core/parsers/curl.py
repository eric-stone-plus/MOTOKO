'curl output parser — robots.txt mode, IMDS mode, generic passthrough.\n\n* a fetch of ``<base>/robots.txt`` is parsed as robots (opsec.parse_robots) and\n  stamps the base asset with the OPSEC facts the burst rules gate on\n  (``robots_host`` / ``canary_paths`` / ``crawl_delay``);\n* a fetch whose command names a link-local metadata endpoint is parsed as an\n  IMDS probe, in two modes that must not be conflated (see below);\n* any other curl invocation has no stable shape — the body goes to the dead\n  letter intact (audit trail, never silently dropped).\n\nIMDS mode exists because ``R-VULN-SSRF-CHAIN-001`` declares\n``on_hit_class: ssrf.cloud_imds`` and the hit oracle\n(``_hypothesis_hit(required_class=…)``) credits a hit ONLY from a finding of\nthat class produced by this hypothesis\'s own runs. A parser that stayed silent\nwould leave the rule firing, exiting 0, and minting nothing — coverage on the\nboard, zero evidence on the graph.\n\nThe two modes are told apart by the action\'s command TEMPLATE, which the\norchestrator hands over unrendered (``payload["cmd"] = template``), so this is a\nfact about the invocation and not a guess from the body:\n\n* ``injected`` — the template renders ``{ssrf_url}``/``{ssrf_param}``, i.e. the\n  metadata request was smuggled through a confirmed SSRF point on the TARGET.\n  An echoed metadata listing is target evidence and mints ``ssrf.cloud_imds``;\n* ``local`` — the template names the metadata endpoint directly\n  (``R-CTX-CLOUD-001``). That curl runs on the scanning host, so it describes\n  the EXECUTION ENVIRONMENT, not the target. It is reported as such and mints\n  no finding: attributing our own host\'s cloud membership to a target asset\n  would be a fabricated finding.\n\n* a 404 page arrives on stdout with exit **0** (no ``-f`` in the corpus), so the\n  exit code proves nothing and an HTML body must never read as metadata;\n* a refused connect is exit 7 with curl\'s diagnostic on stderr and empty stdout.\n\nCoverage limits, recorded rather than papered over: only the AWS/Alibaba shape\n(a bare key listing) is recognised. GCP needs ``Metadata-Flavor: Google`` and\nAzure needs ``Metadata: true``, and neither header is in the corpus command, so\na GCP/Azure target answers 403 and this parser correctly reports "no metadata\nechoed" instead of inventing a hit.\n'

from __future__ import annotations

from urllib.parse import urlparse

from .. import opsec
from . import Parser, register

# The key listing a reachable AWS/Alibaba-style metadata endpoint returns for
# `/latest/meta-data/`. Several must co-occur before a body is called metadata:
# the common case is an HTML 404 or a WAF block page echoed back through the
# injection point, and that must never mint a cloud-metadata finding.
_IMDS_KEYS = frozenset({
    "ami-id", "ami-launch-index", "ami-manifest-path", "block-device-mapping",
    "events", "hostname", "iam", "identity-credentials", "instance-action",
    "instance-id", "instance-life-cycle", "instance-type", "local-hostname",
    "local-ipv4", "mac", "metrics", "network", "placement", "profile",
    "public-hostname", "public-ipv4", "public-keys", "reservation-id",
    "security-groups", "services",
})
_IMDS_MIN_HITS = 3

# Link-local metadata endpoints. AWS, GCP and Azure share 169.254.169.254;
# Alibaba Cloud uses 100.100.100.200; Azure also answers on 168.63.129.16;
# AWS over IPv6 and GCP by name round out the set.
_IMDS_HOSTS = (
    "169.254.169.254", "100.100.100.200", "168.63.129.16",
    "fd00:ec2::254", "metadata.google.internal",
)


@register
class CurlParser(Parser):
    tool = "curl"

    def parse(self, stdout, stderr="", action=None):
        action = action or {}
        url = str(action.get("url") or "")
        if url.rstrip("/").lower().endswith("/robots.txt"):
            return self._robots_result(stdout, url)
        mode = self._imds_mode(action)
        if mode:
            return self._imds_result(stdout, stderr, action, mode)
        lines = stdout.splitlines() if stdout else []
        return self._result(
            summary=(f"curl: {len(lines)} lines (no structured parser for "
                     f"this target shape)"),
            dead_letter=[stdout[:2000]] if stdout else [],
        )

    # -- IMDS ----------------------------------------------------------
    def _imds_mode(self, action: dict) -> str:
        """'injected' | 'local' | '' — which metadata probe this was."""
        template = str(action.get("cmd") or "")
        blob = f"{template} {action.get('url') or ''}"
        if not any(host in blob for host in _IMDS_HOSTS):
            return ""
        # The template arrives UNRENDERED, so the placeholder names are still
        # visible: their presence is what makes this the target's metadata
        # endpoint rather than ours.
        return "injected" if "{ssrf_url}" in template else "local"

    def _imds_result(self, stdout, stderr, action: dict, mode: str):
        body = stdout or ""
        if mode == "local":
            # About the scanning host. Reporting it as target evidence would
            # be a fabricated finding, so it is named for what it is.
            return self._result(
                summary=("curl IMDS: direct probe of THIS host's metadata "
                         "endpoint — an execution-environment fact, not target "
                         "evidence"),
                dead_letter=[body[:2000]] if body else [])

        tokens = {ln.strip().rstrip("/") for ln in body.splitlines() if ln.strip()}
        hits = sorted(tokens & _IMDS_KEYS)
        url = str(action.get("url") or "")
        if len(hits) >= _IMDS_MIN_HITS:
            if not url:
                # A hit we cannot aim a follow-up at is not deliverable
                # evidence (M2) — the rule needs an obs_url.
                return self._result(
                    summary=("curl IMDS via SSRF: metadata listing echoed "
                             f"({len(hits)} known keys) but the action carries "
                             "no observation URL — no finding minted"),
                    dead_letter=[body[:2000]])
            sample = ", ".join(hits[:4])
            return self._result(
                summary=("curl IMDS via SSRF: cloud metadata echoed through "
                         f"the injection point ({len(hits)} known keys: "
                         f"{sample})"),
                findings=[self._finding(
                    class_="ssrf.cloud_imds",
                    title="cloud metadata reachable through an SSRF injection "
                          "point",
                    url=url,
                    severity="high",
                    extra={"imds_keys": len(hits)},
                )],
                dead_letter=[body[:2000]])
        if body.lstrip().lower().startswith("<"):
            return self._result(
                summary=("curl IMDS via SSRF: HTML body (404/block page) "
                         "echoed — no metadata reached"),
                dead_letter=[body[:2000]])
        if not body.strip():
            detail = (stderr or "").strip().splitlines()
            return self._result(
                summary=("curl IMDS via SSRF: empty body — the injection point "
                         "returned nothing"
                         + (f" ({detail[-1][:120]})" if detail else "")),
                dead_letter=[(stderr or "")[:2000]] if stderr else [])
        return self._result(
            summary=("curl IMDS via SSRF: unrecognised body — no metadata key "
                     "listing, format not assumed"),
            dead_letter=[body[:2000]])

    # -- robots --------------------------------------------------------
    def _robots_result(self, body: str, url: str):
        paths, delay = opsec.parse_robots(body)
        parts = urlparse(url)
        base = f"{parts.scheme}://{parts.netloc}"
        host = (parts.hostname or "").lower()
        canary_shaped = [p for p in paths if opsec.canary_hit(p)]
        if body.lstrip().lower().startswith("<"):
            return self._result(
                summary=("curl robots.txt: HTML body (404/block page) — "
                         "robots state UNKNOWN, burst gate stays closed"),
                assets=[])
        asset = self._asset(type_="url", value=base, extra={
            "robots_host": host,
            "canary_paths": paths[:64],
            "crawl_delay": delay,
        })
        return self._result(
            summary=(f"curl robots.txt: {len(paths)} disallow, "
                     f"{len(canary_shaped)} canary-shaped, "
                     f"crawl-delay={delay}"),
            assets=[asset],
        )
