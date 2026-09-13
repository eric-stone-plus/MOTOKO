"""OPSEC layer — WAF detection, canary guard, per-origin cooldowns.

Landed in the 2026-09-13 P0 iteration after three production lessons:

* ``R-CTX-WAF-001`` was dead code: it gates on ``fact waf == true``, and
  ``orchestrator._fact_view`` read ``asset.get("waf")``, but no parser ever
  wrote that fact. The one rule meant to slow the engine down could never
  fire — and when it was hand-authored it pointed at ``-rl 10``, FASTER
  than the ``-rl 5`` baseline it was supposed to improve on.
* The engine had no detection feedback: an origin that started blocking
  (a CDN's deny code 60, a per-vhost 405 wall, Aliyun WAF block pages)
  kept being hit at the original cadence. P-005 recorded 28 wasted
  expansion rounds against a 200→405 flip. Detection must cool the origin
  down, not provoke it.
* ``P-031``: an amass run escaped the engine's process group and kept
  scanning for 3 hours after the engine died. Knowing which scan processes
  are alive — and reaping them on exit — is an OPSEC requirement; that half
  lives in ``executor.py`` (pid registry + ``reap()``).

Everything in this module is pure stdlib and side-effect free: signatures,
parsers and an in-memory cooldown board. The orchestrator owns the wiring
(parsers stamp the ``waf`` fact; ``_act`` consults the canary guard and the
cooldown board before any dispatch).

Vendor list is evidence-led: the Aliyun WAF block title is the one observed
in production (54 hits across campaign observations); the rest are the
common CN/global vendors a domestic engagement will actually meet. Order
matters — first match wins, so the specific page titles come before the
generic header names.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

# A realistic, boring, current browser UA. The engine's own probe used to
# send ``User-Agent: MOTOKO/0.1`` — a one-line IDS signature. Override per
# engagement with MOTOKO_UA; rules render it via the {ua} context key.
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")

# (substring, vendor) — matched case-insensitively against title, webserver,
# tech strings and header names/values. First match wins.
_WAF_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("阿里云", "aliyun-waf"),           # observed production block title
    ("aliyun waf", "aliyun-waf"),
    ("yundun", "aliyun-waf"),
    ("雷池", "safeline"),
    ("safeline", "safeline"),
    ("安全狗", "safedog"),
    ("safedog", "safedog"),
    ("云锁", "yunsuo"),
    ("yunsuo", "yunsuo"),
    ("创宇盾", "zhidao-chuangyu"),
    ("知道创宇", "zhidao-chuangyu"),
    ("腾讯云waf", "tencent-waf"),
    ("tencent waf", "tencent-waf"),
    ("t-sec", "tencent-waf"),          # T-Sec Web应用防火墙
    ("火山引擎", "volcengine"),
    ("volcengine", "volcengine"),
    ("深信服", "sangfor"),
    ("sangfor", "sangfor"),
    ("网宿", "wangsu"),
    ("wangsu", "wangsu"),
    ("incapsula", "imperva"),
    ("imperva", "imperva"),
    ("cloudflare", "cloudflare"),
    ("akamai", "akamai"),
    ("sucuri", "sucuri"),
    ("web application firewall", "generic-waf"),
)

# Header names whose bare presence means a WAF sits in front.
_WAF_HEADER_NAMES = ("x-waf", "x-yundun", "x-safedog", "yunsuo_session",
                     "x-cdn-waf", "x-waf-status")

# Path tokens that mark a defender-planted trap (a production robots.txt
# disallowed /honeypot.html verbatim, "安全/恶意爬虫陷阱"). Matched as whole
# path segments split on / - _ . so a legit path like "bootstrap" cannot
# false-positive on "trap". Substring matching is exactly how a canary gets
# hit by accident.
_CANARY_TOKENS = frozenset({
    "honeypot", "honey", "tarpit", "canary", "bait", "蜜罐",
})

_SEGMENT_SPLIT = re.compile(r"[/_\-.?]")


def detect_waf(*, title: str = "", webserver: str = "",
               tech: list[str] | tuple[str, ...] | None = None,
               headers: dict | None = None) -> str | None:
    """Return a vendor name when a WAF signature is present, else None.

    ``title``/``webserver`` are the httpx JSON fields; ``tech`` is its tech
    list (or a nuclei tag list); ``headers`` an optional response-header
    mapping (names and values are both scanned).
    """
    candidates: list[str] = []
    for text in (title, webserver):
        if text:
            candidates.append(str(text))
    for t in tech or ():
        if t:
            candidates.append(str(t))
    if headers:
        for k, v in headers.items():
            candidates.append(str(k))
            if v is not None:
                candidates.append(str(v))

    joined = "\n".join(candidates).lower()
    if not joined:
        return None
    for needle, vendor in _WAF_SIGNATURES:
        if needle in joined:
            return vendor
    if headers:
        for name in headers:
            if str(name).lower() in _WAF_HEADER_NAMES:
                return "generic-waf"
    return None


def canary_hit(url: str) -> str | None:
    """The canary token a URL trips, or None.

    Tokens are matched against whole path segments (split on ``/ - _ . ?``),
    never substrings — ``/bootstrap`` must not trip ``trap``.
    """
    if not url:
        return None
    path = urlparse(str(url)).path or ""
    segments = {s.lower() for s in _SEGMENT_SPLIT.split(path) if s}
    return next((tok for tok in segments if tok in _CANARY_TOKENS), None)


def parse_robots(text: str) -> tuple[list[str], float | None]:
    """Parse a robots.txt body into ``(disallow_paths, crawl_delay)``.

    Conservative v1: the Disallow lists of ALL user-agent groups are
    unioned (a trap declared for any crawler is a trap for us), and the
    first Crawl-delay seen wins. Comments and blank lines are ignored;
    an empty ``Disallow:`` (allow-all marker) is not a path.
    """
    disallow: list[str] = []
    delay: float | None = None
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "disallow":
            if value:
                disallow.append(value)
        elif field == "crawl-delay" and delay is None:
            try:
                delay = float(value)
            except ValueError:
                pass
    return disallow, delay


class CooldownBoard:
    """Per-origin cooldown registry (in-memory, orchestrator-scoped).

    When a target shows active blocking (a WAF fact lands, a run classifies
    as ``detected``), the orchestrator cools the whole origin down: further
    ACT dispatch against it is skipped with an ``opsec_cooldown_skip``
    event instead of hammering the wall. Default 30 min; cooldowns stack to
    the LATER deadline so repeated detections extend the quiet period.

    The clock is injectable for tests; production uses ``time.monotonic``.
    """

    def __init__(self, *, cooldown_s: float = 1800.0,
                 clock=time.monotonic):
        self.cooldown_s = float(cooldown_s)
        self._clock = clock
        self._until: dict[str, float] = {}
        self._reason: dict[str, str] = {}

    @staticmethod
    def normalize(origin: str | None) -> str:
        """Host key for an origin: lowercase, port stripped."""
        return str(origin or "").strip().lower().split(":", 1)[0]

    def trigger(self, origin: str | None, reason: str, *,
                cooldown_s: float | None = None) -> bool:
        """Cool an origin down. Returns True when this is a NEW cooldown
        (an expired or never-seen origin), False for an extension."""
        o = self.normalize(origin)
        if not o:
            return False
        now = self._clock()
        fresh = self._until.get(o, 0.0) <= now
        until = now + (self.cooldown_s if cooldown_s is None
                       else float(cooldown_s))
        self._until[o] = max(self._until.get(o, 0.0), until)
        self._reason[o] = reason
        return fresh

    def blocked(self, origin: str | None) -> bool:
        o = self.normalize(origin)
        return bool(o) and self._until.get(o, 0.0) > self._clock()

    def remaining(self, origin: str | None) -> float:
        o = self.normalize(origin)
        return max(0.0, self._until.get(o, 0.0) - self._clock())

    def reason(self, origin: str | None) -> str | None:
        return self._reason.get(self.normalize(origin))

    def active(self) -> dict[str, dict]:
        """Snapshot of currently-cooling origins (for events/digests)."""
        now = self._clock()
        return {
            o: {"reason": self._reason.get(o),
                "remaining_s": round(max(0.0, until - now), 1)}
            for o, until in self._until.items() if until > now
        }
