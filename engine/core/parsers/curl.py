'curl output parser — robots, IMDS, SSTI, CMDI, CORS, CRLF and CSRF probes,\npassthrough.\n\n* a fetch of ``<base>/robots.txt`` is parsed as robots (opsec.parse_robots) and\n  stamps the base asset with the OPSEC facts the burst rules gate on\n  (``robots_host`` / ``canary_paths`` / ``crawl_delay``);\n* a fetch whose command names a link-local metadata endpoint is parsed as an\n  IMDS probe, in two modes that must not be conflated (see below);\n* a fetch whose command injects an arithmetic sentinel is parsed as an SSTI\n  probe and mints ``ssti.suspected`` only on the exact evaluated product (see\n  below);\n* a fetch whose command injects a shell arithmetic echo is parsed as a\n  command-injection probe and mints ``rce`` only on the exact echoed marker\n  (see below);\n* a fetch whose command injects an ``Origin`` header naming an inert sentinel\n  origin is parsed as a CORS probe, and it reads the RESPONSE HEADERS: it mints\n  ``misconfig.cors`` only on a reflected origin AND an allowed-credentials grant\n  (see below);\n * a fetch whose command injects a percent-encoded CR/LF plus a distinctive header\n   name is parsed as a CRLF-injection probe; it reads the RESPONSE HEADERS like the\n   CORS mode and mints ``crlf.injection`` only when the injected header stands\n   alone in the block with exactly the sentinel value (see below);\n * a fetch whose command sends a distinctive custom request header is parsed as a\n   CSRF probe — a PASSIVE fetch that injects nothing into the page. It reads BOTH\n   halves of the response (the HTML body for the form, the header block for\n   ``Set-Cookie``) and mints ``misconfig.csrf`` only on a three-way conjunction\n   (see below);\n * any other curl invocation has no stable shape — the body goes to the dead\n   letter intact (audit trail, never silently dropped).\n\nIMDS mode exists because ``R-VULN-SSRF-CHAIN-001`` declares\n``on_hit_class: ssrf.cloud_imds`` and the hit oracle\n(``_hypothesis_hit(required_class=…)``) credits a hit ONLY from a finding of\nthat class produced by this hypothesis\'s own runs. A parser that stayed silent\nwould leave the rule firing, exiting 0, and minting nothing — coverage on the\nboard, zero evidence on the graph.\n\nThe two modes are told apart by the action\'s command TEMPLATE, which the\norchestrator hands over unrendered (``payload["cmd"] = template``), so this is a\nfact about the invocation and not a guess from the body:\n\n* ``injected`` — the template renders ``{ssrf_url}``/``{ssrf_param}``, i.e. the\n  metadata request was smuggled through a confirmed SSRF point on the TARGET.\n  An echoed metadata listing is target evidence and mints ``ssrf.cloud_imds``;\n* ``local`` — the template names the metadata endpoint directly\n  (``R-CTX-CLOUD-001``). That curl runs on the scanning host, so it describes\n  the EXECUTION ENVIRONMENT, not the target. It is reported as such and mints\n  no finding: attributing our own host\'s cloud membership to a target asset\n  would be a fabricated finding.\n\nSSTI mode exists for the same reason IMDS mode does: ``R-VULN-SSTI-PROBE-001``\ndeclares ``on_hit_class: ssti.suspected`` and routes to the OOB validator, so a\nparser that stayed silent would leave the rule firing, exiting 0, and minting\nnothing. Its discriminator is the arithmetic EXPRESSION literal\n(``_SSTI_PROBE_EXPR``) in the same unrendered template, chosen because that\nliteral is common to every template syntax a probe could inject\n(``{{1337*1337}}``, ``${1337*1337}``, ``<%= 1337*1337 %>``) — mode selection\nand the product oracle read the same constant and cannot drift apart. The\noracle is the exact product standing alone as a digit run, and two weaker\nsignals are refused on purpose: a bare ``49`` (the textbook ``7*7`` canary)\noccurs in benign markup as a percentage width, a port, a price and a counter,\nand a body carrying the injected EXPRESSION proves only that the request\narrived, because a 404 or a WAF block page routinely echoes the request URL\nback. Unlike IMDS mode this one does NOT reject an HTML body: a server-side\ntemplate renders inside the page that reflects the parameter, so HTML is the\nnormal vulnerable shape here, and what replaces the IMDS HTML guard is the\nstrength of the sentinel itself.\n\nThis mode has NO delay oracle, and the omission is deliberate rather than an\noversight. A timing signal needs a recorded baseline for the same endpoint plus\na delta and a margin, and one action yields exactly one observation: ``parse()``\nis handed no duration and no second, uninjected request to compare against, so\nany threshold written here would be invented rather than measured. An\nunbaselined duration is the weakest signal in the family and it is left out\nrather than shipped flaky. What this parser mints is the SUSPECTED finding;\nconfirming it out-of-band is the verification layer\'s job, which is where the\n``rce`` class already routes.\n\nCORS mode exists for the same reason again: ``R-VULN-CORS-PROBE-001`` declares\n``on_hit_class: misconfig.cors``, so a parser that stayed silent would leave the\nrule firing, exiting 0, and minting nothing. It reads the RESPONSE HEADERS\ninstead of the body, a capability the invocation asks for explicitly (``-i``\nputs the headers on the same stdout stream ahead of the body) and that the CRLF\nmode below shares. Its discriminator is the sentinel ORIGIN literal\n(``_CORS_PROBE_ORIGIN``) in the same unrendered template — the value the probe\ninjects as its ``Origin`` request header — and it shares no literal with either\narithmetic sentinel, so one command can never select two modes and one probe\'s\nevidence can never credit another\'s rule.\n\nThe oracle is a CONJUNCTION, and the coupling that keeps it honest is that the\ndiscriminator and the oracle are the SAME literal: the string injected as the\nrequest ``Origin`` is the string ``Access-Control-Allow-Origin`` must equal,\nexactly, for the first half to hold; the second half is\n``Access-Control-Allow-Credentials: true``. Neither half alone is the\nvulnerability, and the two refusals run in different directions — a reflection\nwithout credentials exposes only the anonymous response a stranger can already\nread, while a wildcard cannot be combined with credentials at all because the\ncross-origin check compares that header against the request origin and ``*`` is\nnot an origin. A static allowlist entry, a ``null`` grant this probe never asked\nfor, a repeated ``Access-Control-Allow-Origin`` stacked by an intermediary on top of the\napplication\'s, and a sentinel embedded inside a LONGER origin are refused for\none reason: the comparison is exact and single-valued, so a substring match\ncannot mint. This is the arithmetic modes\' digit-boundary rule wearing a header.\n\nThe header block is DELIMITED, never searched. It is the text before the first\nblank line, and it counts as a header block only when the stream opens with an\nHTTP status line; field names are matched case-insensitively as HTTP requires,\nwhile the credentials value is matched exactly because it is a literal token. A\nbody-only stream — what every other mode here sees, because their invocations\npass no header-dump flag — has no header block at all, so a page that DOCUMENTS\nthe two header names cannot read as a reflection. The probe also never follows a\nredirect, which is what keeps the first block the endpoint\'s own answer rather\nthan a 3xx on the way to somewhere else. Unlike the two arithmetic probes this\none needs no out-of-band leg: the reflected header IS the evidence, observed in\nthe response the probe asked for, which is why the registry grades the class\nTERMINAL and the router sends it to the default replay validator.\n\nCRLF mode exists for the same reason again: ``R-VULN-CRLF-PROBE-001`` declares\n``on_hit_class: crlf.injection``, so a parser that stayed silent would leave the\nrule firing, exiting 0, and minting nothing. It reads the RESPONSE HEADERS like\nthe CORS mode, reusing that mode\'s delimited block (``_response_headers``) rather\nthan growing a second header reader, and the invocation asks for the headers the\nsame way (``-i``). Its discriminator is a percent-encoded CR/LF followed by the\ndistinctive probe header name (``_CRLF_PROBE_TOKEN``, whose tail is that name) in\nthe same unrendered template; it shares no literal with either arithmetic\nsentinel or the CORS origin, so one command can never select two modes and one\nprobe\'s evidence can never credit another\'s rule.\n\nThe oracle is the injected header standing ALONE — present, appearing exactly\nonce, and equal to the sentinel value (``_CRLF_SENTINEL``) — and the coupling\nthat keeps it honest is the CORS mode\'s: the header-name constant is both the\ntail of the discriminator and the key the oracle looks up, and the sentinel is\nboth in the injected payload and the value the oracle demands, so a rule that\nchanges the injected header changes the expected split with it and the two cannot\ndrift. Everything else is refused for one reason, the comparison being exact and\nsingle-valued: a header name that appears only in the BODY proves only that the\nrequest arrived, because a documentation page or a 404 echoing the request URI\ncarries the same bytes, and a body-only stream has no header block to read; a\nheader with any other value, or the sentinel embedded inside a longer value, is a\nstatic or partial reflection rather than a split; and a name stacked twice by a\nlane is ambiguous, so the parser refuses it instead of picking the copy that\nwould mint. Like the CORS probe it needs no out-of-band leg — the split header IS\nthe evidence, observed in the very response the probe asked for — which is why the\nregistry grades the class TERMINAL and the router sends it to the default replay\nvalidator. The probe never follows a redirect, so the block read back is the\nendpoint\'s own answer and not a 3xx on the way to somewhere else.\n\nCSRF mode exists for the same reason again: ``R-VULN-CSRF-PROBE-001`` declares\n``on_hit_class: misconfig.csrf``, so a parser that stayed silent would leave the\nrule firing, exiting 0, and minting nothing. Unlike every mode above it this one\nINJECTS NOTHING. It is a passive fetch of a page the engine already believes is a\nlive application surface, and it reads BOTH halves of the response: the HTML body\nfor the form, and the header block for ``Set-Cookie``, reusing the CORS mode\'s\ndelimited reader (``_response_headers``) for the second. Its discriminator is a\ndistinctive custom request header (``_CSRF_PROBE_MARKER``, the composed\n``Name: value`` pair) in the same unrendered template; it shares no literal with\neither arithmetic sentinel, the CORS origin or the CRLF header and sentinel, and\nit is not a URL, so it can never name a metadata host or a ``/robots.txt`` suffix\n— one command can never select two modes and one probe\'s evidence can never credit\nanother\'s rule.\n\nThe marker rides in a REQUEST HEADER because the oracle reads the page as the\nendpoint\'s OWN unaltered answer, and a marker that changed that answer would make\nthe reading circular: this is the one mode here whose evidence is the page\'s\npre-existing state rather than a reaction to a payload. That is also why the\npredicate demands the composed ``Name: value`` pair and not the name alone — a\nrule edit that moved the marker into the query, turning a passive fetch into an\ninjection that could alter the page, deselects the mode instead of quietly reading\nan altered page as evidence. A server ignores an unknown ``X-`` header, so the\nfetch is indistinguishable from an ordinary page view apart from that one field.\n\nThe oracle is a THREE-WAY CONJUNCTION, and it is the most refusal-heavy one in\nthis file because it is the one whose individual halves are weakest. All three\nmust hold or nothing is minted:\n\n* a STATE-CHANGING FORM — the body carries exactly one ``<form>`` whose method is\n  POST, PUT or DELETE, and that form is CLOSED. A form whose method is GET, or\n  that carries no method attribute at all (HTML\'s default is GET), submits a query\n  and changes nothing, so there is no state change to forge;\n* NO ANTI-CSRF TOKEN — no ``<input>`` anywhere on the page carries a token-like\n  ``name`` or ``id``, and no ``<meta name>`` does either (the double-submit\n  pattern). The token matcher is deliberately GENEROUS, and the generosity runs in\n  the safe direction: a name it catches that was not really a token costs one\n  miss, while a name it misses costs a false positive on a protected form;\n* COOKIE-BASED AMBIENT AUTH WITHOUT PROTECTIVE SameSite — the response sets at\n  least one cookie AND at least one of them carries ``SameSite=None``, exactly and\n  single-valued. ``None`` is the ONLY value that satisfies this conjunct, because\n  it is the only one that tells a browser to send the cookie on a cross-site\n  request. ``Strict`` and ``Lax`` both block it, and — this is a deliberate\n  reading, not an oversight — a MISSING ``SameSite`` attribute blocks it too,\n  because every current browser defaults an attribute-less cookie to ``Lax``. A\n  page that simply omits the attribute is therefore reported as protected, which\n  costs recall on the legacy browsers that had no default and buys precision on\n  every modern site that omits it and is not vulnerable. No cookie at all means no\n  ambient auth is visible from a single stateless fetch.\n\nEverything else is refused, and the refusals are the point rather than the\nresidue: no header block (so no ``Set-Cookie`` to read, and a body is never header\nevidence); no body; markup the reader cannot walk at all; markup it can walk but\nwill not interpret — a ``<form>`` nested in a ``<form>``, a method attribute with\nno value, a method value outside the two known sets, a stray ``</form>``; more\nthan one state-changing form, because which of them is unprotected cannot be\nattributed confidently; an unclosed state-changing form, because a truncated page\ncannot be attributed its inputs. Each refusal names what WAS observed, so an\noperator can tell "protected" from "could not tell".\n\nTwo limits are recorded rather than papered over. The protection this probe\ncannot see is a custom request header or an ``Origin``/``Referer`` check enforced\nserver-side: neither is observable from a single passive GET, so a minted finding\nis a LOW-CONFIDENCE triage signal that cannot rule them out, and the finding says\nso on its own record. The second is that one stateless fetch sees only the cookies\nTHIS response sets — a session cookie issued at login is invisible to it — so the\ncookie conjunct can UNDER-detect. Both are the accepted price of an oracle that\nnever guesses, and both are carried on the minted finding rather than left in this\ndocstring alone. Like the CORS and CRLF probes it needs no out-of-band leg: the\ngap is observed in the very response the probe asked for, which is why the\nregistry grades the class TERMINAL and the router sends it to the default replay\nvalidator.\n\n* a 404 page arrives on stdout with exit **0** (no ``-f`` in the corpus), so the\n  exit code proves nothing and an HTML body must never read as metadata;\n* a refused connect is exit 7 with curl\'s diagnostic on stderr and empty stdout.\n\nCoverage limits, recorded rather than papered over: only the AWS/Alibaba shape\n(a bare key listing) is recognised. GCP needs ``Metadata-Flavor: Google`` and\nAzure needs ``Metadata: true``, and neither header is in the corpus command, so\na GCP/Azure target answers 403 and this parser correctly reports "no metadata\nechoed" instead of inventing a hit. The SSTI probe has the same shape of limit\non the other side: one corpus command injects one template syntax, so a target\nrunning a different engine answers with a literal echo and this parser reports\n"no evaluated product" instead of inventing a hit. The command-injection probe\ncarries three limits of the same kind: it injects ONE separator (``;``), so an\ninjection point that only breaks out on a newline, or that sits inside a quoted\nshell argument, answers with a literal echo; the marker needs POSIX arithmetic\nexpansion, so an interpreter without ``$(())`` answers the same way; and the\npayload spends a space, so a filter that rejects whitespace in a parameter value\nanswers the same way. In each of those cases this parser reports "no evaluated\nmarker" instead of inventing a hit. The CORS probe carries two limits of the\nsame kind: it injects ONE origin scheme (``https``), so an endpoint that\nreflects only a plain-HTTP origin answers with no grant at all; and it reads the\nFIRST header block, so a redirect-following variant of the command would read a\n3xx instead of the endpoint\'s own answer — which is why the corpus command\npasses no ``-L``, and why adding one would need this paragraph rewritten first.\nIn each of those cases this parser reports "no credentialed reflection" instead\nof inventing a hit. The CRLF probe carries two limits of the same kind: it\ninjects ONE header name and ONE sentinel value, so an endpoint that reflects a\nCR/LF but strips, folds or rewrites the injected header answers with no split;\nand it reads the FIRST header block, so a redirect-following variant of the\ncommand would read a 3xx instead of the endpoint\'s own answer — the same ``-L``\nboundary the CORS probe records. In each of those cases this parser reports "no\nsplit header" instead of inventing a hit. The CSRF probe carries four limits of\nthe same kind, and they are the widest in this file because its oracle is the only\none that reads a PAGE rather than a marker: it recognises ONE token vocabulary, so\na framework whose anti-CSRF field is named outside ``_CSRF_TOKEN_MARKERS`` reads as\nunprotected — the matcher is generous for exactly this reason, and the generous\ndirection is the one that costs a miss rather than a false positive; it reads ONE\n``Set-Cookie`` per header line, so a cookie folded into a single repeated field by\na lane is refused as ambiguous rather than split; it sees only the cookies THIS\nresponse sets, so a session cookie issued at login is invisible and the conjunct\nunder-detects; and it cannot observe a custom-header or ``Origin``/``Referer``\ncheck at all, because neither leaves a trace in one passive GET. In each of those\ncases this parser reports which conjunct failed instead of inventing a gap. All\nfive probe modes are also unproven in vivo — no vulnerable target was queried to\ncapture a real evaluated, reflected, split or unprotected response, and the\nfixtures in ``tests/test_curl_ssti.py``, ``tests/test_curl_cmdi.py``,\n``tests/test_curl_cors.py``, ``tests/test_curl_crlf.py`` and\n``tests/test_curl_csrf.py`` encode the documented response shape rather than a\ncapture.\n'

from __future__ import annotations

import re
from html.parser import HTMLParser
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

# The arithmetic sentinel an SSTI probe injects, and the product a template
# that EVALUATED it must render. The expression is the discriminator and the
# product is the oracle, and they are the same arithmetic — that coupling is
# the point: a rule that changed one without the other would select the mode
# and never match, or match a product nobody asked for.
#
# The product must stand alone as a digit run. A substring search would mint
# on a request id or a millisecond timestamp that happens to embed the seven
# digits, which is the same class of false positive `_IMDS_MIN_HITS` exists to
# close on the metadata side.
_SSTI_PROBE_EXPR = "1337*1337"
_SSTI_PRODUCT = "1787569"                     # 1337 * 1337
_SSTI_PRODUCT_RE = re.compile(rf"(?<!\d){_SSTI_PRODUCT}(?!\d)")

# The arithmetic sentinel a command-injection probe injects, and the marker a
# shell that EVALUATED it must echo. The coupling is the same as the SSTI pair
# above, and the arithmetic is deliberately a DIFFERENT one: the two probes'
# sentinels share no literal, so one command can never select both modes and one
# probe's marker can never credit the other's rule.
#
# The marker must stand alone as a digit run, for the reason the SSTI product
# must: a substring search would mint on a trace id or a millisecond timestamp
# that happens to embed the seven digits.
_CMDI_PROBE_EXPR = "1339*1339"
_CMDI_MARKER = "1792921"                      # 1339 * 1339
_CMDI_MARKER_RE = re.compile(rf"(?<!\d){_CMDI_MARKER}(?!\d)")

# The origin a CORS probe injects as its `Origin` request header, which is also
# the value the response must reflect back. ONE literal on both sides, and that
# is the coupling: the discriminator that selects the mode and the string the
# oracle demands in `Access-Control-Allow-Origin` are the same constant, so a
# rule that changes the injected origin changes the expected reflection with it
# and the two cannot drift apart. It shares no literal with either arithmetic
# sentinel above, so one command can never select two modes.
#
# `.invalid` is the reserved TLD, so the sentinel can never be a registrable
# origin: the probe cannot be mistaken for a real cross-origin reader, and any
# grant that comes back cannot have been meant for anyone.
_CORS_PROBE_ORIGIN = "https://cors-probe.invalid"

# The two response header fields the oracle reads, spelled in the lower case
# this parser normalises every field name to — HTTP field names are
# case-insensitive, so a match that was not would refuse real hits on any
# server that capitalises differently. The credentials VALUE is NOT normalised:
# it is a literal token that the cross-origin check compares to `true` exactly,
# so `True` is refused in the same fail-closed direction as an absent header.
_CORS_ACAO = "access-control-allow-origin"
_CORS_ACAC = "access-control-allow-credentials"
_CORS_CREDENTIALED = "true"

# The header name and sentinel value a CRLF-injection probe injects, and the
# token that selects the mode off the unrendered template. The name is a
# distinctive `X-` header no legitimate response emits; the sentinel is a
# literal token the oracle matches exactly. The coupling that keeps the two
# honest is the same one the CORS mode relies on: the header-name constant is
# BOTH the tail of the discriminator token AND the key the oracle looks up in
# the parsed header block, and the sentinel constant is BOTH in the injected
# payload AND the value the oracle demands — one source of truth on each side,
# so a rule that changes the injected header changes the expected split with it
# and the two cannot drift apart.
#
# Neither literal shares a substring with the two arithmetic sentinels or the
# CORS origin above, so one command can never select two modes and one probe's
# evidence can never credit another's rule. The discriminator carries the
# percent-encoded CRLF (`%0d%0a`) in front of the header name: a bare encoded
# CRLF could ride in any URL, so the token requires the distinctive name after
# it before this mode is selected.
_CRLF_PROBE_HEADER = "X-Crlf-Split-Marker"
_CRLF_SENTINEL = "crlf-split-sentinel"
_CRLF_PROBE_TOKEN = "%0d%0a" + _CRLF_PROBE_HEADER

# The custom request header a CSRF probe sends, and the composed `Name: value`
# pair that selects the mode off the unrendered template. This probe injects
# NOTHING into the page: the oracle reads the page as the endpoint's own unaltered
# answer, so a marker that could change that answer would make the reading
# circular. A server ignores an unknown `X-` header, which is what makes the fetch
# passive, and demanding the COMPOSED pair rather than the name alone is the
# coupling that keeps it that way — a rule edit that moved the marker into the
# query, turning a passive fetch into an injection, deselects the mode instead of
# quietly reading an altered page as evidence.
#
# Neither literal shares a substring with the two arithmetic sentinels, the CORS
# origin or the CRLF header and sentinel above, and the marker is not a URL, so it
# can never name a metadata host or end in a `/robots.txt` suffix: one command can
# never select two modes and one probe's evidence can never credit another's rule.
_CSRF_PROBE_HEADER = "X-Form-Protection-Audit"
_CSRF_PROBE_VALUE = "passive-form-audit"
_CSRF_PROBE_MARKER = f"{_CSRF_PROBE_HEADER}: {_CSRF_PROBE_VALUE}"

# The form methods that change state on the target, and the two spellings that
# provably do not. A `<form>` with no method attribute submits a query — HTML's
# missing-value default is GET — and so does an explicit `method=""`, so neither
# is a state change worth forging. Every OTHER value (a valueless attribute, an
# unknown token, a repeated attribute) is recorded as ambiguous and refused rather
# than read as GET: this oracle's whole value is that it never guesses, and a
# method it cannot interpret is a page it cannot call unprotected.
_CSRF_STATE_CHANGING = frozenset({"post", "put", "delete"})
_CSRF_READ_ONLY = frozenset({"get", ""})

# Substrings that make an input's name or id — or a `<meta name>` — look like an
# anti-CSRF token. Matched case-insensitively as substrings, so one list covers
# `csrf`, `csrfmiddlewaretoken`, `_token`, `__RequestVerificationToken`, Rails'
# `authenticity_token`, Laravel's `_token`, a bare `nonce` and the double-submit
# `<meta name="csrf-token">` alike. `token` subsumes `_token` and every other
# `*token*` spelling; the rest are the families that do not contain that word.
#
# The list is deliberately GENEROUS, and the generosity runs in the safe
# direction: a name it catches that was not really a token costs one miss, while a
# name it misses costs a false positive on a form that IS protected. That asymmetry
# is the whole reason this family is graded as the batch's highest
# false-positive risk and answered with a conjunction instead of a heuristic.
_CSRF_TOKEN_MARKERS = (
    "csrf", "xsrf", "token", "nonce", "authenticity", "requestverification",
    "auth_key", "authkey", "antiforgery", "anti_forgery", "anti-forgery",
    "formkey", "form_key",
)

# The one `SameSite` value that satisfies the cookie conjunct. `None` is the only
# spelling that tells a browser to send the cookie on a CROSS-SITE request;
# `Strict` and `Lax` both block it, and so does a MISSING attribute, because every
# current browser defaults an attribute-less cookie to `Lax`. Reading "missing" as
# protected is a deliberate deviation from the literal "no SameSite cookie"
# phrasing this mode was scoped against: flagging a missing attribute would fire on
# every modern site that omits it and relies on the browser default, which is
# precisely the false positive the conjunction exists to refuse. The cost is recall
# on the legacy browsers that had no default, and it is recorded rather than hidden.
#
# Values are compared lower-cased (the attribute is case-insensitive) and
# single-valued, so a cookie carrying `SameSite` twice is refused as ambiguous
# instead of having the copy that would mint picked out of it — the exactness the
# CORS and CRLF oracles apply to a repeated header field.
_CSRF_SAMESITE_CROSS_SITE = "none"


class _FormFacts(HTMLParser):
    """The page facts the CSRF conjunction reads, in document order.

    `html.parser` is the stdlib's forgiving reader: it lower-cases tag and
    attribute names, unquotes and unescapes attribute values, and tolerates the
    attribute-order, quoting and case variance real pages carry — which is why
    this mode walks the markup instead of regexing it. Forgiving is not the same
    as safe, so the shapes a guess would be needed for are RECORDED as ambiguous
    rather than interpreted: a `<form>` nested inside a `<form>` (invalid markup,
    so which element an input belongs to is a guess), a `</form>` with no form
    open, a method attribute present with no value, a repeated method attribute,
    and a method value outside the two known sets. A form that never closes is
    recorded as unclosed rather than dropped, because a truncated page is the
    common cause and an unclosed form cannot be attributed its inputs.

    Nothing here raises into the caller: `_csrf_page` wraps the walk and returns
    None on any exception, which the oracle reports as an unreadable page and
    mints nothing.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.token_names: list[str] = []
        self.ambiguous: list[str] = []
        self._open = 0

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self._open += 1
            if self._open > 1:
                self.ambiguous.append("a <form> nested inside a <form>")
            self.forms.append({"method": self._method(attrs), "closed": False})
        elif tag == "input":
            self._collect(attrs, ("name", "id"))
        elif tag == "meta":
            # The double-submit pattern puts the token in a `<meta name>` rather
            # than in a field, so a page-level meta protects the form too.
            self._collect(attrs, ("name",))

    def handle_endtag(self, tag):
        if tag != "form":
            return
        if not self._open:
            self.ambiguous.append("a </form> with no <form> open")
            return
        self._open -= 1
        for form in reversed(self.forms):
            if not form["closed"]:
                form["closed"] = True
                break

    def _method(self, attrs) -> str | None:
        """The normalised method, or None when this reader will not guess."""
        values = [v for k, v in attrs if k == "method"]
        if not values:
            return ""                       # absent -> HTML's default, GET
        if len(values) > 1:
            self.ambiguous.append("a repeated method attribute on one <form>")
            return None
        raw = values[0]
        if raw is None:
            self.ambiguous.append("a method attribute with no value")
            return None
        text = str(raw).strip().lower()
        if text in _CSRF_STATE_CHANGING or text in _CSRF_READ_ONLY:
            return text
        self.ambiguous.append(f"a method this reader does not interpret ({text!r})")
        return None

    def _collect(self, attrs, keys) -> None:
        """Every token-like value on the named attributes of one start tag."""
        for key, value in attrs:
            if key not in keys or not value:
                continue
            text = str(value).strip()
            if any(marker in text.lower() for marker in _CSRF_TOKEN_MARKERS):
                self.token_names.append(text)


def _csrf_page(body: str) -> _FormFacts | None:
    """Walk a page for the CSRF conjunction, or None when it cannot be walked.

    ``html.parser`` is forgiving, so a shape that reaches the except clause is
    genuinely broken markup — and broken markup is exactly the case where a token
    could be hiding in a fragment this reader never saw. Fail closed: None, and the
    caller reports an unreadable page and mints nothing.
    """
    facts = _FormFacts()
    try:
        facts.feed(body)
        facts.close()
    except Exception:
        return None
    return facts


# The limits this finding carries on its OWN record rather than leaving in the
# module docstring: they are what make it a triage signal and not a confirmed
# vulnerability, and an operator reading the graph alone — with no access to this
# file — has to see them beside the class. Kept as one constant so the docstring,
# the rule's hypothesis text and the persisted finding cannot drift apart about
# what the oracle does not know.
_CSRF_FINDING_LIMITS = (
    "low-confidence operator-triage signal, never an auto-confirmed vulnerability",
    "a custom request header or an Origin/Referer check enforced server-side "
    "leaves no trace in a single passive GET, so this finding cannot rule one out",
    "only the cookies THIS response sets are visible; a session cookie issued at "
    "login is not, so the cookie conjunct can under-detect",
    "a browser also requires Secure before it stores a SameSite=None cookie, so a "
    "cross-site cookie sent without Secure may never be sent at all",
)

# Upper bound on the canary paths stamped onto the asset. A robots.txt with
# more Disallow entries than this is hostile or broken; the summary reports
# the truncation so the burst gate never sees a silently shortened list.
_CANARY_PATH_CAP = 512


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
        if self._ssti_probe(action):
            return self._ssti_result(stdout, stderr, action)
        if self._cmdi_probe(action):
            return self._cmdi_result(stdout, stderr, action)
        if self._cors_probe(action):
            return self._cors_result(stdout, stderr, action)
        if self._crlf_probe(action):
            return self._crlf_result(stdout, stderr, action)
        if self._csrf_probe(action):
            return self._csrf_result(stdout, stderr, action)
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

    # -- SSTI ----------------------------------------------------------
    def _ssti_probe(self, action: dict) -> bool:
        """Is this curl an arithmetic-sentinel template-injection probe?"""
        # The template arrives UNRENDERED, and the orchestrator hands over the
        # variant it actually rendered (`cmd` or `cmd_<intensity>`), so the
        # expression is visible in every intensity. Reading the template and
        # never the body is what keeps this a fact about the invocation: a
        # benign fetch whose response happens to contain seven digits does not
        # select the mode, while a probe that came back empty still does, and
        # is reported as a probe that came back empty.
        return _SSTI_PROBE_EXPR in str(action.get("cmd") or "")

    def _ssti_result(self, stdout, stderr, action: dict):
        body = stdout or ""
        url = str(action.get("url") or "")
        if _SSTI_PRODUCT_RE.search(body):
            if not url:
                # A hit we cannot aim a follow-up at is not deliverable
                # evidence (M2): ingest refuses a url-less finding, and the
                # OOB validator this class routes to needs a url to re-send
                # its canary through.
                return self._result(
                    summary=("curl SSTI: arithmetic sentinel evaluated — the "
                             f"response carries the exact product "
                             f"{_SSTI_PRODUCT}, but the action carries no "
                             "observation URL — no finding minted"),
                    dead_letter=[body[:2000]])
            return self._result(
                summary=("curl SSTI: template expression evaluated server-side "
                         f"— the response carries the exact product "
                         f"{_SSTI_PRODUCT} of the injected {_SSTI_PROBE_EXPR}"),
                findings=[self._finding(
                    class_="ssti.suspected",
                    title="server-side template expression evaluated "
                          "(arithmetic sentinel echoed)",
                    url=url,
                    severity="high",
                    extra={"ssti_expr": _SSTI_PROBE_EXPR,
                           "ssti_product": _SSTI_PRODUCT},
                )],
                dead_letter=[body[:2000]])
        # No product. An HTML body is NOT a rejection here — a server-side
        # template renders inside the page that reflects the parameter, so the
        # vulnerable shape is normally HTML. What decides is the sentinel alone.
        if not body.strip():
            detail = (stderr or "").strip().splitlines()
            return self._result(
                summary=("curl SSTI: empty body — the probe returned nothing"
                         + (f" ({detail[-1][:120]})" if detail else "")),
                dead_letter=[(stderr or "")[:2000]] if stderr else [])
        return self._result(
            summary=("curl SSTI: no evaluated product "
                     f"({_SSTI_PRODUCT}) in the response — the expression was "
                     "not rendered server-side, format not assumed"),
            dead_letter=[body[:2000]])

    # -- command injection ---------------------------------------------
    def _cmdi_probe(self, action: dict) -> bool:
        """Is this curl a shell-arithmetic command-injection probe?"""
        return _CMDI_PROBE_EXPR in str(action.get("cmd") or "")

    def _cmdi_result(self, stdout, stderr, action: dict):
        body = stdout or ""
        url = str(action.get("url") or "")
        if _CMDI_MARKER_RE.search(body):
            if not url:
                # A hit we cannot aim a follow-up at is not deliverable
                # evidence (M2): ingest refuses a url-less finding, and the
                # OOB validator this class routes to needs a url to re-send
                # its canary through.
                return self._result(
                    summary=("curl CMDI: shell arithmetic evaluated — the "
                             f"response carries the exact marker "
                             f"{_CMDI_MARKER}, but the action carries no "
                             "observation URL — no finding minted"),
                    dead_letter=[body[:2000]])
            # `critical`, not the SSTI mode's `high`: an evaluated arithmetic
            # marker means the target's shell already ran an expression this
            # engine supplied, which is execution itself rather than a
            # precondition for it. The same grade parsers/sqlmap.py gives a
            # confirmed injectable parameter — echo-confirmed, pre-OOB.
            return self._result(
                summary=("curl CMDI: injected command evaluated server-side — "
                         f"the response carries the exact marker "
                         f"{_CMDI_MARKER} of the injected {_CMDI_PROBE_EXPR}"),
                findings=[self._finding(
                    class_="rce",
                    title="shell command evaluated through a parameter "
                          "(echo marker reflected)",
                    url=url,
                    severity="critical",
                    extra={"cmdi_expr": _CMDI_PROBE_EXPR,
                           "cmdi_marker": _CMDI_MARKER},
                )],
                dead_letter=[body[:2000]])
        # No marker. An HTML body is NOT a rejection here either — a diagnostic
        # endpoint reflects the command's stdout inside the page that ran it, so
        # the vulnerable shape is often HTML. The marker alone decides, and the
        # exit code is never consulted: a 404 arrives on stdout with exit 0, and
        # `parse()` is not handed an exit code at all.
        if not body.strip():
            detail = (stderr or "").strip().splitlines()
            return self._result(
                summary=("curl CMDI: empty body — the probe returned nothing"
                         + (f" ({detail[-1][:120]})" if detail else "")),
                dead_letter=[(stderr or "")[:2000]] if stderr else [])
        return self._result(
            summary=("curl CMDI: no evaluated marker "
                     f"({_CMDI_MARKER}) in the response — the injected "
                     "expression was not run by a shell, format not assumed"),
            dead_letter=[body[:2000]])

    # -- CORS ------------------------------------------------------------
    def _cors_probe(self, action: dict) -> bool:
        """Is this curl an injected-Origin cross-origin probe?"""
        return _CORS_PROBE_ORIGIN in str(action.get("cmd") or "")

    def _response_headers(self, stdout) -> dict[str, list[str]] | None:
        """Header fields off a header-dumping stdout, or None with no block.

        None means the stream does not open with an HTTP status line, i.e. the
        invocation put no response headers on stdout and this is a body alone —
        the shape every other mode in this parser sees. A body is never header
        evidence: the block is DELIMITED by the status line and the first blank
        line rather than searched, so a page documenting the two CORS header
        names cannot read as a reflection.

        Names are lower cased (HTTP field names are case-insensitive); values
        keep their case, because the credentials value is a literal token. A
        repeated name keeps every value in order, so the oracle can SEE the
        ambiguity and refuse it instead of inheriting one arbitrary copy.
        """
        text = stdout or ""
        # A lone LF is a line terminator and a preceding CR is ignored, so a
        # server or an intercepting middlebox that emits bare LF splits the same
        # way and no value keeps a trailing CR.
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines[0].startswith("HTTP/"):
            return None
        end = next((i for i, ln in enumerate(lines[1:], 1) if not ln.strip()),
                   None)
        fields: dict[str, list[str]] = {}
        for line in lines[1:] if end is None else lines[1:end]:
            name, sep, value = line.partition(":")
            if not sep:
                continue          # an obs-fold continuation carries no name
            fields.setdefault(name.strip().lower(), []).append(value.strip())
        return fields

    def _cors_result(self, stdout, stderr, action: dict):
        stream = stdout or ""
        url = str(action.get("url") or "")
        fields = self._response_headers(stream)
        if fields is None:
            if not stream.strip():
                detail = (stderr or "").strip().splitlines()
                return self._result(
                    summary=("curl CORS: empty response — the probe returned "
                             "nothing"
                             + (f" ({detail[-1][:120]})" if detail else "")),
                    dead_letter=[(stderr or "")[:2000]] if stderr else [])
            return self._result(
                summary=("curl CORS: no response-header block on stdout — the "
                         "invocation put no headers there, so there is no "
                         "grant to read and a body is never header evidence"),
                dead_letter=[stream[:2000]])
        acao = fields.get(_CORS_ACAO, [])
        acac = fields.get(_CORS_ACAC, [])
        # The conjunction, exact and single-valued on both sides. A repeated
        # field is read as one comma-joined value, which is not an origin, so
        # the cross-origin check refuses it and this parser refuses with it
        # rather than picking the copy that would mint.
        reflected = acao == [_CORS_PROBE_ORIGIN]
        credentialed = acac == [_CORS_CREDENTIALED]
        if reflected and credentialed:
            if not url:
                # A hit we cannot aim a follow-up at is not deliverable
                # evidence (M2): ingest refuses a url-less finding, and the
                # replay validator this class routes to has nothing to
                # re-send.
                return self._result(
                    summary=("curl CORS: credentialed reflection observed — "
                             f"the injected origin {_CORS_PROBE_ORIGIN} came "
                             "back with credentials allowed, but the action "
                             "carries no observation URL — no finding minted"),
                    dead_letter=[stream[:2000]])
            # `high`, not the command-injection mode's `critical`: this one is
            # confirmed by observation, but spending it needs a victim browser
            # session, whereas an echoed shell marker is execution the target
            # already performed. `critical` is what this corpus reserves for
            # confirmed injection and verified secret material.
            return self._result(
                summary=("curl CORS: credentialed cross-origin reflection — "
                         "Access-Control-Allow-Origin echoes the injected "
                         f"origin {_CORS_PROBE_ORIGIN} exactly and "
                         "Access-Control-Allow-Credentials is true, so an "
                         "outside origin can read an authenticated response"),
                findings=[self._finding(
                    class_="misconfig.cors",
                    title="credentialed CORS origin reflection (injected "
                          "Origin echoed with Allow-Credentials: true)",
                    url=url,
                    severity="high",
                    extra={"cors_origin": _CORS_PROBE_ORIGIN,
                           "cors_credentials": _CORS_CREDENTIALED},
                )],
                dead_letter=[stream[:2000]])
        # No conjunction. The refusals are reported in the order a reader needs
        # them — which half failed, and what was actually observed — and the
        # exit code is never consulted: `parse()` is not handed one, and an
        # error response arrives on stdout with exit 0 anyway.
        if not acao:
            return self._result(
                summary=("curl CORS: no Access-Control-Allow-Origin in the "
                         "response header block — the endpoint made no "
                         "cross-origin grant at all"),
                dead_letter=[stream[:2000]])
        if acao == ["*"]:
            return self._result(
                summary=("curl CORS: Access-Control-Allow-Origin is the "
                         "wildcard * — not a reflection, and a wildcard cannot "
                         "be combined with credentials at all, so no "
                         "authenticated response is readable cross-origin"),
                dead_letter=[stream[:2000]])
        if not reflected:
            return self._result(
                summary=("curl CORS: Access-Control-Allow-Origin is "
                         f"{', '.join(acao)} — not the injected origin "
                         f"{_CORS_PROBE_ORIGIN}, so a value this probe never "
                         "sent is a static grant rather than a reflection"),
                dead_letter=[stream[:2000]])
        return self._result(
            summary=("curl CORS: the injected origin "
                     f"{_CORS_PROBE_ORIGIN} is reflected but "
                     "Access-Control-Allow-Credentials is "
                     f"{', '.join(acac) or 'absent'} — without credentials a "
                     "cross-origin reader gets the anonymous response, so "
                     "there is nothing to exfiltrate"),
            dead_letter=[stream[:2000]])

    # -- CRLF injection (response splitting) -----------------------------
    def _crlf_probe(self, action: dict) -> bool:
        """Is this curl a CRLF-injection (response-splitting) probe?"""
        return _CRLF_PROBE_TOKEN in str(action.get("cmd") or "")

    def _crlf_result(self, stdout, stderr, action: dict):
        stream = stdout or ""
        url = str(action.get("url") or "")
        fields = self._response_headers(stream)
        if fields is None:
            if not stream.strip():
                detail = (stderr or "").strip().splitlines()
                return self._result(
                    summary=("curl CRLF: empty response — the probe returned "
                             "nothing"
                             + (f" ({detail[-1][:120]})" if detail else "")),
                    dead_letter=[(stderr or "")[:2000]] if stderr else [])
            return self._result(
                summary=("curl CRLF: no response-header block on stdout — the "
                         "invocation put no headers there, so there is no split "
                         "to read and a body is never header evidence"),
                dead_letter=[stream[:2000]])
        injected = fields.get(_CRLF_PROBE_HEADER.lower(), [])
        # The split is confirmed only when the injected header stands ALONE in
        # the block with EXACTLY the sentinel value. Exact and single-valued, so
        # a header present with any other value, the sentinel embedded in a
        # longer value, or the name stacked twice by an intermediary all fail the same
        # comparison — a repeated field is ambiguous and this parser refuses it
        # rather than picking the copy that would mint.
        if injected == [_CRLF_SENTINEL]:
            if not url:
                # A hit we cannot aim a follow-up at is not deliverable
                # evidence (M2): ingest refuses a url-less finding, and the
                # replay validator this class routes to has nothing to re-send.
                return self._result(
                    summary=("curl CRLF: header split observed — the injected "
                             f"{_CRLF_PROBE_HEADER}: {_CRLF_SENTINEL} came back "
                             "as a real response header, but the action carries "
                             "no observation URL — no finding minted"),
                    dead_letter=[stream[:2000]])
            # `high`, not the command-injection mode's `critical`: a split
            # header is confirmed by observation, but it is a precondition for
            # cache poisoning or a header-injection chain rather than execution
            # the target already performed. `critical` is what this corpus
            # reserves for confirmed code/command injection and verified secret
            # material — the same boundary the CORS mode records.
            return self._result(
                summary=("curl CRLF: HTTP response splitting confirmed — the "
                         f"injected header {_CRLF_PROBE_HEADER}: "
                         f"{_CRLF_SENTINEL} stands on its own in the response "
                         "header block, so a CR/LF in the parameter broke out "
                         "of the value it was reflected into"),
                findings=[self._finding(
                    class_="crlf.injection",
                    title="HTTP response splitting (injected header reflected "
                          "into the response header block)",
                    url=url,
                    severity="high",
                    extra={"crlf_header": _CRLF_PROBE_HEADER,
                           "crlf_value": _CRLF_SENTINEL},
                )],
                dead_letter=[stream[:2000]])
        # No split. The refusals are reported in the order a reader needs them —
        # was the header there at all, was it ambiguous, and what value did it
        # carry — and the exit code is never consulted: `parse()` is not handed
        # one, and an error response arrives on stdout with exit 0 anyway.
        if not injected:
            return self._result(
                summary=("curl CRLF: no " + _CRLF_PROBE_HEADER + " in the "
                         "response header block — the parameter was reflected "
                         "without splitting a new header out, so the request "
                         "arrived but nothing was injected"),
                dead_letter=[stream[:2000]])
        if len(injected) > 1:
            return self._result(
                summary=("curl CRLF: " + _CRLF_PROBE_HEADER + " appears "
                         f"{len(injected)} times ({', '.join(injected)}) — a "
                         "repeated header is ambiguous, so this parser refuses "
                         "it instead of picking the copy that would mint"),
                dead_letter=[stream[:2000]])
        return self._result(
            summary=("curl CRLF: " + _CRLF_PROBE_HEADER + " is "
                     f"{injected[0]} — not the injected sentinel "
                     f"{_CRLF_SENTINEL}, so a value this probe did not inject "
                     "is a static header rather than a split"),
            dead_letter=[stream[:2000]])

    # -- CSRF (form-protection gap) --------------------------------------
    def _csrf_probe(self, action: dict) -> bool:
        """Is this curl a passive form-protection (CSRF) probe?"""
        return _CSRF_PROBE_MARKER in str(action.get("cmd") or "")

    def _response_body(self, stdout) -> str:
        """The body after the delimited header block, or '' with no block.

        The same delimiter ``_response_headers`` uses — the first blank line after
        a stream that opens with an HTTP status line, with a lone LF accepted as a
        terminator — so the two readers cannot disagree about where the headers end
        and the page begins. It is a SIBLING of that method rather than a refactor
        of it on purpose: the CORS and CRLF modes were measured against
        ``_response_headers`` exactly as it stands, and the one mode that needs the
        body must not change a reader two landed modes depend on. '' means there is
        no body to walk, which the oracle reports and mints nothing on.
        """
        text = stdout or ""
        lines = text.replace("\r\n", "\n").split("\n")
        if not lines[0].startswith("HTTP/"):
            return ""
        end = next((i for i, ln in enumerate(lines[1:], 1) if not ln.strip()),
                   None)
        return "\n".join(lines[end + 1:]) if end is not None else ""

    def _cookie_samesite(self, value: str) -> tuple[str, list[str], bool]:
        """(name, every SameSite value, Secure present) off one Set-Cookie line.

        Attributes are the ``;``-separated tail after the name=value pair. Keys are
        lower-cased, and so are the SameSite values, because that attribute is
        case-insensitive in the browser — unlike the CORS credentials value, which
        is compared exactly because it is a literal token in a cross-origin check.
        EVERY SameSite value is kept rather than the first one, so the oracle can
        SEE a cookie that carries the attribute twice and refuse it instead of
        inheriting whichever copy would mint.
        """
        parts = [p.strip() for p in str(value or "").split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else ""
        samesite: list[str] = []
        secure = False
        for attr in parts[1:]:
            key, _sep, val = attr.partition("=")
            low = key.strip().lower()
            if low == "samesite":
                samesite.append(val.strip().lower())
            elif low == "secure":
                secure = True
        return name, samesite, secure

    def _csrf_result(self, stdout, stderr, action: dict):
        stream = stdout or ""
        url = str(action.get("url") or "")
        fields = self._response_headers(stream)
        if fields is None:
            # The cookie conjunct is a HEADER fact, so a stream with no header
            # block cannot establish it however unprotected the page looks. A body
            # is never header evidence — the same refusal the CORS and CRLF modes
            # make, and the reason a page documenting `Set-Cookie: …; SameSite=None`
            # cannot mint.
            if not stream.strip():
                detail = (stderr or "").strip().splitlines()
                return self._result(
                    summary=("curl CSRF: empty response — the probe returned "
                             "nothing"
                             + (f" ({detail[-1][:120]})" if detail else "")),
                    dead_letter=[(stderr or "")[:2000]] if stderr else [])
            return self._result(
                summary=("curl CSRF: no response-header block on stdout — the "
                         "invocation put no headers there, so there is no "
                         "Set-Cookie to read and the cookie conjunct cannot be "
                         "established; a body is never header evidence"),
                dead_letter=[stream[:2000]])
        page = self._response_body(stream)
        if not page.strip():
            return self._result(
                summary=("curl CSRF: no HTML body after the header block — a "
                         "response with nothing to walk carries no form"),
                dead_letter=[stream[:2000]])
        facts = _csrf_page(page)
        if facts is None:
            return self._result(
                summary=("curl CSRF: the HTML could not be parsed — a page this "
                         "reader cannot walk is not a page this oracle can call "
                         "unprotected"),
                dead_letter=[stream[:2000]])
        if facts.ambiguous:
            return self._result(
                summary=("curl CSRF: ambiguous markup — "
                         + "; ".join(facts.ambiguous[:4])
                         + " — refused rather than guessed, because a shape this "
                           "reader will not interpret is a shape a token could be "
                           "hiding inside"),
                dead_letter=[stream[:2000]])

        # (a) a state-changing form. GET and no-method are HTML's query submission
        # and change nothing, so neither is worth forging; both are refusals with
        # their own wording rather than one shared "not vulnerable".
        state_changing = [f for f in facts.forms
                          if f["method"] in _CSRF_STATE_CHANGING]
        if not facts.forms:
            return self._result(
                summary=("curl CSRF: no <form> in the page — there is no "
                         "submission to forge"),
                dead_letter=[stream[:2000]])
        if not state_changing:
            return self._result(
                summary=("curl CSRF: no state-changing form — the page's "
                         f"{len(facts.forms)} <form> element(s) submit a query "
                         "(method GET, or no method attribute, which is HTML's "
                         "default), so there is no state change to forge"),
                dead_letter=[stream[:2000]])
        if len(state_changing) > 1:
            return self._result(
                summary=("curl CSRF: "
                         f"{len(state_changing)} state-changing forms on one page "
                         "— which of them is unprotected cannot be attributed "
                         "confidently, so the conjunction is refused instead of "
                         "picking the one that would mint"),
                dead_letter=[stream[:2000]])
        form = state_changing[0]
        if not form["closed"]:
            return self._result(
                summary=("curl CSRF: the state-changing <form> is never closed — "
                         "a truncated page cannot be attributed its inputs, so "
                         "the token conjunct cannot be established"),
                dead_letter=[stream[:2000]])

        # (b) no anti-CSRF token. Page-scoped on purpose rather than scoped to the
        # one form: a token that sits outside the <form> element — a framework
        # injecting it, a double-submit <meta>, markup that let an input escape its
        # form — is still evidence the page has a token mechanism, and refusing to
        # mint on it is the direction this family is graded on.
        if facts.token_names:
            sample = ", ".join(sorted(set(facts.token_names))[:4])
            return self._result(
                summary=("curl CSRF: an anti-CSRF token is present "
                         f"({sample}) — a token-like field name or a "
                         "double-submit <meta name> — so the form is protected "
                         "and there is no gap to report"),
                dead_letter=[stream[:2000]])

        # (c) cookie-based ambient auth with no protective SameSite. `None` is the
        # ONLY value that satisfies this conjunct; `Strict`, `Lax` and a MISSING
        # attribute all leave the browser blocking the cookie on a cross-site POST.
        cookies = fields.get("set-cookie", [])
        if not cookies:
            return self._result(
                summary=("curl CSRF: the response sets no cookie — one stateless "
                         "fetch sees no ambient auth to ride, so there is nothing "
                         "for a forged cross-site request to be authenticated "
                         "with"),
                dead_letter=[stream[:2000]])
        parsed = [self._cookie_samesite(c) for c in cookies]
        cross_site = [(name, secure) for name, same, secure in parsed
                      if same == [_CSRF_SAMESITE_CROSS_SITE]]
        if not cross_site:
            observed = ", ".join(
                f"{name or '<unnamed>'} SameSite="
                + (",".join(v or "<empty>" for v in same) or "absent")
                for name, same, _secure in parsed[:4])
            return self._result(
                summary=("curl CSRF: no Set-Cookie carries SameSite=None exactly "
                         f"once (observed {observed}) — Strict and Lax both block "
                         "the cookie on a cross-site request, and so does a "
                         "missing attribute, because every current browser "
                         "defaults it to Lax; a cookie carrying the attribute "
                         "twice is ambiguous and refused"),
                dead_letter=[stream[:2000]])

        cookie_name, secure = cross_site[0]
        if not url:
            # A hit we cannot aim a follow-up at is not deliverable evidence
            # (M2): ingest refuses a url-less finding, and the replay validator
            # this class routes to has nothing to re-send.
            return self._result(
                summary=("curl CSRF: unprotected state-changing form observed — "
                         f"a method={form['method']} <form> with no anti-CSRF "
                         f"token, plus a SameSite=None cookie "
                         f"({cookie_name or '<unnamed>'}) — but the action "
                         "carries no observation URL, so no finding is minted"),
                dead_letter=[stream[:2000]])
        # `medium`, and deliberately below every sibling probe: this is a GAP read
        # off one passive fetch, not an injection the target performed. The CORS
        # and CRLF modes grade `high` because a reflected origin or a split header
        # is confirmed by observation; this one is confirmed too, but what it
        # confirms is the ABSENCE of three protections, and a fourth (a custom
        # header or an origin check) cannot be observed from here at all. It is
        # the grade this corpus gives a reported-but-unconfirmed observation
        # (`parsers/strix.py`'s `vuln.cve_reported`, `parsers/dalfox.py`'s
        # reflected-XSS candidate), and `graph_health.py` buckets only critical
        # and high as serious, so a parked triage signal never escalates a report.
        return self._result(
            summary=("curl CSRF: state-changing form with no anti-CSRF token and "
                     f"a cross-site cookie — method={form['method']} <form>, no "
                     "token-like field or double-submit <meta name> on the page, "
                     f"and Set-Cookie {cookie_name or '<unnamed>'} carries "
                     "SameSite=None, so a browser would ride that cookie on a "
                     "forged cross-site submission. Low-confidence triage signal: "
                     "a custom-header or origin check is not observable from one "
                     "passive GET"),
            findings=[self._finding(
                class_="misconfig.csrf",
                title="state-changing form with no anti-CSRF token and a "
                      "SameSite=None cookie",
                url=url,
                severity="medium",
                extra={"csrf_form_method": form["method"],
                       "csrf_cookie": cookie_name,
                       "csrf_cookie_secure": secure,
                       "csrf_limits": list(_CSRF_FINDING_LIMITS)},
            )],
            dead_letter=[stream[:2000]])

    # -- robots --------------------------------------------------------
    def _robots_result(self, body: str, url: str):
        paths, delay = opsec.parse_robots(body)
        try:
            parts = urlparse(url)
            base = f"{parts.scheme}://{parts.netloc}"
            host = (parts.hostname or "").lower()
        except ValueError:
            # A malformed observation URL (e.g. an unclosed IPv6 bracket)
            # must not raise out of the parser — there is no asset to stamp,
            # so the robots state stays unknown and the gate stays closed.
            return self._result(
                summary=("curl robots.txt: unparseable robots URL — "
                         "robots state UNKNOWN, burst gate stays closed"),
                dead_letter=[body[:2000]] if body else [])
        canary_shaped = [p for p in paths if opsec.canary_hit(p)]
        if body.lstrip().lower().startswith("<"):
            return self._result(
                summary=("curl robots.txt: HTML body (404/block page) — "
                         "robots state UNKNOWN, burst gate stays closed"),
                assets=[])
        asset = self._asset(type_="url", value=base, extra={
            "robots_host": host,
            "canary_paths": paths[:_CANARY_PATH_CAP],
            "crawl_delay": delay,
        })
        summary = (f"curl robots.txt: {len(paths)} disallow, "
                   f"{len(canary_shaped)} canary-shaped, "
                   f"crawl-delay={delay}")
        if len(paths) > _CANARY_PATH_CAP:
            summary += (f" — canary_paths truncated to {_CANARY_PATH_CAP} "
                        f"of {len(paths)}")
        return self._result(
            summary=summary,
            assets=[asset],
        )
