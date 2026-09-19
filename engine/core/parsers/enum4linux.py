'enum4linux — SMB/LDAP enumeration disclosures, url-less by design.\n\nThe tool the corpus names is `enum4linux-ng` (v1.3.10 in the deploy-site\ncontainer, behind an `enum4linux` alias). Two consequences shape this parser:\n\n* Its "enumerate everything" flag is `-A`; classic enum4linux.pl\'s `-a` is an\n  unrecognized argument here and exits 2. The rule was corrected in the same\n  change that added this parser.\n* Its machine-readable output (`-oJ`) goes to a FILE, and it force-appends\n  `.json` to whatever path it is given. The parser contract hands a parser the\n  captured stdout/stderr and the action\'s `{url, host}` context only — there is\n  no artifact-path channel — and the container route is `podman exec` into a\n  volume-less persistent container, so a host `{out}` path would not exist\n  inside it anyway. So this parses STDOUT, which is the tool\'s own stable\n  line grammar: a versioned banner, `print_heading` ASCII boxes, and every\n  datum on a `[+]`/`[-]`/`[*]`/`[!]`/`[V]` marker line.\n\nThe grammar is quoted from the printers in the shipped single-file script\n(`/usr/bin/enum4linux-ng`, lines cited in tests/test_enum4linux_parser.py\'s\ndocstring), and the refusal path is a real TEST-NET-1 capture, so neither half\nis guessed.\n\nWhat it emits, and what it deliberately does not:\n\n* one finding per DISCLOSURE CATEGORY the transcript proves — an accepted\n  anonymous (null) session, an enumerated user list, reachable shares, disclosed\n  OS information. Four categories, four findings, never one per account: a\n  domain with 500 RIDs would otherwise mint 500 rows that all say the same thing\n  about the same host. Counts and names ride on the finding beside `title`.\n* groups are folded into the user finding. They are enumerated by the same\n  unauthenticated RPC session and disclose the same misconfiguration; a separate\n  row would double-count it in every report.\n* NO services. nmap remains the sole producer of `service` facts, so\n  `add_service` never writes a second 445 row for the port the gating rule\n  already read. This rule consumes the SMB fact; it does not corroborate it back\n  into the table that produced it.\n* NO assets. The accounts and shares are attributes of a host the graph already\n  has, and the engine\'s asset kinds are target surfaces, not an inventory of\n  remote principals.\n\nClass is `info_disclosure.smb`, the gating rule\'s own declared `on_hit_class`.\nA parser that invented a class would add a `class_without_response` row and make\nthe corpus check worse than the dead rule it was written to fix.\n\nEverything the tool printed that this parser does not recognize is recorded in\n`dead_letter` rather than dropped — that is the Observation contract, and it is\nalso what makes "SMB was reachable and disclosed nothing" distinguishable from\n"the tool died before it enumerated".\n'

from __future__ import annotations

import re

from . import Parser, register

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# enum4linux-ng's five line markers (print_success/error/info/warning/verbose).
_MARKER = re.compile(r"^\[(\+|-|\*|!|V)\]\s?(.*)$")
# print_heading's two bar shapes: " ====" and "|    Title    |".
_HEADING = re.compile(r"^(?:\s*=+\s*)$|^\|\s{4}(.+?)\s{4}\|$")
_BANNER = re.compile(r"^ENUM4LINUX - next generation \(v([\d.]+)\)$")
_COMPLETED = re.compile(r"^Completed after [\d.]+ seconds$")

# Datum lines, each quoted from the upstream printer that emits it.
_RE_USER = re.compile(r"^Found user '(.+?)' \(RID (\d+)\)$")
_RE_GROUP = re.compile(r"^Found (domain|builtin) group '(.+?)' \(RID (\d+)\)$")
_RE_LISTENER_UP = re.compile(r"^(\S.*?) is accessible on (\d+)/tcp$")
_RE_LISTENER_DOWN = re.compile(r"^Could not connect to (\S.*?) on (\d+)/tcp")
_RE_SHARE_OK = re.compile(r"^Found share: (\S+)$")
_RE_SHARE_COUNT = re.compile(r"^Found (\d+) share\(s\)")
_RE_SESSION_OK = re.compile(
    r"^Server allows (?:authentication via username '(.*?)' and password|("
    r"Kerberos|NTLM) authentication)")
_RE_OS_MERGED = re.compile(r"^After merging OS information we have")
_RE_TARGET = re.compile(r"^Target \.+\s(\S+)$")

# A `[+]` message ending in a colon introduces an indented YAML block
# (`Found N share(s):`, `After merging … we have the following result:`); its
# continuation lines carry no marker and are part of the datum, not noise.
_BLOCK_INTRO = re.compile(r":$")

_DEAD_LEN = 120


@register
class Enum4LinuxParser(Parser):
    tool = "enum4linux"

    def parse(self, stdout, stderr="", action=None):
        text = _ANSI.sub("", stdout or "")
        action = action or {}
        host = str(action.get("host") or "")

        findings: list[dict] = []
        dead: list[str] = []

        version = ""
        target = host
        up: list[str] = []
        down: list[str] = []
        users: list[tuple[str, str]] = []       # (username, rid)
        groups: list[tuple[str, str]] = []      # (groupname, type)
        shares: list[str] = []
        share_total = 0
        session: str | None = None              # auth method that was accepted
        os_info = False
        aborted = False
        in_block = False

        for raw in text.splitlines():
            line = raw.rstrip()
            if not line.strip():
                continue

            m = _MARKER.match(line)
            if not m:
                # Non-marker lines are headings, the banner, the completion
                # line, or a YAML block's continuation. Anything else is output
                # this parser does not understand and must not swallow.
                if in_block and (line.startswith(" ") or line.startswith("\t")):
                    continue
                b = _BANNER.match(line.strip())
                if b:
                    version = b.group(1)
                    continue
                if _COMPLETED.match(line.strip()):
                    continue
                h = _HEADING.match(line)
                if h:
                    in_block = False
                    continue
                dead.append(self._marker(line))
                continue

            mark, msg = m.group(1), m.group(2).strip()
            in_block = bool(_BLOCK_INTRO.search(msg))

            if mark == "*":
                t = _RE_TARGET.match(msg)
                if t and not target:
                    target = t.group(1)
                continue

            if mark in ("!", "V"):
                if mark == "!" and "Aborting" in msg:
                    aborted = True
                continue

            if mark == "-":
                d = _RE_LISTENER_DOWN.match(msg)
                if d:
                    down.append(f"{d.group(1)}:{d.group(2)}")
                continue

            # mark == "+": the only lines that can prove a disclosure.
            s = _RE_SESSION_OK.match(msg)
            if s:
                user = s.group(1)
                kind = s.group(2)
                session = (kind.lower() if kind
                           else ("anonymous" if not user else f"user '{user}'"))
                continue
            u = _RE_USER.match(msg)
            if u:
                users.append((u.group(1), u.group(2)))
                continue
            g = _RE_GROUP.match(msg)
            if g:
                groups.append((g.group(2), g.group(1)))
                continue
            sh = _RE_SHARE_OK.match(msg)
            if sh:
                if sh.group(1) not in shares:
                    shares.append(sh.group(1))
                continue
            sc = _RE_SHARE_COUNT.match(msg)
            if sc:
                share_total = int(sc.group(1))
                continue
            lu = _RE_LISTENER_UP.match(msg)
            if lu:
                up.append(f"{lu.group(1)}:{lu.group(2)}")
                continue
            if _RE_OS_MERGED.match(msg):
                os_info = True
                continue

        if session is not None:
            findings.append(self._finding(
                class_="info_disclosure.smb",
                title=(f"SMB {session} session accepted on {target or 'target'} "
                       f"(IPC$ reachable without credentials)"),
                url="",
                severity="high",
                extra={"disclosure": "null_session", "auth": session,
                       "source_host": target, "protocol": "smb"},
            ))
        if users:
            findings.append(self._finding(
                class_="info_disclosure.smb",
                title=(f"SMB user enumeration via unauthenticated RPC: "
                       f"{len(users)} account(s) on {target or 'target'}"),
                url="",
                severity="medium",
                extra={"disclosure": "users", "count": len(users),
                       "names": sorted(n for n, _ in users),
                       "rids": {n: r for n, r in users},
                       "groups": sorted(n for n, _ in groups),
                       "source_host": target, "protocol": "smb"},
            ))
        if shares:
            findings.append(self._finding(
                class_="info_disclosure.smb",
                title=(f"SMB share enumeration: {len(shares)} reachable "
                       f"share(s) on {target or 'target'}"),
                url="",
                severity="medium",
                extra={"disclosure": "shares", "count": len(shares),
                       "names": sorted(shares), "listed_total": share_total,
                       "source_host": target, "protocol": "smb"},
            ))
        if os_info:
            findings.append(self._finding(
                class_="info_disclosure.smb",
                title=f"SMB OS information disclosed via RPC on {target or 'target'}",
                url="",
                severity="info",
                extra={"disclosure": "os_info", "source_host": target,
                       "protocol": "smb"},
            ))

        bits = [f"enum4linux{f' {version}' if version else ''}:"]
        if findings:
            bits.append(f"{len(findings)} disclosure(s) — "
                        + ", ".join(sorted(
                            f["disclosure"] for f in findings)))
        else:
            # The distinction this parser exists to preserve: "reachable and
            # disclosed nothing" is a clean result, "not accessible" is a scan
            # that learned nothing about the service at all.
            if up:
                bits.append("reachable, no disclosure enumerated")
            elif down or aborted:
                bits.append("SMB/LDAP not accessible — enumeration aborted, "
                            "nothing learned about the service")
            else:
                bits.append("no enumeration result in output")
        if users:
            bits.append(f"{len(users)} user(s)")
        if groups:
            bits.append(f"{len(groups)} group(s)")
        if shares:
            bits.append(f"{len(shares)}/{share_total or len(shares)} share(s) reachable")
        if up:
            bits.append("listeners up: " + ", ".join(up))

        return self._result(" ".join(bits), findings=findings, dead_letter=dead)

    @staticmethod
    def _marker(line: str) -> str:
        """A dead-letter row for output this parser does not understand.

        Truncated and length-stamped so a long refusal (an rpcclient backtrace)
        stays diagnosable without becoming the summary. Unlike the credential
        parsers there is nothing to redact here — enum4linux enumerates
        principals, it does not retrieve secrets — but a null-session probe
        echoes the password it was given, so a line carrying one is dropped
        rather than excerpted.
        """
        head = line[:_DEAD_LEN]
        if re.search(r"password '[^']+'", head):
            return f"unparsed enum4linux line ({len(line)} chars, credential-bearing, text withheld)"
        return f"unparsed enum4linux line ({len(line)} chars): {head}"
