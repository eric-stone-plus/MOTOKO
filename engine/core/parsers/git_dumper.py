'git-dumper — the feeder action\'s record, so a failed dump is not a silent one.\n\n`R-TECH-GIT-001` chains two actions: git-dumper reconstructs an exposed `.git`\ninto `{out}`, then trufflehog scans it and produces the findings. The first action\nis a feeder and is *supposed* to yield no findings — but before this parser existed\nits observation was a dead letter whose summary read "no parser registered for\ntool \'git-dumper\'" identically for a full dump and for a target that answered 404.\nSo when trufflehog then reported zero secrets, "clean repository" and "we never got\nthe repository" were the same row on the graph. That is the gap this closes.\n\n* success — `[-] Testing <url> [200]` probes, many `[-] Fetching <url> [NNN]`,\n  then `[-] Sanitizing .git/config` and `[-] Running git checkout .`, with git\'s\n  own `Updated N paths from the index` on **stderr**;\n* failure — one line, `[-] Testing <url> [404]`, exit 1.\n\nThe parser never sees the exit code, so success is recognised from the transcript:\n200-valued fetches plus either the checkout marker or git\'s path count. A run with\nfetches but neither marker is reported PARTIAL rather than as a working copy —\nthat distinction is the whole reason to parse this tool at all.'

from __future__ import annotations

import re

from . import Parser, register

# `[-] Testing http://h/.git/HEAD [200]` / `[-] Fetching http://h/.git/x [404]`
_LINE = re.compile(r"^\[-\]\s+(Testing|Fetching)\s+(\S+)\s+\[(\d{3})\]\s*$")
# git's own line, on stderr: `Updated 2 paths from the index`
_UPDATED = re.compile(r"Updated (\d+) paths? from the index")
_CHECKOUT = "Running git checkout ."
_DEAD_LEN = 200


@register
class GitDumperParser(Parser):
    tool = "git-dumper"

    def parse(self, stdout, stderr="", action=None):
        dead: list[str] = []
        # the two stages are counted apart: a Testing probe is not an object, and
        # reporting one tally for both made a 7-object dump read as 9
        fetch_codes: dict[int, int] = {}
        probe_codes: dict[int, int] = {}
        chatter = 0
        checkout = False
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE.match(line)
            if m:
                stage, code = m.group(1), int(m.group(3))
                tally = fetch_codes if stage == "Fetching" else probe_codes
                tally[code] = tally.get(code, 0) + 1
                continue
            if _CHECKOUT in line:
                checkout = True
                continue
            if line.startswith("[-]"):
                chatter += 1        # the tool's own stage lines (Sanitizing…)
                continue
            dead.append(line[:_DEAD_LEN])
        got = fetch_codes.get(200, 0)
        probed = sum(probe_codes.values())
        paths = 0
        m = _UPDATED.search(stderr or "")
        if m:
            paths = int(m.group(1))
        # stderr's own `[-] <url> responded with status code 404` lines are the
        # tool restating what stdout already coded; anything else is information
        for line in (stderr or "").splitlines():
            line = line.strip()
            if line and not line.startswith("[-]") and not _UPDATED.search(line):
                dead.append(line[:_DEAD_LEN])
        if chatter and not (fetch_codes or probe_codes):
            # Every line was the tool's own prefix and not one was recognisable:
            # the output format moved. Say so instead of reporting a clean zero.
            dead.append("git-dumper output format not recognised — "
                        f"{chatter} `[-]` line(s), no Testing/Fetching row")

        def _tally(t: dict[int, int]) -> str:
            return ", ".join(f"{c}\u00d7{n}" for c, n in sorted(t.items())
                             if c != 200)

        missing = _tally(fetch_codes) or "none missing"
        if got and (checkout or paths):
            summary = (f"git-dumper: {got} object(s) fetched over "
                       f"{probed} probe(s) ({missing}), working tree restored"
                       + (f" ({paths} paths)" if paths else ""))
        elif got:
            summary = (f"git-dumper: {got} object(s) fetched ({missing}) but "
                       "no checkout marker — PARTIAL dump, the working copy is "
                       "incomplete")
        else:
            why = (_tally(fetch_codes) or _tally(probe_codes)
                   or ("unrecognised output format" if chatter else "no output"))
            summary = f"git-dumper: 0 objects fetched ({why}) — nothing dumped"
        return self._result(summary, dead_letter=dead)
