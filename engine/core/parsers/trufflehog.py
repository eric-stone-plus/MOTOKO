''

from __future__ import annotations

import hashlib
import json
import re

from . import Parser, register

_FP_LEN = 8
_DEAD_LEN = 120      # a dead-letter marker, never the line itself


def _fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:_FP_LEN]


@register
class TrufflehogParser(Parser):
    tool = "trufflehog"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        dead: list[str] = []
        seen: set[tuple] = set()
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                dead.append(self._marker(line))
                continue
            if not isinstance(d, dict) or not d.get("DetectorName"):
                dead.append(self._marker(line))
                continue
            raw = str(d.get("Raw") or "")
            fp = _fingerprint(raw)
            detector = str(d.get("DetectorName"))
            meta = ((d.get("SourceMetadata") or {}).get("Data") or {})
            fs = meta.get("Filesystem") or {}
            file_ = str(fs.get("file") or "")
            identity = (fp, detector, file_)
            if identity in seen:
                continue          # the same secret via a second decoder
            seen.add(identity)
            verified = bool(d.get("Verified"))
            line_no = fs.get("line")
            findings.append(self._finding(
                class_="secret.leak",
                title=(f"{detector} credential in {file_ or 'scanned output'} "
                       f"(fp {fp})"),
                url="",
                severity="critical" if verified else "high",
                extra={
                    "fingerprint": fp,
                    "detector_name": detector,
                    "decoder": str(d.get("DecoderName") or ""),
                    "verified": verified,
                    "source_file": file_,
                    "source_line": int(line_no) if isinstance(
                        line_no, (int, float)) else 0,
                    "source_url": str((action or {}).get("url") or ""),
                },
            ))
        if findings:
            detectors = sorted({f["detector_name"] for f in findings})
            summary = (f"trufflehog: {len(findings)} secret(s) — "
                       f"{', '.join(detectors)} (values withheld, fingerprints "
                       f"only, the internal doctrine)")
        else:
            summary = "trufflehog: 0 secrets"
        return self._result(summary, findings=findings, dead_letter=dead)

    @staticmethod
    def _marker(line: str) -> str:
        """A dead-letter row that cannot carry the secret.

        The base class's contract is "never silently dropped", and a truncated
        JSON line from this tool is exactly the shape that still contains a
        `Raw` value — so the marker keeps the length and a hash of the line and
        leaves the text in the raw evidence file, where it already is.
        """
        head = line[:_DEAD_LEN]
        digest = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:8]
        # Any run long enough to be a credential is replaced before the head is
        # kept, so even the 120-char excerpt cannot leak one.
        masked = re.sub(r"[A-Za-z0-9_\-]{16,}", "<redacted>", head)
        return f"unparsed trufflehog line ({len(line)} chars, sha1 {digest}): {masked}"
