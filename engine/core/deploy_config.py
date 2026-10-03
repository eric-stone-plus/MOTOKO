'FIX-7/FIX-12. The knowledge that used to live as prose (and as a class→\naddress table inside ``engine/launch-strix.sh``) is one module:\n\nFail-closed posture, three layers (decision 5 of the FIX-7 spec):\n\n* the loader rejects any value matching ``egress.HOST_SECRET_VALUE_RE``\n  and any key outside ``ALLOWED_KEYS`` — secrets are structurally\n  impossible, not merely discouraged;\n* doctor FAILs a present-but-defective file (absent = feature-off OK);\n* the shipped ``core/defaults/deploy.json`` carries only ``.invalid``\n  hosts and a TEST-NET-3 gateway, so the example doubles as the schema\n  document without naming any seat-specific endpoint.'

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import dns_channel, egress

ALLOWED_KEYS: frozenset[tuple[str, ...]] = frozenset({
    ("egress", "default_class"),
    ("egress", "echo_url"),
    ("egress", "expect_ip"),
    ("egress", "classes"),
    ("dns", "resolver"),
    ("dns", "local_addr"),
})

ENV_TRANSLATION: dict[tuple[str, ...], str] = {
    ("egress", "echo_url"): egress.ECHO_URL_ENV,
    ("egress", "expect_ip"): egress.EXPECT_IP_ENV,
    ("dns", "resolver"): dns_channel.resolver_env,
    ("dns", "local_addr"): dns_channel.local_addr_env,
}

#: The shipped example, resolvable from an installed wheel too (package
#: data) — the remedy text points operators at it.
SHIPPED_EXAMPLE = "core/defaults/deploy.json"

_RE_CLASS_NAME = egress.EGRESS_CLASS_NAME_RE
_GATEWAY_RE = (r"(?P<host>[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)"
               r":(?P<port>[0-9]+)")
_RE_GATEWAY = re.compile(_GATEWAY_RE)


class DeployConfigError(Exception):
    ''


def deploy_path() -> Path:
    """``$MOTOKO_DEPLOY`` > ``$MOTOKO_HOME/deploy.json``.

    With neither set the result is a Path that does not exist: the tier is
    off, and no code may invent a third location (the fallback decision
    was operator-ruled: MOTOKO_HOME is engagement-state root, and a file
    beside the engagements is tolerated by every census that iterates it).
    """
    override = os.environ.get("MOTOKO_DEPLOY")
    if override:
        return Path(override).expanduser()
    home = os.environ.get("MOTOKO_HOME")
    if home:
        return Path(home) / "deploy.json"
    return Path("/nonexistent/deploy.json")


def _dotted(path: tuple[str, ...]) -> str:
    return ".".join(path)


def _check_scalar(data: dict, path: tuple[str, ...], *, what: str) -> str:
    value = data[path[-1]]
    if not isinstance(value, str) or not value.strip():
        raise DeployConfigError(
            f"deploy config key {_dotted(path)!r} must be a non-empty "
            f"string ({what})")
    # Every value ends up in an environment line, an EnvironmentFile= or a
    # tool argv — a whitespace or control character splits it at a hop and
    # forges the NEXT line (a newline in dns.resolver made `deploy env`
    # emit a second MOTOKO_*= assignment), and non-ASCII needs an encoding
    # decision this loader will not make. Judged over the whole raw value,
    # not over one parsed component: urlsplit silently strips the very
    # characters that make the injection.
    if any(ord(ch) > 127 or ch.isspace() or not ch.isprintable()
           for ch in value):
        raise DeployConfigError(
            f"deploy config key {_dotted(path)!r} carries a non-ASCII, "
            "whitespace or control character — a value that cannot ride "
            "one environment line unsplit (the internal doctrine)")
    return value


def _validate_leaf(data: dict, path: tuple[str, ...]) -> None:
    key = _dotted(path)
    if path == ("egress", "default_class"):
        v = _check_scalar(data, path, what="an egress class name")
        if not _RE_CLASS_NAME.fullmatch(v):
            raise DeployConfigError(
                f"deploy config key {key!r} is not a valid egress class "
                f"name (expected a name like 'browser')")
    elif path == ("egress", "echo_url"):
        v = _check_scalar(data, path, what="an http(s) URL")
        defect = egress.echo_url_defect(v)
        if defect:
            raise DeployConfigError(
                f"deploy config key {key!r} is unusable: {defect}")
    elif path == ("egress", "expect_ip"):
        v = _check_scalar(data, path, what="an IP literal")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise DeployConfigError(
                f"deploy config key {key!r} is not an IP literal") from None
    elif path == ("dns", "resolver"):
        v = _check_scalar(data, path, what="a resolver IP or URL")
        if "://" in v:
            parts = urlsplit(v)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise DeployConfigError(
                    f"deploy config key {key!r} is neither an IP literal "
                    f"nor an http(s) DoH resolver URL")
            if parts.username or parts.password:
                raise DeployConfigError(
                    f"deploy config key {key!r} embeds credentials — the "
                    "resolver needs none, and a credential in the spec "
                    "reaches tool argv and every captured log (the internal doctrine)")
            try:
                parts.port
            except ValueError:
                raise DeployConfigError(
                    f"deploy config key {key!r} carries a port that is "
                    "not a number within 0-65535") from None
        else:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise DeployConfigError(
                    f"deploy config key {key!r} is neither an IP literal "
                    f"nor an http(s) DoH resolver URL") from None
    elif path == ("dns", "local_addr"):
        v = _check_scalar(data, path, what="an IP literal")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise DeployConfigError(
                f"deploy config key {key!r} is not an IP literal") from None


def _validate(data: dict) -> None:
    if not isinstance(data, dict):
        raise DeployConfigError(
            "deploy config root must be a JSON object")
    allowed_dotted = ", ".join(sorted(_dotted(k) for k in ALLOWED_KEYS))
    for section in data:
        if not isinstance(section, str) or (section,) not in \
                {k[:1] for k in ALLOWED_KEYS}:
            raise DeployConfigError(
                f"unknown deploy config key {section!r} (allowed: "
                f"{allowed_dotted}); see the shipped example "
                f"{SHIPPED_EXAMPLE}")
        inner = data[section]
        if not isinstance(inner, dict):
            raise DeployConfigError(
                f"deploy config key {section!r} must be an object")
        for key in inner:
            if (section, key) not in ALLOWED_KEYS:
                raise DeployConfigError(
                    f"unknown deploy config key '{section}.{key}' "
                    f"(allowed: {allowed_dotted}); see the shipped example "
                    f"{SHIPPED_EXAMPLE}")
    for allowed in sorted(ALLOWED_KEYS):
        scope = data
        for part in allowed[:-1]:
            scope = scope.get(part, {})
        if allowed[-1] not in scope:
            continue
        if allowed == ("egress", "classes"):
            _validate_classes(scope["classes"])
        else:
            _validate_leaf(scope, allowed)
            _reject_secret(scope[allowed[-1]], allowed)


def _validate_classes(classes: object) -> None:
    if not isinstance(classes, dict) or not classes:
        raise DeployConfigError(
            "deploy config key 'egress.classes' must be a non-empty object "
            "mapping class name -> {gateway}")
    for name, entry in classes.items():
        if not isinstance(name, str) or not _RE_CLASS_NAME.fullmatch(name):
            raise DeployConfigError(
                "deploy config 'egress.classes' has a malformed class "
                "name (expected a name like 'browser')")
        if not isinstance(entry, dict) or set(entry) - {"gateway"}:
            raise DeployConfigError(
                f"unknown deploy config key 'egress.classes.{name}."
                f"{sorted(set(entry) - {'gateway'})[0]}' (a class entry "
                "carries exactly 'gateway')")
        gw = entry.get("gateway")
        if not isinstance(gw, str):
            raise DeployConfigError(
                f"deploy config key 'egress.classes.{name}.gateway' must "
                "be a 'host:port' string")
        m = _RE_GATEWAY.fullmatch(gw)
        if not m or not (0 < int(m.group("port")) < 65536):
            raise DeployConfigError(
                f"deploy config key 'egress.classes.{name}.gateway' is not "
                "a 'host:port' gateway address")


def _reject_secret(value: str, path: tuple[str, ...]) -> None:
    if isinstance(value, str) and egress.HOST_SECRET_VALUE_RE.search(value):
        raise DeployConfigError(
            f"deploy config key {_dotted(path)!r} carries a "
            "credential-shaped value — this file never carries secrets "
            "(the internal doctrine); credentials reach children only via MOTOKO_SECRET_*")


@dataclass(frozen=True)
class DeployConfig:
    """The frozen view of one deploy config file (or of its absence)."""

    path: Path | None
    _data: dict = field(default_factory=dict, repr=False)

    def gateway(self, egress_class: str) -> str:
        'The ``host:port`` gateway for one egress class.'
        if not _RE_CLASS_NAME.fullmatch(egress_class):
            raise DeployConfigError(
                f"{egress_class!r} is not a valid egress class name "
                "(expected a name like 'browser': alphanumerics and "
                "dashes, no metacharacters — the name reaches gateway "
                "lookups and rotation regexes)")
        entry = self._data.get("egress", {}).get("classes", {}) \
            .get(egress_class)
        if not isinstance(entry, dict) or "gateway" not in entry:
            if self.path is None:
                looked = deploy_path()
                raise DeployConfigError(
                    f"no deploy config file at {looked} ($MOTOKO_DEPLOY "
                    "overrides; $MOTOKO_HOME/deploy.json is the default "
                    f"seat) — create it after the shipped example "
                    f"{SHIPPED_EXAMPLE}, or export MOTOKO_CAIDO_UPSTREAM "
                    "for this launch")
            raise DeployConfigError(
                f"egress class {egress_class!r} has no gateway — add "
                f"egress.classes.{egress_class}.gateway to {self.path} "
                f"(shipped example: {SHIPPED_EXAMPLE})")
        return entry["gateway"]

    def env_map(self) -> dict[str, str]:
        ''
        out: dict[str, str] = {}
        for path, var in ENV_TRANSLATION.items():
            if var in os.environ:
                continue
            scope = self._data
            for part in path[:-1]:
                scope = scope.get(part, {}) if isinstance(scope, dict) else {}
            value = scope.get(path[-1]) if isinstance(scope, dict) else None
            if isinstance(value, str) and value:
                out[var] = value
        return out


def load(path: Path | None = None) -> DeployConfig:
    """Load and validate the deploy config.

    Default location (``path=None``) absent → feature-off ``DeployConfig``
    (``path=None``): legal, and doctor reports it as OK. An explicitly
    named path that does not exist raises — naming a file is an assertion.
    Content is strict: unknown key, bad shape or a credential-shaped
    value raise ``DeployConfigError`` whose message never repeats a value.
    """
    if path is None:
        path = deploy_path()
        if not path.is_file():
            # A default location that does not exist is feature-off; an
            # EXPLICIT $MOTOKO_DEPLOY that does not exist is a typo, and
            # fail-closed draws the line between them here: the override
            # is an operator assertion, and an assertion that resolves
            # to nothing must refuse rather than read as "off".
            if os.environ.get("MOTOKO_DEPLOY"):
                raise DeployConfigError(
                    f"MOTOKO_DEPLOY names a file that does not exist: "
                    f"{path} — an explicit override that resolves to "
                    "nothing is a typo, not feature-off (unset the "
                    "variable or fix the path)")
            return DeployConfig(path=None)
    else:
        path = Path(path)
        if not path.is_file():
            raise DeployConfigError(f"no deploy config file at {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DeployConfigError(
            f"deploy config unreadable: {path} ({exc.strerror})") from None
    except ValueError as exc:
        raise DeployConfigError(
            f"deploy config is not valid JSON: {path} (line "
            f"{getattr(exc, 'lineno', '?')})") from None
    _validate(raw)
    return DeployConfig(path=path, _data=raw)


def defects(cfg: DeployConfig) -> list[str]:
    """Doctor-side coherence lines for a LOADED config, value-free.

    Load-time validation already refused everything syntactic; what
    remains is coherence the syntax cannot see — today: a default class
    that names no gateway entry.
    """
    out: list[str] = []
    egress_sec = cfg._data.get("egress", {})
    default = egress_sec.get("default_class")
    classes = egress_sec.get("classes", {})
    if isinstance(default, str) and default not in classes:
        out.append(
            "deploy config: egress.default_class names a class with no "
            "egress.classes entry — the default class would fail gateway "
            "resolution at launch")
    return out


def _usage() -> str:
    return ("usage: python3 -m core.deploy_config "
            "{gateway <class> [path] | env [path] | validate [path]}")


def main(argv: list[str] | None = None) -> int:
    "The module CLI — the wrapper's gate-2 seam and ``motoko deploy``."
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("gateway", "env", "validate"):
        print(_usage(), file=sys.stderr)
        return 2
    verb, rest = argv[0], argv[1:]
    if verb == "gateway":
        if not rest or len(rest) > 2:
            print(_usage(), file=sys.stderr)
            return 2
    elif len(rest) > 1:
        print(_usage(), file=sys.stderr)
        return 2
    try:
        cfg = load(Path(rest[-1]) if rest and verb != "gateway" else
                   Path(rest[1]) if verb == "gateway" and len(rest) > 1
                   else None)
        if verb == "gateway":
            if cfg.path is None:
                if not _RE_CLASS_NAME.fullmatch(rest[0]):
                    print(f"deploy config: {rest[0]!r} is not a valid "
                          "egress class name (alphanumerics and dashes, "
                          "no metacharacters)", file=sys.stderr)
                    return 1
                print(f"no deploy config file at {deploy_path()} "
                      "($MOTOKO_DEPLOY overrides; $MOTOKO_HOME/deploy.json "
                      "is the default seat) — create it after the shipped "
                      f"example {SHIPPED_EXAMPLE}, or export "
                      "MOTOKO_CAIDO_UPSTREAM for this launch",
                      file=sys.stderr)
                return 3
            print(cfg.gateway(rest[0]))
            return 0
        if verb == "env":
            for var, value in sorted(cfg.env_map().items()):
                print(f"{var}={value}")
            return 0
        lines = defects(cfg)
        for line in lines:
            print(line)
        if cfg.path is None:
            print(f"deploy config: none (feature off; looked at "
                  f"{deploy_path()})")
        elif not lines:
            print(f"deploy config: {cfg.path} OK")
        return 1 if lines else 0
    except DeployConfigError as exc:
        print(f"deploy config: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
