'Theme tokens for the MOTOKO interface (design/DESIGN.md section 7).\n\nA theme is *data*, not code: ~30 semantic token names mapped to sRGB hex\ncolors, in btop-style ``key=value`` form (see :func:`load_theme_file`). The\nrender layer resolves every color through :class:`Theme`; no widget or panel\nhardcodes a hue.\n\nLetter flags (P4, s-tui pattern): every state that colors also gets a letter\n(``C``/``K``/``L``/``M``/``S``/``W``), so the UI stays usable for colorblind\noperators and greppable in captured logs. See :func:`letter_flags`.\n\nstdlib + rich only; no Textual import here so the render layer stays\nframework-independent (a future Rich-Live ``motoko watch`` tier reuses it).\n'

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from rich.text import Text

#: Every semantic token a theme must define. Kept as a tuple (order is the
#: order used for docs/README; dicts preserve insertion order anyway).
TOKEN_NAMES: tuple[str, ...] = (
    # base
    "bg",
    "panel.bg",
    "panel.border",
    "panel.border_focus",
    "panel.title",
    "table.header",
    "text.primary",
    "text.muted",
    "text.inverse",
    "accent",
    "accent.muted",
    # state colors (glances legend: GREEN ok / BLUE careful / MAGENTA warning / RED critical)
    "state.ok",
    "state.info",
    "state.warn",
    "state.crit",
    "state.stale",
    "state.busy",
    "state.idle",
    # opsec + liveness
    "opsec.cooldown",
    "opsec.canary",
    "live.dot",
    "sealed.dot",
    "funnel.bar",
    # progress / feed
    "progress.fill",
    "progress.back",
    "feed.ts",
    "feed.kind_act",
    "feed.kind_opsec",
    "feed.kind_rule",
    # letter flags (P4)
    "flag.cool",
    "flag.canary",
    "flag.lane",
    "flag.manual",
    "flag.stuck",
    "flag.waf",
)

#: The built-in themes (DESIGN section 7): motoko-dark (default), motoko-light,
#: motoko-amber (CRT retro for night-long runs) and colorblind (green -> blue
#: remap). Values are plain sRGB hex; degradation is the renderer's job.
BUILT_IN_THEMES: dict[str, dict[str, str]] = {
    "motoko-dark": {
        "bg": "#101418",
        "panel.bg": "#141a20",
        "panel.border": "#2c3a48",
        "panel.border_focus": "#4a9eff",
        "panel.title": "#9fb4c7",
        "table.header": "#7d8fa3",
        "text.primary": "#d6e2ee",
        "text.muted": "#6d7f92",
        "text.inverse": "#101418",
        "accent": "#4a9eff",
        "accent.muted": "#2b5f8f",
        "state.ok": "#8fd460",
        "state.info": "#4a9eff",
        "state.warn": "#e8c34a",
        "state.crit": "#f05b5b",
        "state.stale": "#e8c34a",
        "state.busy": "#4a9eff",
        "state.idle": "#6d7f92",
        "opsec.cooldown": "#e8c34a",
        "opsec.canary": "#f05b5b",
        "live.dot": "#8fd460",
        "sealed.dot": "#6d7f92",
        "funnel.bar": "#4a9eff",
        "progress.fill": "#8fd460",
        "progress.back": "#25303b",
        "feed.ts": "#6d7f92",
        "feed.kind_act": "#4a9eff",
        "feed.kind_opsec": "#e8c34a",
        "feed.kind_rule": "#b48ee8",
        "flag.cool": "#e8c34a",
        "flag.canary": "#f05b5b",
        "flag.lane": "#e8934a",
        "flag.manual": "#b48ee8",
        "flag.stuck": "#e8c34a",
        "flag.waf": "#f05b5b",
    },
    "motoko-light": {
        "bg": "#f4f2ec",
        "panel.bg": "#fbfaf6",
        "panel.border": "#c2bba8",
        "panel.border_focus": "#2563a8",
        "panel.title": "#5c6659",
        "table.header": "#6b7261",
        "text.primary": "#2b3026",
        "text.muted": "#8b917f",
        "text.inverse": "#fbfaf6",
        "accent": "#2563a8",
        "accent.muted": "#7d9cc0",
        "state.ok": "#3f7d20",
        "state.info": "#2563a8",
        "state.warn": "#a86a08",
        "state.crit": "#b3261e",
        "state.stale": "#a86a08",
        "state.busy": "#2563a8",
        "state.idle": "#8b917f",
        "opsec.cooldown": "#a86a08",
        "opsec.canary": "#b3261e",
        "live.dot": "#3f7d20",
        "sealed.dot": "#8b917f",
        "funnel.bar": "#2563a8",
        "progress.fill": "#3f7d20",
        "progress.back": "#ded9c8",
        "feed.ts": "#8b917f",
        "feed.kind_act": "#2563a8",
        "feed.kind_opsec": "#a86a08",
        "feed.kind_rule": "#7a4fa0",
        "flag.cool": "#a86a08",
        "flag.canary": "#b3261e",
        "flag.lane": "#b06a1a",
        "flag.manual": "#7a4fa0",
        "flag.stuck": "#a86a08",
        "flag.waf": "#b3261e",
    },
    "motoko-amber": {
        "bg": "#141008",
        "panel.bg": "#1a140a",
        "panel.border": "#5c4517",
        "panel.border_focus": "#ffb340",
        "panel.title": "#c99a3c",
        "table.header": "#a87f2e",
        "text.primary": "#ffcf7d",
        "text.muted": "#8a6d31",
        "text.inverse": "#141008",
        "accent": "#ffb340",
        "accent.muted": "#946a1d",
        "state.ok": "#ffb340",
        "state.info": "#d99c2b",
        "state.warn": "#e07f1f",
        "state.crit": "#ff5c33",
        "state.stale": "#e07f1f",
        "state.busy": "#d99c2b",
        "state.idle": "#8a6d31",
        "opsec.cooldown": "#e07f1f",
        "opsec.canary": "#ff5c33",
        "live.dot": "#ffb340",
        "sealed.dot": "#8a6d31",
        "funnel.bar": "#d99c2b",
        "progress.fill": "#ffb340",
        "progress.back": "#33270e",
        "feed.ts": "#8a6d31",
        "feed.kind_act": "#d99c2b",
        "feed.kind_opsec": "#e07f1f",
        "feed.kind_rule": "#e0a83f",
        "flag.cool": "#e07f1f",
        "flag.canary": "#ff5c33",
        "flag.lane": "#e07f1f",
        "flag.manual": "#e0a83f",
        "flag.stuck": "#e07f1f",
        "flag.waf": "#ff5c33",
    },
    "colorblind": {
        # Green -> blue remap (DESIGN section 7, oh-my-pi colorBlindMode
        # pattern): ok/progress/live move to blues; warm colors are kept for
        # crit only, so red always means "act now" and never "fine".
        "bg": "#0f1216",
        "panel.bg": "#13181d",
        "panel.border": "#2c3a48",
        "panel.border_focus": "#56b4e9",
        "panel.title": "#9fb4c7",
        "table.header": "#7d8fa3",
        "text.primary": "#d6e2ee",
        "text.muted": "#6d7f92",
        "text.inverse": "#0f1216",
        "accent": "#56b4e9",
        "accent.muted": "#2f6d92",
        "state.ok": "#56b4e9",
        "state.info": "#8ab4d9",
        "state.warn": "#e8c34a",
        "state.crit": "#f05b5b",
        "state.stale": "#e8c34a",
        "state.busy": "#56b4e9",
        "state.idle": "#6d7f92",
        "opsec.cooldown": "#e8c34a",
        "opsec.canary": "#f05b5b",
        "live.dot": "#56b4e9",
        "sealed.dot": "#6d7f92",
        "funnel.bar": "#56b4e9",
        "progress.fill": "#56b4e9",
        "progress.back": "#25303b",
        "feed.ts": "#6d7f92",
        "feed.kind_act": "#56b4e9",
        "feed.kind_opsec": "#e8c34a",
        "feed.kind_rule": "#c79bd9",
        "flag.cool": "#e8c34a",
        "flag.canary": "#f05b5b",
        "flag.lane": "#e8a34a",
        "flag.manual": "#c79bd9",
        "flag.stuck": "#e8c34a",
        "flag.waf": "#f05b5b",
    },
}


@dataclass(frozen=True)
class Theme:
    """An immutable token->color mapping plus its name."""

    name: str
    tokens: Mapping[str, str]

    def style(self, token: str) -> str:
        """Rich style string for a token (empty string if unknown)."""
        return self.tokens.get(token, "")

    def missing_tokens(self) -> list[str]:
        """Tokens absent from this theme (should be empty for built-ins)."""
        return [name for name in TOKEN_NAMES if name not in self.tokens]


def get_builtin_theme(name: str) -> Theme | None:
    """Return a built-in theme by name, or None."""
    tokens = BUILT_IN_THEMES.get(name)
    return Theme(name, dict(tokens)) if tokens else None


def load_theme_file(path: str | Path) -> tuple[Theme, list[str]]:
    """Load a btop-style ``key=value`` theme file.

    Format: one ``token=value`` per line; blank lines and ``#`` comments are
    ignored. Values are sRGB hex (``#rrggbb``) or any Rich-compatible color
    string. Unknown keys are collected as warnings (data, not code: a typo
    must be visible, never silently reinterpreted). Keys missing from the
    file fall back to the motoko-dark defaults so a partial file still
    renders coherently.

    Returns:
        (theme, warnings) — warnings is a list of human-readable strings.
    """
    base = dict(BUILT_IN_THEMES["motoko-dark"])
    warnings: list[str] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                warnings.append(f"{path}:{lineno}: not key=value, skipped: {line!r}")
                continue
            key, value = key.strip(), value.strip()
            if key not in TOKEN_NAMES:
                warnings.append(f"{path}:{lineno}: unknown token {key!r}, ignored")
                continue
            base[key] = value
    return Theme(Path(path).stem, base), warnings


# --- letter flags (P4) ------------------------------------------------------

#: (flag letter, theme token, human description) — s-tui throttle-letter
#: pattern. Order is fixed so flag strings align across table rows.
FLAG_SPECS: tuple[tuple[str, str, str], ...] = (
    ("C", "flag.cool", "cooldown active"),
    ("K", "flag.canary", "canary tripped"),
    ("L", "flag.lane", "egress lane saturated"),
    ("M", "flag.manual", "manual pause"),
    ("S", "flag.stuck", "stuck_testing held"),
    ("W", "flag.waf", "WAF aware"),
)


def letter_flags(active: Mapping[str, bool], theme: Theme) -> Text:
    """Render the six OPSEC letter flags as a fixed-width Rich Text.

    Active flags render as their (token-colored) letter — always a plain
    letter, never a glyph-only symbol, so ``grep ' C '` on a captured log
    finds cooldown-active rows. Inactive flags render as a dim ``·``
    placeholder to keep columns aligned. The string is always 6 characters
    wide (one per flag, in :data:`FLAG_SPECS` order).
    """
    out = Text()
    for letter, token, _desc in FLAG_SPECS:
        if active.get(letter):
            out.append(letter, style=theme.style(token))
        else:
            out.append("·", style=theme.style("text.muted"))
    return out
