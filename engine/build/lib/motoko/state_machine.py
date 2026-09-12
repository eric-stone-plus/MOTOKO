"""Finding state machine — kimi influence ladder + triaged budget gate.

States: candidate -> triaged -> reproduced -> verified -> exploitable ->
confirmed_impact, with terminal branches false_positive / duplicate /
out_of_scope / wont_test.

Hard rules (grok/kimi review):

* Only deterministic validators promote a finding. An LLM may propose but
  never drive a transition — ``advance(actor="llm")`` raises.
* Hard evidence is an EVENT, never a caller-supplied signal (F05): the only
  rows that reach ``verified`` are validator events (oob_callback /
  dom_confirmed / credential_usable), and ``advance`` accepts no
  ``extra_signals`` argument. A verdict object may be passed for audit
  binding, but its signals must be backed by its own event.
* ``verified`` requires BOTH a hard-evidence signal AND confidence >=
  VERIFIED_MIN_CONF; a high score alone caps at ``reproduced``.
* ``poc_success`` only reaches ``exploitable`` at confidence >=
  EXPLOITABLE_MIN_CONF (F23); otherwise it falls back to ``verified``
  (when still qualified) or ``reproduced``.
* Falsification is symmetric with confirmation: OOB-negative needs two
  distinct canaries before it demotes a finding, and it REVOKES the
  ``oob_callback`` signal it contradicts (F24). Same for replay_fail /
  replay_ok.
* Illegal events do not escape into the main loop (F30): use
  ``advance_safe`` and record a ``validation_error`` event.
"""

from __future__ import annotations

from . import confidence

TERMINAL_STATES = frozenset({
    "false_positive", "duplicate", "out_of_scope", "wont_test", "confirmed_impact",
})

# Events that carry a confidence signal (added to the finding's signal log).
EVIDENCE_EVENTS = frozenset({
    "replay_ok", "replay_fail", "oob_callback", "oob_negative",
    "dom_confirmed", "credential_usable", "second_tool_hit",
    "waf_blocked", "version_mismatch",
})

# F24: a falsifying event removes the positive signal(s) it contradicts,
# instead of only appending. Without this, one oob_callback would keep
# ``has_hard_evidence`` true forever and a later two-canary negative could
# not retract it.
_SIGNAL_REVOCATIONS: dict[str, tuple[str, ...]] = {
    "oob_negative": ("oob_callback",),
    "replay_fail": ("replay_ok",),
}

# (current_state, event) -> next_state
_TRANSITIONS: dict[tuple[str, str], str] = {
    # candidate — dedup + noise gate, then validator queue
    ("candidate", "dedup_pass"): "triaged",
    ("candidate", "dedup_hit"): "duplicate",
    ("candidate", "noise_rule"): "false_positive",
    ("candidate", "out_of_scope"): "out_of_scope",
    ("candidate", "wont_test"): "wont_test",
    # triaged — only validators promote from here
    ("triaged", "replay_ok"): "reproduced",
    ("triaged", "oob_callback"): "verified",
    ("triaged", "dom_confirmed"): "verified",
    ("triaged", "credential_usable"): "verified",
    ("triaged", "replay_fail"): "false_positive",
    ("triaged", "oob_negative"): "false_positive",
    ("triaged", "noise_rule"): "false_positive",
    ("triaged", "wont_test"): "wont_test",
    ("triaged", "out_of_scope"): "out_of_scope",
    # F26/F27: inconclusive (infra failure / missing url) is a NO-OP — it
    # never falsifies and never promotes.
    ("triaged", "inconclusive"): "triaged",
    # reproduced — waiting on hard evidence (F10: not a promotion dead end)
    ("reproduced", "replay_ok"): "reproduced",
    ("reproduced", "oob_callback"): "verified",
    ("reproduced", "dom_confirmed"): "verified",
    ("reproduced", "credential_usable"): "verified",
    ("reproduced", "inconclusive"): "reproduced",
    ("reproduced", "oob_negative"): "false_positive",
    ("reproduced", "replay_fail"): "false_positive",
    ("reproduced", "wont_test"): "wont_test",
    ("reproduced", "out_of_scope"): "out_of_scope",
    # verified — attempt exploitation; contradicted evidence demotes (F10)
    ("verified", "poc_success"): "exploitable",
    ("verified", "poc_fail"): "reproduced",
    ("verified", "oob_negative"): "reproduced",
    ("verified", "replay_fail"): "reproduced",
    ("verified", "wont_test"): "wont_test",
    ("verified", "out_of_scope"): "out_of_scope",
    # exploitable — demonstrate business impact
    ("exploitable", "impact_confirmed"): "confirmed_impact",
    ("exploitable", "oob_negative"): "verified",
    ("exploitable", "replay_fail"): "verified",
    ("exploitable", "wont_test"): "wont_test",
    ("exploitable", "out_of_scope"): "out_of_scope",
}


class InvalidTransition(Exception):
    pass


class ForbiddenActor(Exception):
    """Raised when an LLM tries to drive a finding transition."""


def transition(state: str, event: str) -> str:
    """Pure state transition (no side effects). Raises on illegal move."""
    key = (state, event)
    if key in _TRANSITIONS:
        return _TRANSITIONS[key]
    # refute is a universal demotion to false_positive from any non-terminal
    if event == "refute" and state not in TERMINAL_STATES:
        return "false_positive"
    if event == "out_of_scope" and state not in TERMINAL_STATES:
        return "out_of_scope"
    if event == "wont_test" and state not in TERMINAL_STATES:
        return "wont_test"
    raise InvalidTransition(f"no transition for ({state!r}, {event!r})")


def _apply_signals(signals: list[str], event: str) -> list[str]:
    """Revoke contradicted positive signals, then log the event's own signal.

    R3 H2: a signal name appears at most ONCE. The same evidence re-observed
    (``replay_ok`` self-loops while the orchestrator re-validates reproduced
    rows) must not stack — otherwise the confidence score drifts one logit
    per beat and walks itself through the EXPLOITABLE_MIN_CONF gate.
    """
    revoked = _SIGNAL_REVOCATIONS.get(event, ())
    out = list(dict.fromkeys(s for s in signals if s not in revoked))
    if event in EVIDENCE_EVENTS and event not in out:
        out.append(event)
    return out


def _bind_verdict(event: str, verdict) -> None:
    """F05: a verdict is provenance for ONE event; it may not smuggle extra
    signals (or a different event) into the signal log."""
    if verdict is None:
        return
    v_event = getattr(verdict, "event", None)
    if v_event != event:
        raise ValueError(
            f"verdict.event {v_event!r} does not match transition event {event!r}")
    extra = [s for s in (getattr(verdict, "signals", []) or []) if s != event]
    if extra:
        raise ValueError(
            f"verdict signals {extra!r} are not backed by its event {event!r}")


def advance(finding: dict, event: str, *, actor: str = "validator",
            verdict=None) -> dict:
    """Apply an event to a finding: enforce actor, update state + confidence.

    Returns the mutated finding dict. ``actor="llm"`` is rejected — the LLM
    cannot promote a finding. Signals come from the event only; ``verified``
    is guarded by hard evidence + confidence threshold, ``exploitable`` by
    EXPLOITABLE_MIN_CONF (falling back to verified/reproduced).
    """
    if actor == "llm":
        raise ForbiddenActor("LLM may not drive finding state transitions")
    _bind_verdict(event, verdict)
    cur = finding.get("state", "candidate")
    new_state = transition(cur, event)

    signals = _apply_signals(list(finding.get("signals") or []), event)
    conf = confidence.score(finding.get("detector", "unknown"), signals)

    # verified guard: hard evidence + threshold, else cap at reproduced.
    if new_state == "verified":
        if not confidence.has_hard_evidence(signals) or conf < confidence.VERIFIED_MIN_CONF:
            new_state = "reproduced"
    # exploitable gate (F23): no exploitation claim below EXPLOITABLE_MIN_CONF.
    elif new_state == "exploitable" and conf < confidence.EXPLOITABLE_MIN_CONF:
        if confidence.has_hard_evidence(signals) and conf >= confidence.VERIFIED_MIN_CONF:
            new_state = "verified"
        else:
            new_state = "reproduced"

    finding["state"] = new_state
    finding["signals"] = signals
    if signals:
        finding["confidence"] = conf
    return finding


def advance_safe(finding: dict, event: str, *, actor: str = "validator",
                 verdict=None) -> tuple[bool, str]:
    """``advance`` that reports instead of raising (F30).

    Returns ``(ok, reason)``; on an illegal event the finding is left
    untouched so the caller can record a ``validation_error`` event and move
    on to the next finding instead of killing the run.
    """
    try:
        advance(finding, event, actor=actor, verdict=verdict)
        return True, ""
    except InvalidTransition as e:
        return False, str(e)
