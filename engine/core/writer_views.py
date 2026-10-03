"The reflector is untrusted: if it holds the writer handle, ``ForbiddenActor``\nis a comment rather than a control, because it can call ``upsert_entity`` /\n``advance_and_persist`` directly. It therefore only ever receives THIS\nobject, whose interface contains no method that can create arbitrary\nentities or move a finding's state. Its entire write surface is:\n\n* ``propose_hypothesis`` — creates a hypothesis in state ``proposed`` only;\n  id, kind and state are forced, never taken from the caller.\n* ``adjust_priority`` — nudges the priority column of an existing entity.\n\nAnything else (``upsert_entity``, ``advance_and_persist``, ``append_event``,\n``commit``, the raw ``conn``, ...) raises ``AttributeError`` instead of\nexisting."

from __future__ import annotations

import math

from . import util


def valid_priority(value) -> bool:
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and 0 <= value <= 100)


class ProposeOnlyView:
    """Read + proposal facade over ``Database`` — no state-machine access."""

    # Methods that are allowed to exist; everything else raises AttributeError
    # from __getattr__, so hasattr() is False for the write paths.
    _INTERFACE = (
        "propose_hypothesis", "adjust_priority",
        "get_entity", "query_entities", "get_edges", "get_services", "get_scope",
        "engagement_id",
    )

    def __init__(self, writer, engagement_id: str):
        self.__w = writer
        self.engagement_id = engagement_id

    # -- proposals (the only writes the reflector has) -------------------
    def propose_hypothesis(self, hypothesis: dict) -> str:
        'Persist a hypothesis proposal.'
        proposal = hypothesis or {}
        if proposal.get("rule_id") or proposal.get("asset_id"):
            # Only the deterministic engine materializes executable plans.
            # A model can select one of those plans, but cannot bypass rule
            # conditions, attempt budgets, scope, or inject its own argv.
            for hyp in self.query_entities(kind="hypothesis", state="proposed"):
                if (hyp.get("rule_id") == proposal.get("rule_id") and
                        hyp.get("asset_id") == proposal.get("asset_id") and hyp.get("actions")):
                    if not self.adjust_priority(hyp["id"], proposal.get("priority", 50)):
                        return ""
                    return hyp["id"]
            self.__w.append_event("reflector.proposal_refused", self.engagement_id,
                                  {"reason": "no eligible rule/asset plan"})
            return ""
        clean = {"statement": str(proposal.get("statement") or "")[:2000],
                 "planning_status": "unbound"}
        if valid_priority(proposal.get("priority")):
            clean["priority"] = proposal["priority"]
        # Preserve human ideas without creating repeated inert queue rows.
        for hyp in self.query_entities(kind="hypothesis", state="proposed"):
            if not hyp.get("actions") and hyp.get("statement") == clean["statement"]:
                return hyp["id"]
        clean["id"] = util.new_id("hypothesis")
        clean["kind"] = "hypothesis"
        clean["state"] = "proposed"
        clean["engagement_id"] = self.engagement_id
        clean.pop("dedup_key", None)
        return self.__w.upsert_entity(clean)

    def adjust_priority(self, entity_id: str, priority: float) -> bool:
        """Adjust ONLY the priority column of an existing entity."""
        if not valid_priority(priority) or not self.get_entity(entity_id):
            return False
        return self.__w.set_priority(entity_id, priority)

    # -- reads -----------------------------------------------------------
    def get_entity(self, entity_id: str) -> dict | None:
        entity = self.__w.get_entity(entity_id)
        return entity if entity and entity.get("engagement_id") == self.engagement_id else None

    def query_entities(self, **kwargs) -> list[dict]:
        kwargs["engagement_id"] = self.engagement_id
        return self.__w.query_entities(**kwargs)

    def get_edges(self, **kwargs) -> list[dict]:
        return self.__w.get_edges(**kwargs)

    def get_services(self, asset_id: str | None = None) -> list[dict]:
        return self.__w.get_services(asset_id)

    def get_scope(self) -> dict | None:
        return self.__w.get_scope(self.engagement_id)

    def __getattr__(self, name: str):
        raise AttributeError(
            f"ProposeOnlyView has no attribute {name!r}: the reflector cannot "
            f"write entities or drive finding transitions (F04)")
