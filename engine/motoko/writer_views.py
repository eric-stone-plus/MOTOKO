"""Propose-only view of the graph for the LLM reflector (F04).

The reflector is untrusted: if it holds the writer handle, ``ForbiddenActor``
is a comment rather than a control, because it can call ``upsert_entity`` /
``advance_and_persist`` directly. It therefore only ever receives THIS
object, whose interface contains no method that can create arbitrary
entities or move a finding's state. Its entire write surface is:

* ``propose_hypothesis`` — creates a hypothesis in state ``proposed`` only;
  id, kind and state are forced, never taken from the caller.
* ``adjust_priority`` — nudges the priority column of an existing entity.

Anything else (``upsert_entity``, ``advance_and_persist``, ``append_event``,
``commit``, the raw ``conn``, ...) raises ``AttributeError`` instead of
existing.

R3 P0-1: the writer handle itself is NOT an exposed attribute. It is stored
under a name-mangled attribute (``self.__w`` -> ``_ProposeOnlyView__w``), so
``view._writer`` raises ``AttributeError`` like every other write path. A
plain ``self._writer = writer`` leaks the whole ``Database``: one line —
``view._writer.advance_and_persist(fid, "oob_callback")`` — forged hard
evidence through the propose-only façade.
"""

from __future__ import annotations

from . import util


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
        # Name-mangled on purpose (see module docstring): the Database handle
        # must stay unreachable as ``view._writer`` (P0-1).
        self.__w = writer
        self.engagement_id = engagement_id

    # -- proposals (the only writes the reflector has) -------------------
    def propose_hypothesis(self, hypothesis: dict) -> str:
        """Persist a hypothesis proposal.

        The shape is forced: a fresh ``hypothesis`` id, kind=hypothesis,
        state=proposed, engagement pinned to this run. A reflector cannot
        propose a finding, cannot propose anything already promoted, and
        cannot pick the id — a caller-supplied id could collide with an
        existing row and overwrite it (R3 P0-2).
        """
        clean = dict(hypothesis or {})
        clean["id"] = util.new_id("hypothesis")
        clean["kind"] = "hypothesis"
        clean["state"] = "proposed"
        clean["engagement_id"] = self.engagement_id
        clean.pop("dedup_key", None)
        return self.__w.upsert_entity(clean)

    def adjust_priority(self, entity_id: str, priority: float) -> bool:
        """Adjust ONLY the priority column of an existing entity."""
        return self.__w.set_priority(entity_id, priority)

    # -- reads -----------------------------------------------------------
    def get_entity(self, entity_id: str) -> dict | None:
        return self.__w.get_entity(entity_id)

    def query_entities(self, **kwargs) -> list[dict]:
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
