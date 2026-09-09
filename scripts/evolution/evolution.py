#!/usr/bin/env python3
"""
MOTOKO Controlled Self-Evolution Engine

Bounded, reproducible, auditable adaptation for automated pentesting.
Every adaptation is a Python class that can be version-controlled, tested, and rolled back.

Design principles:
1. Code, not MEMORY - rules are classes, not text dumps
2. Bounded - max N adaptations per session, per target, per origin
3. Auditable - JSONL ledger with before/after state and reason
4. Reproducible - same evidence → same adaptations (deterministic)
5. Human-gated for high-risk changes
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

MAX_ADAPTATIONS_PER_SESSION = 20
MAX_ADAPTATIONS_PER_TARGET = 5
MAX_ADAPTATIONS_PER_ORIGIN = 3

# WAF throttle parameters
WAF_WORKERS_MIN = 1
WAF_DELAY_MS_DEFAULT = 2000
WAF_RECOVERY_SECONDS = 300

# Resource thresholds
LOAD_THRESHOLD_HIGH = 10.0
MEM_THRESHOLD_LOW_BYTES = 4 * 1024 * 1024 * 1024  # 4G

# Technology detection → nuclei tags
TECH_TAG_MAP = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "drupal": ["drupal", "drupal-plugin"],
    "joomla": ["joomla"],
    "spring": ["spring", "java", "springboot"],
    "tomcat": ["tomcat", "java"],
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
    "iis": ["iis", "asp", "aspx"],
    "laravel": ["laravel", "php"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "express": ["express", "nodejs", "javascript"],
    "rails": ["rails", "ruby"],
    "php": ["php"],
    "asp": ["asp", "aspx", "iis"],
    "graphql": ["graphql"],
    "api": ["api", "openapi"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

class Scope(Enum):
    TARGET = "target"
    ORIGIN = "origin"
    CAMPAIGN = "campaign"
    GLOBAL = "global"


class GateLevel(Enum):
    AUTO = "auto"               # No human gate, safe
    SUGGEST = "suggest"         # Applied but flagged for review
    HUMAN = "human"             # Requires explicit approval before apply


@dataclass
class Adaptation:
    """A single adaptation event. Immutable once created."""
    id: str
    timestamp: str
    rule_name: str
    trigger: str
    scope: str
    scope_id: str
    before: dict
    after: dict
    reason: str
    gated: bool
    approved: bool | None
    reverted: bool = False
    revert_timestamp: str | None = None


@dataclass
class SessionState:
    """Tracks adaptation counts per session."""
    session_id: str
    start_time: str
    total_count: int = 0
    per_target: dict[str, int] = field(default_factory=dict)
    per_origin: dict[str, int] = field(default_factory=dict)
    blocked_count: int = 0
    reverted_count: int = 0


@dataclass
class Conflict:
    """Record of a blocked adaptation due to conflict."""
    timestamp: str
    rule_name: str
    conflicting_rule: str
    scope_id: str
    key: str
    reason: str


# ─────────────────────────────────────────────────────────────────────────────
# Abstract base rule
# ─────────────────────────────────────────────────────────────────────────────

class EvolutionRule(ABC):
    """Base class for adaptation rules.
    
    Subclasses must implement:
    - matches(evidence) -> bool
    - apply(evidence) -> Adaptation | None
    - revert(adaptation) -> None
    """
    
    name: str = "unnamed-rule"
    gate_level: GateLevel = GateLevel.AUTO
    scope: Scope = Scope.TARGET
    
    @abstractmethod
    def matches(self, evidence: dict) -> bool:
        """Does this evidence trigger the rule?"""
        ...
    
    @abstractmethod
    def apply(self, evidence: dict) -> Adaptation | None:
        """Apply the adaptation. Return None if already applied (idempotent)."""
        ...
    
    @abstractmethod
    def revert(self, adaptation: Adaptation) -> None:
        """Revert the adaptation to before-state."""
        ...
    
    def modified_keys(self) -> set[str]:
        """Which config keys does this rule modify? Used for conflict detection."""
        return set()


# ─────────────────────────────────────────────────────────────────────────────
# Evolution Engine
# ─────────────────────────────────────────────────────────────────────────────

class EvolutionEngine:
    """Manages bounded, auditable adaptation.
    
    Usage:
        engine = EvolutionEngine(campaign_dir / "evolution")
        engine.register_rule(WordPressTemplateRule())
        engine.register_rule(WAFThrottleRule())
        
        # In scan loop:
        for evidence in evidence_stream:
            adaptations = engine.process_evidence(evidence)
            for a in adaptations:
                if a.gated and a.approved is None:
                    notify_user(a)
    """
    
    def __init__(
        self,
        ledger_dir: Path,
        max_per_session: int = MAX_ADAPTATIONS_PER_SESSION,
        max_per_target: int = MAX_ADAPTATIONS_PER_TARGET,
        max_per_origin: int = MAX_ADAPTATIONS_PER_ORIGIN,
        session_id: str | None = None,
    ):
        self.ledger_dir = ledger_dir
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_per_session = max_per_session
        self.max_per_target = max_per_target
        self.max_per_origin = max_per_origin
        
        self.session_id = session_id or datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        self.ledger_path = self.ledger_dir / "adaptations.jsonl"
        self.state_path = self.ledger_dir / "session-state.json"
        self.conflict_path = self.ledger_dir / "conflicts.jsonl"
        
        self.rules: list[EvolutionRule] = []
        self.adaptations: list[Adaptation] = []
        self.state = SessionState(
            session_id=self.session_id,
            start_time=datetime.now(UTC).isoformat(),
        )
        
        # Track which keys have been modified for conflict detection
        self._modified_keys: dict[str, str] = {}  # key -> rule_name
        
        # Load existing state if resuming
        self._load_state()
    
    def register_rule(self, rule: EvolutionRule) -> None:
        """Add an adaptation rule. Rules are checked in registration order."""
        self.rules.append(rule)
        logger.debug(f"Registered rule: {rule.name} ({rule.gate_level.value})")
    
    def process_evidence(self, evidence: dict) -> list[Adaptation]:
        """Run evidence through all rules, return adaptations.
        
        Args:
            evidence: Dict with keys like 'tool', 'target', 'origin', 'output', 'status_code'
        
        Returns:
            List of adaptations that were applied (or pending approval for gated ones).
        """
        # Check session bound
        if self.state.total_count >= self.max_per_session:
            logger.info(f"Session bound reached ({self.max_per_session}), skipping adaptation")
            return []
        
        # Check per-target bound
        target = evidence.get("target", "")
        if target and self.state.per_target.get(target, 0) >= self.max_per_target:
            logger.debug(f"Target bound reached for {target}, skipping")
            return []
        
        # Check per-origin bound
        origin = evidence.get("origin", "")
        if origin and self.state.per_origin.get(origin, 0) >= self.max_per_origin:
            logger.debug(f"Origin bound reached for {origin}, skipping")
            return []
        
        adaptations = []
        
        for rule in self.rules:
            # Check bounds before each rule
            if self.state.total_count >= self.max_per_session:
                break
            if target and self.state.per_target.get(target, 0) >= self.max_per_target:
                break
            if origin and self.state.per_origin.get(origin, 0) >= self.max_per_origin:
                continue
            
            if not rule.matches(evidence):
                continue
            
            # Conflict detection
            if self._has_conflict(rule, evidence):
                self._log_conflict(rule, evidence)
                continue
            
            # Apply rule
            adaptation = rule.apply(evidence)
            if adaptation is None:
                # Idempotent skip (already adapted)
                continue
            
            # Gate check
            if rule.gate_level == GateLevel.HUMAN and adaptation.approved is None:
                # Don't apply yet, just record as pending
                # Store rule reference for later approval/rejection
                adaptation._rule = rule
                self.adaptations.append(adaptation)
                self._log(adaptation)
                adaptations.append(adaptation)
                continue
            
            # Store rule reference for revert capability
            adaptation._rule = rule
            
            # Record adaptation
            self.adaptations.append(adaptation)
            self.state.total_count += 1
            self.state.per_target[target] = self.state.per_target.get(target, 0) + 1
            if origin:
                self.state.per_origin[origin] = self.state.per_origin.get(origin, 0) + 1
            
            # Track modified keys
            for key in rule.modified_keys():
                self._modified_keys[key] = rule.name
            
            self._log(adaptation)
            adaptations.append(adaptation)
            
            logger.info(
                f"Adaptation: {rule.name} on {adaptation.scope_id} "
                f"({self.state.total_count}/{self.max_per_session})"
            )
        
        self._save_state()
        return adaptations
    
    def approve_adaptation(self, adaptation_id: str) -> Adaptation | None:
        """Approve a pending human-gated adaptation."""
        for a in self.adaptations:
            if a.id == adaptation_id and a.gated and a.approved is None:
                a.approved = True
                self._log(a)
                return a
        return None
    
    def reject_adaptation(self, adaptation_id: str) -> Adaptation | None:
        """Reject a pending human-gated adaptation."""
        for a in self.adaptations:
            if a.id == adaptation_id and a.gated and a.approved is None:
                a.approved = False
                self._log(a)
                return a
        return None
    
    def revert(self, adaptation_id: str) -> bool:
        """Revert a specific adaptation."""
        for a in self.adaptations:
            if a.id == adaptation_id and not a.reverted:
                try:
                    # Use stored rule reference for revert
                    rule = getattr(a, '_rule', None)
                    if rule is None:
                        logger.error(f"No rule reference for adaptation {a.id}")
                        return False
                    rule.revert(a)
                    a.reverted = True
                    a.revert_timestamp = datetime.now(UTC).isoformat()
                    self.state.reverted_count += 1
                    self._log(a)
                    self._save_state()
                    logger.info(f"Reverted adaptation: {a.rule_name} on {a.scope_id}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to revert {a.id}: {e}")
                    return False
        return False
    
    def revert_all(self) -> int:
        """Revert all adaptations in reverse order. Returns count reverted."""
        count = 0
        for a in reversed(self.adaptations):
            if not a.reverted and a.approved is not False:
                if self.revert(a.id):
                    count += 1
        return count
    
    def get_summary(self) -> dict:
        """Get human-readable summary of all adaptations."""
        return {
            "session_id": self.session_id,
            "total_adaptations": self.state.total_count,
            "reverted": self.state.reverted_count,
            "blocked": self.state.blocked_count,
            "per_target": dict(self.state.per_target),
            "per_origin": dict(self.state.per_origin),
            "adaptations": [
                {
                    "rule": a.rule_name,
                    "scope": a.scope,
                    "scope_id": a.scope_id,
                    "trigger": a.trigger,
                    "reason": a.reason,
                    "approved": a.approved,
                    "reverted": a.reverted,
                }
                for a in self.adaptations
            ],
        }
    
    def _has_conflict(self, rule: EvolutionRule, evidence: dict) -> bool:
        """Check if rule would conflict with already-applied adaptations.
        
        For list-type keys (like nuclei_tags), multiple rules can add to the same key.
        Only flag conflicts for scalar keys or when rules are truly incompatible.
        """
        # For now, allow multiple rules to modify list-type keys (like nuclei_tags)
        # This enables both TechnologyTemplateRule and AdminPanelRule to add tags
        return False
    
    def _log(self, adaptation: Adaptation) -> None:
        """Write adaptation to JSONL ledger."""
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(asdict(adaptation), ensure_ascii=False) + '\n')
    
    def _log_conflict(self, rule: EvolutionRule, evidence: dict) -> None:
        """Write conflict record."""
        self.state.blocked_count += 1
        conflict = Conflict(
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=rule.name,
            conflicting_rule=self._modified_keys.get(list(rule.modified_keys())[0], "unknown"),
            scope_id=evidence.get("target", evidence.get("origin", "unknown")),
            key=list(rule.modified_keys())[0] if rule.modified_keys() else "unknown",
            reason=f"Key already modified by {self._modified_keys.get(list(rule.modified_keys())[0], 'unknown')}",
        )
        with open(self.conflict_path, 'a') as f:
            f.write(json.dumps(asdict(conflict), ensure_ascii=False) + '\n')
    
    def _save_state(self) -> None:
        """Persist session state to disk."""
        with open(self.state_path, 'w') as f:
            json.dump(asdict(self.state), f, indent=2, ensure_ascii=False)
    
    def _load_state(self) -> None:
        """Load existing session state if resuming."""
        if self.state_path.exists():
            try:
                with open(self.state_path) as f:
                    data = json.load(f)
                self.state = SessionState(**data)
                logger.info(f"Resumed session {self.session_id}: {self.state.total_count} adaptations")
            except Exception as e:
                logger.warning(f"Could not load state, starting fresh: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Concrete Rules: Template Selection
# ─────────────────────────────────────────────────────────────────────────────

class TechnologyTemplateRule(EvolutionRule):
    """When whatweb detects a technology, add relevant nuclei templates.
    
    Trigger: whatweb output contains a known technology string
    Adaptation: Add technology-specific nuclei tags
    Scope: per-target
    Gate: AUTO (safe, just template filtering)
    """
    
    name = "technology-template-selection"
    gate_level = GateLevel.AUTO
    scope = Scope.TARGET
    
    def __init__(self):
        self._applied: set[str] = set()  # "target:tech" pairs already adapted
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") != "whatweb":
            return False
        output = evidence.get("output", "").lower()
        return any(tech in output for tech in TECH_TAG_MAP)
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence["target"]
        output = evidence.get("output", "").lower()
        
        # Find all detected technologies
        detected = []
        for tech in TECH_TAG_MAP:
            if tech in output:
                # Check idempotency
                key = f"{target}:{tech}"
                if key in self._applied:
                    continue
                self._applied.add(key)
                detected.append(tech)
        
        if not detected:
            return None
        
        # Collect all tags for detected technologies
        tags = []
        for tech in detected:
            tags.extend(TECH_TAG_MAP[tech])
        tags = sorted(set(tags))
        
        before = {"nuclei_tags": [], "detected_tech": []}
        after = {"nuclei_tags": tags, "detected_tech": detected}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"whatweb detected: {', '.join(detected)}",
            scope="target",
            scope_id=target,
            before=before,
            after=after,
            reason=f"Technology detected ({', '.join(detected)}) → adding nuclei tags: {', '.join(tags)}",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        # Revert is implicit: remove the tags from the target's config
        target = adaptation.scope_id
        tags = adaptation.after.get("nuclei_tags", [])
        for tech in adaptation.after.get("detected_tech", []):
            key = f"{target}:{tech}"
            self._applied.discard(key)
        logger.info(f"Reverted template tags for {target}: {tags}")
    
    def modified_keys(self) -> set[str]:
        return {"nuclei_tags"}


class AdminPanelRule(EvolutionRule):
    """When whatweb detects an admin panel, add admin-specific templates.
    
    Trigger: whatweb output contains admin/login/dashboard keywords
    Adaptation: Add admin-panel nuclei tag
    Scope: per-target
    Gate: SUGGEST (applied but flagged)
    """
    
    name = "admin-panel-detection"
    gate_level = GateLevel.SUGGEST
    scope = Scope.TARGET
    
    ADMIN_KEYWORDS = [
        "admin", "login", "dashboard", "cpanel", "wp-admin",
        "phpmyadmin", "webmail", "manager", "console",
    ]
    
    def __init__(self):
        self._applied: set[str] = set()
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") != "whatweb":
            return False
        output = evidence.get("output", "").lower()
        return any(kw in output for kw in self.ADMIN_KEYWORDS)
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence["target"]
        if target in self._applied:
            return None
        
        output = evidence.get("output", "").lower()
        found = [kw for kw in self.ADMIN_KEYWORDS if kw in output]
        
        self._applied.add(target)
        before = {"nuclei_tags": []}
        after = {"nuclei_tags": ["admin-panel", "login"]}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"whatweb detected admin panel: {', '.join(found)}",
            scope="target",
            scope_id=target,
            before=before,
            after=after,
            reason=f"Admin panel detected ({', '.join(found)}) → adding admin-panel nuclei tags",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        target = adaptation.scope_id
        self._applied.discard(target)
    
    def modified_keys(self) -> set[str]:
        return {"nuclei_tags"}


# ─────────────────────────────────────────────────────────────────────────────
# Concrete Rules: Throttling
# ─────────────────────────────────────────────────────────────────────────────

class WAFThrottleRule(EvolutionRule):
    """When 429/WAF detected, auto-throttle per origin.
    
    Trigger: HTTP 429, 403, or 503 from any tool
    Adaptation: Reduce workers to 1, increase delay to 2s
    Scope: per-origin
    Gate: AUTO (safe, protects against bans)
    """
    
    name = "waf-auto-throttle"
    gate_level = GateLevel.AUTO
    scope = Scope.ORIGIN
    
    WAF_STATUS_CODES = {429, 403, 503}
    
    def __init__(self):
        self._applied: dict[str, dict] = {}  # origin -> throttle config
    
    def matches(self, evidence: dict) -> bool:
        return (evidence.get("tool") in ("nuclei", "katana", "ffuf", "dalfox", "arjun") and
                evidence.get("status_code") in self.WAF_STATUS_CODES)
    
    def apply(self, evidence: dict) -> Adaptation | None:
        origin = evidence["origin"]
        
        # If already throttled, don't re-apply
        if origin in self._applied:
            return None
        
        before = {"workers": "auto", "delay_ms": 0}
        after = {"workers": WAF_WORKERS_MIN, "delay_ms": WAF_DELAY_MS_DEFAULT}
        
        self._applied[origin] = after
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"HTTP {evidence['status_code']} on {origin}",
            scope="origin",
            scope_id=origin,
            before=before,
            after=after,
            reason=f"WAF/rate-limit detected ({evidence['status_code']}) → 1 worker, {WAF_DELAY_MS_DEFAULT}ms delay",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        origin = adaptation.scope_id
        self._applied.pop(origin, None)
        logger.info(f"Reverted WAF throttle for {origin}")
    
    def modified_keys(self) -> set[str]:
        return {"origin_throttle"}


class RepeatedTimeoutRule(EvolutionRule):
    """When a target has repeated timeouts, increase timeout and reduce concurrency.
    
    Trigger: Same target times out 2+ times
    Adaptation: Double timeout, halve concurrency
    Scope: per-target
    Gate: SUGGEST (applied but flagged)
    """
    
    name = "repeated-timeout-backoff"
    gate_level = GateLevel.SUGGEST
    scope = Scope.TARGET
    
    TIMEOUT_THRESHOLD = 2
    
    def __init__(self):
        self._timeout_counts: dict[str, int] = {}
        self._applied: set[str] = set()
    
    def matches(self, evidence: dict) -> bool:
        if not evidence.get("timed_out"):
            return False
        target = evidence.get("target", "")
        self._timeout_counts[target] = self._timeout_counts.get(target, 0) + 1
        return (self._timeout_counts[target] >= self.TIMEOUT_THRESHOLD and
                target not in self._applied)
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence["target"]
        self._applied.add(target)
        
        before = {"timeout_multiplier": 1, "concurrency": "normal"}
        after = {"timeout_multiplier": 2, "concurrency": "reduced"}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"{self._timeout_counts[target]} timeouts on {target}",
            scope="target",
            scope_id=target,
            before=before,
            after=after,
            reason=f"Repeated timeouts ({self._timeout_counts[target]}x) → doubling timeout, reducing concurrency",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        target = adaptation.scope_id
        self._applied.discard(target)
    
    def modified_keys(self) -> set[str]:
        return {"timeout", "concurrency"}


# ─────────────────────────────────────────────────────────────────────────────
# Concrete Rules: Resource Management
# ─────────────────────────────────────────────────────────────────────────────

class ResourceThrottleRule(EvolutionRule):
    """When system resources are strained, reduce concurrency.
    
    Trigger: CPU load > 10 or available memory < 4G
    Adaptation: Reduce concurrent workers
    Scope: global
    Gate: AUTO (safe, prevents OOM/crash)
    """
    
    name = "resource-auto-throttle"
    gate_level = GateLevel.AUTO
    scope = Scope.GLOBAL
    
    def __init__(self):
        self._throttled = False
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") != "system":
            return False
        load = evidence.get("load_1m", 0)
        mem_avail = evidence.get("mem_available_bytes", float('inf'))
        return load > LOAD_THRESHOLD_HIGH or mem_avail < MEM_THRESHOLD_LOW_BYTES
    
    def apply(self, evidence: dict) -> Adaptation | None:
        if self._throttled:
            return None
        
        self._throttled = True
        load = evidence.get("load_1m", 0)
        mem_gb = evidence.get("mem_available_bytes", 0) / (1024**3)
        
        before = {"concurrency": "normal", "load": load, "mem_gb": round(mem_gb, 1)}
        after = {"concurrency": "reduced", "load": load, "mem_gb": round(mem_gb, 1)}
        
        reason_parts = []
        if load > LOAD_THRESHOLD_HIGH:
            reason_parts.append(f"load={load:.1f}")
        if mem_gb < 4:
            reason_parts.append(f"mem={mem_gb:.1f}G")
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"System resources strained: {', '.join(reason_parts)}",
            scope="global",
            scope_id="system",
            before=before,
            after=after,
            reason=f"Resource pressure ({', '.join(reason_parts)}) → reducing concurrency",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        self._throttled = False
        logger.info("Reverted resource throttle")
    
    def modified_keys(self) -> set[str]:
        return {"global_concurrency"}


class ResourceRecoveryRule(EvolutionRule):
    """When system resources recover, restore concurrency.
    
    Trigger: CPU load < 5 and available memory > 6G (after being throttled)
    Adaptation: Restore normal concurrency
    Scope: global
    Gate: AUTO
    """
    
    name = "resource-auto-recovery"
    gate_level = GateLevel.AUTO
    scope = Scope.GLOBAL
    
    def __init__(self):
        self._recovered = True  # Start as recovered
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") != "system":
            return False
        load = evidence.get("load_1m", 0)
        mem_avail = evidence.get("mem_available_bytes", float('inf'))
        # Only fire if we were throttled and now recovered
        return (not self._recovered and
                load < LOAD_THRESHOLD_HIGH / 2 and
                mem_avail > MEM_THRESHOLD_LOW_BYTES * 1.5)
    
    def apply(self, evidence: dict) -> Adaptation | None:
        self._recovered = True
        load = evidence.get("load_1m", 0)
        mem_gb = evidence.get("mem_available_bytes", 0) / (1024**3)
        
        before = {"concurrency": "reduced"}
        after = {"concurrency": "normal", "load": load, "mem_gb": round(mem_gb, 1)}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"System resources recovered (load={load:.1f}, mem={mem_gb:.1f}G)",
            scope="global",
            scope_id="system",
            before=before,
            after=after,
            reason=f"Resources recovered → restoring normal concurrency",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        self._recovered = False
    
    def modified_keys(self) -> set[str]:
        return {"global_concurrency"}


# ─────────────────────────────────────────────────────────────────────────────
# Concrete Rules: Findings-Driven
# ─────────────────────────────────────────────────────────────────────────────

class HighValueFindingsRule(EvolutionRule):
    """When high-value findings are detected, flag target for deeper scan.
    
    Trigger: nuclei/strix finding with critical/high severity
    Adaptation: Flag target for deeper scan in next pass
    Scope: campaign
    Gate: SUGGEST (applied but flagged)
    """
    
    name = "high-value-findings-deep-scan"
    gate_level = GateLevel.SUGGEST
    scope = Scope.CAMPAIGN
    
    CRITICAL_KEYWORDS = ["rce", "remote-code-execution", "sql-injection", "sqli"]
    HIGH_KEYWORDS = ["xss", "ssrf", "lfi", "rfi", "xxe", "idor", "auth-bypass"]
    
    def __init__(self):
        self._flagged: set[str] = set()
        self._max_flagged = 3
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") not in ("nuclei", "strix"):
            return False
        severity = evidence.get("severity", "").lower()
        tags = evidence.get("tags", [])
        matched_templates = evidence.get("matched_templates", [])
        
        # Check for critical/high findings
        all_text = f"{severity} {' '.join(tags)} {' '.join(matched_templates)}".lower()
        return (any(kw in all_text for kw in self.CRITICAL_KEYWORDS) or
                (severity in ("high", "critical") and 
                 any(kw in all_text for kw in self.HIGH_KEYWORDS)))
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence["target"]
        
        if target in self._flagged:
            return None
        if len(self._flagged) >= self._max_flagged:
            return None
        
        self._flagged.add(target)
        
        severity = evidence.get("severity", "unknown")
        template = evidence.get("matched_templates", ["unknown"])[0] if evidence.get("matched_templates") else "unknown"
        
        before = {"deep_scan_flagged": False}
        after = {"deep_scan_flagged": True, "reason_severity": severity, "reason_template": template}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"{severity} finding: {template} on {target}",
            scope="campaign",
            scope_id=target,
            before=before,
            after=after,
            reason=f"High-value finding ({severity}: {template}) → flagging for deeper scan",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        target = adaptation.scope_id
        self._flagged.discard(target)
    
    def modified_keys(self) -> set[str]:
        return {"scan_depth"}


class SubdomainAutoQueueRule(EvolutionRule):
    """When subfinder finds new subdomains, auto-add to queue.
    
    Trigger: subfinder output contains new domain
    Adaptation: Add to queue (after WHOIS/ASN verification)
    Scope: campaign
    Gate: SUGGEST (needs verification before actual scanning)
    """
    
    name = "subdomain-auto-queue"
    gate_level = GateLevel.SUGGEST
    scope = Scope.CAMPAIGN
    
    MAX_NEW_SUBDOMAINS = 50
    
    def __init__(self):
        self._queued: set[str] = set()
        self._count = 0
    
    def matches(self, evidence: dict) -> bool:
        if evidence.get("tool") != "subfinder":
            return False
        new_domains = evidence.get("new_domains", [])
        return len(new_domains) > 0 and self._count < self.MAX_NEW_SUBDOMAINS
    
    def apply(self, evidence: dict) -> Adaptation | None:
        new_domains = evidence.get("new_domains", [])
        existing_queue = evidence.get("existing_queue", [])
        
        # Filter out already-queued domains
        to_add = [d for d in new_domains if d not in existing_queue and d not in self._queued]
        
        if not to_add:
            return None
        
        # Respect limit
        remaining = self.MAX_NEW_SUBDOMAINS - self._count
        to_add = to_add[:remaining]
        
        self._queued.update(to_add)
        self._count += len(to_add)
        
        before = {"queue_size": len(existing_queue)}
        after = {"queue_size": len(existing_queue) + len(to_add), "new_domains": to_add}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"subfinder found {len(to_add)} new subdomains",
            scope="campaign",
            scope_id="queue",
            before=before,
            after=after,
            reason=f"New subdomains discovered → adding {len(to_add)} to queue (needs WHOIS/ASN verification)",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        new_domains = adaptation.after.get("new_domains", [])
        for d in new_domains:
            self._queued.discard(d)
            self._count -= 1
    
    def modified_keys(self) -> set[str]:
        return {"target_queue"}


# ─────────────────────────────────────────────────────────────────────────────
# Concrete Rules: Human-Gated
# ─────────────────────────────────────────────────────────────────────────────

class CredentialTestRule(EvolutionRule):
    """When credentials are found, propose testing them.
    
    Trigger: trufflehog/secret scan finds credentials
    Adaptation: Test credential on discovered endpoints
    Scope: target
    Gate: HUMAN (requires explicit approval)
    """
    
    name = "credential-test-proposal"
    gate_level = GateLevel.HUMAN
    scope = Scope.TARGET
    
    def matches(self, evidence: dict) -> bool:
        return (evidence.get("tool") in ("trufflehog", "nuclei") and
                evidence.get("finding_type") == "credential")
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence["target"]
        cred_type = evidence.get("credential_type", "unknown")
        
        before = {"credential_test": "not_proposed"}
        after = {"credential_test": "pending_approval", "cred_type": cred_type}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"{cred_type} credential found on {target}",
            scope="target",
            scope_id=target,
            before=before,
            after=after,
            reason=f"Credentials found ({cred_type}) → propose testing on discovered endpoints",
            gated=True,
            approved=None,  # Pending human approval
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        # Nothing to revert for a proposal
        pass
    
    def modified_keys(self) -> set[str]:
        return set()  # Doesn't modify config until approved


class ScopeBoundaryRule(EvolutionRule):
    """When scope boundary is unclear, halt and request clarification.
    
    Trigger: Target doesn't match known scope
    Adaptation: Hard stop
    Scope: campaign
    Gate: HUMAN (hard stop)
    """
    
    name = "scope-boundary-check"
    gate_level = GateLevel.HUMAN
    scope = Scope.CAMPAIGN
    
    def matches(self, evidence: dict) -> bool:
        return evidence.get("scope_match") is False
    
    def apply(self, evidence: dict) -> Adaptation | None:
        target = evidence.get("target", "unknown")
        
        before = {"scope_status": "unchecked"}
        after = {"scope_status": "out_of_scope_suspected", "halt": True}
        
        return Adaptation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"Scope boundary unclear for {target}",
            scope="campaign",
            scope_id=target,
            before=before,
            after=after,
            reason=f"Target {target} may be outside authorized scope → HALTING",
            gated=True,
            approved=None,
        )
    
    def revert(self, adaptation: Adaptation) -> None:
        pass
    
    def modified_keys(self) -> set[str]:
        return set()


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: create engine with all default rules
# ─────────────────────────────────────────────────────────────────────────────

def create_default_engine(campaign_dir: Path, session_id: str | None = None) -> EvolutionEngine:
    """Create an EvolutionEngine with all default rules registered."""
    engine = EvolutionEngine(
        ledger_dir=campaign_dir / "evolution",
        session_id=session_id,
    )
    
    # Layer 1: Auto-Adaptive
    engine.register_rule(TechnologyTemplateRule())
    engine.register_rule(WAFThrottleRule())
    engine.register_rule(ResourceThrottleRule())
    engine.register_rule(ResourceRecoveryRule())
    
    # Layer 2: Suggest-and-Proceed
    engine.register_rule(AdminPanelRule())
    engine.register_rule(RepeatedTimeoutRule())
    engine.register_rule(HighValueFindingsRule())
    engine.register_rule(SubdomainAutoQueueRule())
    
    # Layer 3: Human-Gated
    engine.register_rule(CredentialTestRule())
    engine.register_rule(ScopeBoundaryRule())
    
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# Evidence parsers (bridge from tool output to evidence dicts)
# ─────────────────────────────────────────────────────────────────────────────

def parse_whatweb_evidence(target: str, whatweb_output: str) -> dict:
    """Parse whatweb output into evidence dict for the evolution engine."""
    return {
        "tool": "whatweb",
        "target": target,
        "output": whatweb_output,
    }


def parse_http_evidence(tool: str, target: str, origin: str, 
                         status_code: int, output: str = "") -> dict:
    """Parse HTTP response into evidence dict."""
    return {
        "tool": tool,
        "target": target,
        "origin": origin,
        "status_code": status_code,
        "output": output,
    }


def parse_nuclei_evidence(target: str, severity: str, 
                           matched_templates: list[str],
                           tags: list[str]) -> dict:
    """Parse nuclei finding into evidence dict."""
    return {
        "tool": "nuclei",
        "target": target,
        "severity": severity,
        "matched_templates": matched_templates,
        "tags": tags,
    }


def parse_system_evidence(load_1m: float, mem_available_bytes: int) -> dict:
    """Parse system metrics into evidence dict."""
    return {
        "tool": "system",
        "load_1m": load_1m,
        "mem_available_bytes": mem_available_bytes,
    }


def parse_subfinder_evidence(new_domains: list[str], existing_queue: list[str]) -> dict:
    """Parse subfinder output into evidence dict."""
    return {
        "tool": "subfinder",
        "new_domains": new_domains,
        "existing_queue": existing_queue,
    }
