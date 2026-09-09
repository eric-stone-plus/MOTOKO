# MOTOKO Controlled Self-Evolution Framework

## Design Principles

1. **Code, not MEMORY.** Every adaptation rule is a Python class/function that can be version-controlled, tested, and rolled back.
2. **Bounded.** Max N adaptations per session. Each adaptation has a scope (target/origin/campaign/global).
3. **Auditable.** Every adaptation writes a JSONL record with: trigger, rule, before-state, after-state, reason, timestamp.
4. **Reproducible.** Given the same evidence log, the same adaptations fire. No randomness.
5. **Human-gated for high-risk.** New attack patterns, scope expansion, credential testing require explicit approval.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    unified-scan.py                           │
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Evidence  │───▶│  Perception  │───▶│  Evolution Engine │   │
│  │ Collector │    │  (classify)  │    │  (adapt pipeline) │   │
│  └──────────┘    └──────────────┘    └──────────────────┘   │
│       │                │                       │            │
│       │                │                       ▼            │
│       │                │            ┌──────────────────┐    │
│       │                │            │  Adaptation Ledger│    │
│       │                │            │  (JSONL, bounded) │    │
│       │                │            └──────────────────┘    │
│       │                │                       │            │
│       ▼                ▼                       ▼            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Modified Pipeline Config                │    │
│  │  (tool selection, templates, throttling, depth)      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Three-Layer Adaptation

### Layer 1: Auto-Adaptive (no human gate)
Safe, bounded adjustments that improve efficiency without changing attack surface.

| Trigger | Adaptation | Scope | Bound |
|---------|-----------|-------|-------|
| whatweb detects WordPress | Add `wordpress` nuclei tag | current target | 1 per target |
| whatweb detects Java/Spring | Add `spring`, `java` nuclei tags | current target | 1 per target |
| 429/WAF detected on origin | Reduce workers to 1, increase delay | current origin | auto-recover after 300s |
| High CPU load (>10) | Reduce concurrent workers by 1 | global | min 1, recovers when load drops |
| Low memory (<4G) | Pause non-essential tools | global | resumes when memory frees |
| New subdomain from subfinder | Add to queue (after WHOIS/ASN check) | campaign | max 50 per campaign |
| Nuclei template finds nothing for tech | Skip that template category for similar targets | campaign | logged, not silent |

### Layer 2: Suggest-and-Proceed (logged, user notified)
Adaptations that change tool selection or scan depth. Applied immediately but flagged for review.

| Trigger | Adaptation | Scope | Bound |
|---------|-----------|-------|-------|
| whatweb detects admin panel | Add `admin-panel` nuclei tag, try common creds list | current target | 1 per target |
| Technology change (WordPress → API) | Switch from ffuf to feroxbuster for API endpoints | current target | 1 per origin |
| Repeated timeouts on target | Increase timeout by 2x, reduce concurrency | current target | max 2x original |
| High-value finding (RCE, SQLi) | Flag target for deeper scan in next pass | campaign | max 3 flagged |

### Layer 3: Human-Gated (requires explicit approval)
Adaptations that change attack surface or risk profile.

| Trigger | Adaptation | Gate |
|---------|-----------|------|
| Credential found in source | Test credential on discovered endpoints | User approval + scope check |
| New attack pattern not in MOTOKO | Propose new tool/template addition | User approval |
| Scope boundary unclear | Halt and request clarification | Hard stop |
| High-impact finding (RCE proof) | Auto-exploit to prove impact | User approval |

## Implementation: `evolution.py`

### Core Classes

```python
@dataclass
class Adaptation:
    """A single adaptation event."""
    id: str                    # UUID
    timestamp: str             # ISO-8601
    rule_name: str             # Which rule fired
    trigger: str               # What evidence triggered it
    scope: str                 # target | origin | campaign | global
    scope_id: str              # Which target/origin/campaign
    before: dict               # State before adaptation
    after: dict                # State after adaptation
    reason: str                # Human-readable explanation
    gated: bool                # Whether it needs human approval
    approved: bool | None      # None=pending, True/False=gated result
    reverted: bool = False     # Whether it was rolled back

class EvolutionEngine:
    """Manages bounded, auditable adaptation."""
    
    def __init__(self, ledger_path: Path, max_per_session: int = 20):
        self.ledger_path = ledger_path
        self.max_per_session = max_per_session
        self.adaptations: list[Adaptation] = []
        self.rules: list[EvolutionRule] = []
        self.session_count = 0
    
    def register_rule(self, rule: 'EvolutionRule'):
        """Add an adaptation rule."""
        self.rules.append(rule)
    
    def process_evidence(self, evidence: dict) -> list[Adaptation]:
        """Run evidence through all rules, return adaptations."""
        if self.session_count >= self.max_per_session:
            return []
        
        adaptations = []
        for rule in self.rules:
            if rule.matches(evidence):
                adaptation = rule.apply(evidence)
                if adaptation:
                    adaptations.append(adaptation)
                    self.session_count += 1
                    self._log(adaptation)
                    if self.session_count >= self.max_per_session:
                        break
        
        return adaptations
    
    def revert(self, adaptation_id: str):
        """Revert a specific adaptation."""
        for a in self.adaptations:
            if a.id == adaptation_id:
                a.rule.revert(a)
                a.reverted = True
                self._log_revert(a)
                break
    
    def _log(self, adaptation: Adaptation):
        """Write to JSONL ledger."""
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(asdict(adaptation)) + '\n')

class EvolutionRule(ABC):
    """Base class for adaptation rules."""
    
    @abstractmethod
    def matches(self, evidence: dict) -> bool:
        """Does this evidence trigger the rule?"""
    
    @abstractmethod
    def apply(self, evidence: dict) -> Adaptation | None:
        """Apply the adaptation, return the adaptation record."""
    
    @abstractmethod
    def revert(self, adaptation: Adaptation):
        """Revert the adaptation."""
```

### Concrete Rules

```python
class WordPressTemplateRule(EvolutionRule):
    """When whatweb detects WordPress, add WordPress nuclei templates."""
    
    name = "wordpress-template-selection"
    scope = "target"
    
    def matches(self, evidence: dict) -> bool:
        return (evidence.get("tool") == "whatweb" and 
                "WordPress" in evidence.get("output", ""))
    
    def apply(self, evidence: dict) -> Adaptation:
        target = evidence["target"]
        # Get current nuclei config for this target
        before = get_nuclei_config(target)
        # Add WordPress tags
        add_nuclei_tags(target, ["wordpress", "wp-plugin", "wp-theme"])
        after = get_nuclei_config(target)
        
        return Adaptation(
            id=str(uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger="whatweb detected WordPress",
            scope="target",
            scope_id=target,
            before=before,
            after=after,
            reason="WordPress detected → adding wp-specific nuclei templates",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation):
        target = adaptation.scope_id
        remove_nuclei_tags(target, ["wordpress", "wp-plugin", "wp-theme"])

class WAFThrottleRule(EvolutionRule):
    """When 429/WAF detected, auto-throttle per origin."""
    
    name = "waf-auto-throttle"
    scope = "origin"
    
    def matches(self, evidence: dict) -> bool:
        return (evidence.get("tool") in ("nuclei", "katana", "ffuf") and
                evidence.get("status_code") in (429, 403, 503))
    
    def apply(self, evidence: dict) -> Adaptation:
        origin = evidence["origin"]
        before = get_origin_throttle(origin)
        set_origin_throttle(origin, workers=1, delay_ms=2000)
        after = get_origin_throttle(origin)
        
        return Adaptation(
            id=str(uuid4()),
            timestamp=datetime.now(UTC).isoformat(),
            rule_name=self.name,
            trigger=f"HTTP {evidence['status_code']} on {origin}",
            scope="origin",
            scope_id=origin,
            before=before,
            after=after,
            reason=f"WAF/rate-limit detected → reducing to 1 worker, 2s delay",
            gated=False,
            approved=True,
        )
    
    def revert(self, adaptation: Adaptation):
        origin = adaptation.scope_id
        reset_origin_throttle(origin)
```

## Pipeline Integration

The evolution engine sits between evidence collection and pipeline execution:

```python
# In unified-scan.py's main loop:

evolution = EvolutionEngine(
    ledger_path=campaign_dir / "evolution" / "adaptations.jsonl",
    max_per_session=20,
)

# Register rules
evolution.register_rule(WordPressTemplateRule())
evolution.register_rule(WAFThrottleRule())
evolution.register_rule(JavaTemplateRule())
evolution.register_rule(ResourceThrottleRule())
# ... more rules

# Main scan loop
for target in queue:
    # 1. Run whatweb first (always)
    whatweb_result = run_whatweb(target)
    
    # 2. Feed evidence to evolution engine
    evidence = parse_whatweb(whatweb_result)
    adaptations = evolution.process_evidence(evidence)
    
    # 3. Log adaptations (already done by engine)
    for a in adaptations:
        if a.gated and a.approved is None:
            notify_user(a)  # Slack/Telegram notification
            # Don't proceed until approved
    
    # 4. Run remaining pipeline with adapted config
    nuclei_config = get_adapted_nuclei_config(target, adaptations)
    run_nuclei(target, config=nuclei_config)
    
    # ... rest of pipeline
```

## Safeguards

### 1. Session Bound
```python
MAX_ADAPTATIONS_PER_SESSION = 20  # Hard cap
MAX_ADAPTATIONS_PER_TARGET = 5    # Per-target cap
```

### 2. Rollback
Every adaptation is reversible. The ledger stores before-state:
```python
# At end of session, or on error:
for adaptation in reversed(evolution.adaptations):
    if not adaptation.reverted:
        evolution.revert(adaptation.id)
```

### 3. Audit Trail
JSONL ledger with every adaptation:
```json
{"id":"abc-123","timestamp":"2026-09-09T10:30:00Z","rule_name":"wordpress-template-selection","trigger":"whatweb detected WordPress","scope":"target","scope_id":"blog.example.com","before":{"tags":[]},"after":{"tags":["wordpress","wp-plugin","wp-theme"]},"reason":"WordPress detected → adding wp-specific nuclei templates","gated":false,"approved":true,"reverted":false}
```

### 4. Idempotency
Rules check if adaptation already applied:
```python
def apply(self, evidence: dict) -> Adaptation | None:
    target = evidence["target"]
    existing = get_nuclei_tags(target)
    if "wordpress" in existing:
        return None  # Already adapted, skip
    # ... apply adaptation
```

### 5. Conflict Detection
If two rules try to modify the same config key, the second one is blocked:
```python
def process_evidence(self, evidence: dict) -> list[Adaptation]:
    # ...
    for rule in self.rules:
        if rule.matches(evidence):
            # Check for conflicts with existing adaptations
            if self._has_conflict(rule, evidence):
                log_conflict(rule, evidence)
                continue
            # ...
```

### 6. Learning Rate Decay
Don't keep applying the same adaptation to similar targets:
```python
class TemplateRule(EvolutionRule):
    def __init__(self):
        self.seen_technologies: dict[str, int] = {}
    
    def matches(self, evidence: dict) -> bool:
        tech = extract_technology(evidence)
        if self.seen_technologies.get(tech, 0) > 3:
            return False  # Stop adapting for this tech after 3 targets
        # ...
```

## File Structure

```
motoko/
├── SKILL.md
├── references/
│   └── evolution-design.md          # This file
├── scripts/
│   ├── evolution.py                 # Core engine + rules
│   ├── unified-scan.py              # Main orchestrator
│   └── rules/
│       ├── __init__.py
│       ├── template_selection.py    # Tech → nuclei template rules
│       ├── throttle.py              # WAF/load throttling rules
│       ├── resource.py              # CPU/memory adaptation rules
│       └── target_priority.py       # Findings-driven prioritization
└── tests/
    ├── test_evolution.py            # Unit tests for rules
    └── test_reproducibility.py      # Verify same evidence → same adaptations
```

## Version Control

The rules themselves are version-controlled. The adaptation ledger is campaign-specific:
```
campaign-20260909/
├── evidence/
│   └── evolution/
│       ├── adaptations.jsonl        # What happened
│       ├── session-state.json       # Current bounds/counts
│       └── conflicts.jsonl          # Blocked adaptations
└── reports/
    └── evolution-summary.md         # Human-readable summary
```

## Testing

Every rule must pass:
1. **Unit test**: `matches()` returns True/False correctly
2. **Apply test**: `apply()` produces correct Adaptation
3. **Revert test**: `revert()` restores before-state
4. **Idempotency test**: Applying twice doesn't double-adapt
5. **Bound test**: Session limit enforced
6. **Reproducibility test**: Same evidence → same adaptations (deterministic)