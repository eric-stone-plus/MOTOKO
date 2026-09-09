#!/usr/bin/env python3
"""
Tests for MOTOKO Evolution Engine.

Verifies:
1. Rules match correctly
2. Adaptations are applied and logged
3. Bounds are enforced (per-session, per-target, per-origin)
4. Revert works
5. Idempotency (same evidence doesn't double-adapt)
6. Conflict detection
7. Human-gated rules don't auto-apply
8. Reproducibility (same evidence → same adaptations)
"""

import json
import tempfile
from pathlib import Path

import pytest

# Add parent to path for import
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from evolution import (
    Adaptation,
    EvolutionEngine,
    Scope,
    GateLevel,
    TechnologyTemplateRule,
    AdminPanelRule,
    WAFThrottleRule,
    RepeatedTimeoutRule,
    ResourceThrottleRule,
    ResourceRecoveryRule,
    HighValueFindingsRule,
    SubdomainAutoQueueRule,
    CredentialTestRule,
    ScopeBoundaryRule,
    create_default_engine,
    parse_whatweb_evidence,
    parse_http_evidence,
    parse_nuclei_evidence,
    parse_system_evidence,
    parse_subfinder_evidence,
    MAX_ADAPTATIONS_PER_SESSION,
    MAX_ADAPTATIONS_PER_TARGET,
)


@pytest.fixture
def tmp_campaign(tmp_path):
    """Create a temporary campaign directory."""
    return tmp_path / "campaign-20260909"


@pytest.fixture
def engine(tmp_campaign):
    """Create an EvolutionEngine with all default rules."""
    return create_default_engine(tmp_campaign, session_id="test-session")


# ─────────────────────────────────────────────────────────────────────────────
# Technology Template Rule
# ─────────────────────────────────────────────────────────────────────────────

class TestTechnologyTemplateRule:
    
    def test_wordpress_detection(self, engine):
        evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4 PHP/8.2")
        adaptations = engine.process_evidence(evidence)
        
        assert len(adaptations) >= 1
        wp_adaptation = next(a for a in adaptations if "wordpress" in a.after.get("nuclei_tags", []))
        assert "wordpress" in wp_adaptation.after["nuclei_tags"]
        assert "wp-plugin" in wp_adaptation.after["nuclei_tags"]
        assert wp_adaptation.scope == "target"
        assert wp_adaptation.approved is True
    
    def test_java_spring_detection(self, engine):
        evidence = parse_whatweb_evidence("api.example.com", "Spring Boot 3.2 Java/17 Tomcat")
        adaptations = engine.process_evidence(evidence)
        
        assert len(adaptations) >= 1
        tags = set()
        for a in adaptations:
            tags.update(a.after.get("nuclei_tags", []))
        assert "spring" in tags or "java" in tags
    
    def test_idempotency(self, engine):
        evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        
        # First application
        adaptations1 = engine.process_evidence(evidence)
        assert len(adaptations1) >= 1
        
        # Second application with same evidence
        adaptations2 = engine.process_evidence(evidence)
        # Should not re-apply (idempotent)
        # The TechnologyTemplateRule tracks applied "target:tech" pairs
        assert len(adaptations2) == 0 or all(
            a.rule_name != "technology-template-selection" for a in adaptations2
        )
    
    def test_no_match_for_unknown_tech(self, engine):
        evidence = parse_whatweb_evidence("unknown.example.com", "CustomFramework/1.0")
        adaptations = engine.process_evidence(evidence)
        
        tech_adaptations = [a for a in adaptations if a.rule_name == "technology-template-selection"]
        assert len(tech_adaptations) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Admin Panel Rule
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminPanelRule:
    
    def test_admin_detection(self, engine):
        evidence = parse_whatweb_evidence("admin.example.com", "WordPress wp-admin login page")
        adaptations = engine.process_evidence(evidence)
        
        admin_adaptations = [a for a in adaptations if a.rule_name == "admin-panel-detection"]
        assert len(admin_adaptations) >= 1
        assert "admin-panel" in admin_adaptations[0].after["nuclei_tags"]
    
    def test_phpmyadmin_detection(self, engine):
        evidence = parse_whatweb_evidence("db.example.com", "phpMyAdmin 5.2 MySQL")
        adaptations = engine.process_evidence(evidence)
        
        admin_adaptations = [a for a in adaptations if a.rule_name == "admin-panel-detection"]
        assert len(admin_adaptations) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# WAF Throttle Rule
# ─────────────────────────────────────────────────────────────────────────────

class TestWAFThrottleRule:
    
    def test_429_triggers_throttle(self, engine):
        evidence = parse_http_evidence("nuclei", "target.com", "target.com", 429)
        adaptations = engine.process_evidence(evidence)
        
        waf_adaptations = [a for a in adaptations if a.rule_name == "waf-auto-throttle"]
        assert len(waf_adaptations) == 1
        assert waf_adaptations[0].after["workers"] == 1
        assert waf_adaptations[0].after["delay_ms"] == 2000
    
    def test_403_triggers_throttle(self, engine):
        evidence = parse_http_evidence("katana", "target.com", "target.com", 403)
        adaptations = engine.process_evidence(evidence)
        
        waf_adaptations = [a for a in adaptations if a.rule_name == "waf-auto-throttle"]
        assert len(waf_adaptations) == 1
    
    def test_idempotency_per_origin(self, engine):
        evidence = parse_http_evidence("nuclei", "target.com", "target.com", 429)
        
        # First application
        adaptations1 = engine.process_evidence(evidence)
        assert len([a for a in adaptations1 if a.rule_name == "waf-auto-throttle"]) == 1
        
        # Second application for same origin
        adaptations2 = engine.process_evidence(evidence)
        assert len([a for a in adaptations2 if a.rule_name == "waf-auto-throttle"]) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Resource Throttle Rule
# ─────────────────────────────────────────────────────────────────────────────

class TestResourceThrottleRule:
    
    def test_high_load_triggers_throttle(self, engine):
        evidence = parse_system_evidence(load_1m=15.0, mem_available_bytes=8 * 1024**3)
        adaptations = engine.process_evidence(evidence)
        
        resource_adaptations = [a for a in adaptations if a.rule_name == "resource-auto-throttle"]
        assert len(resource_adaptations) == 1
        assert resource_adaptations[0].scope == "global"
    
    def test_low_memory_triggers_throttle(self, engine):
        evidence = parse_system_evidence(load_1m=5.0, mem_available_bytes=2 * 1024**3)
        adaptations = engine.process_evidence(evidence)
        
        resource_adaptations = [a for a in adaptations if a.rule_name == "resource-auto-throttle"]
        assert len(resource_adaptations) == 1
    
    def test_normal_resources_no_throttle(self, engine):
        evidence = parse_system_evidence(load_1m=3.0, mem_available_bytes=8 * 1024**3)
        adaptations = engine.process_evidence(evidence)
        
        resource_adaptations = [a for a in adaptations if a.rule_name == "resource-auto-throttle"]
        assert len(resource_adaptations) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Bounds Enforcement
# ─────────────────────────────────────────────────────────────────────────────

class TestBounds:
    
    def test_session_bound(self, tmp_campaign):
        engine = EvolutionEngine(
            ledger_dir=tmp_campaign / "evolution",
            max_per_session=3,
            session_id="bound-test",
        )
        engine.register_rule(TechnologyTemplateRule())
        
        # Apply adaptations for different targets
        for i in range(5):
            evidence = parse_whatweb_evidence(f"target{i}.example.com", f"WordPress PHP/{i}")
            engine.process_evidence(evidence)
        
        # Should only have 3 adaptations (session bound)
        assert engine.state.total_count <= 3
    
    def test_per_target_bound(self, tmp_campaign):
        engine = EvolutionEngine(
            ledger_dir=tmp_campaign / "evolution",
            max_per_target=2,
            session_id="target-bound-test",
        )
        engine.register_rule(TechnologyTemplateRule())
        engine.register_rule(AdminPanelRule())
        
        # Same target, multiple evidence
        evidence1 = parse_whatweb_evidence("target.com", "WordPress wp-admin PHP")
        engine.process_evidence(evidence1)
        
        # Second round - should be limited
        evidence2 = parse_whatweb_evidence("target.com", "WordPress wp-admin PHP")
        adaptations2 = engine.process_evidence(evidence2)
        
        # Per-target count should not exceed 2
        assert engine.state.per_target.get("target.com", 0) <= 2


# ─────────────────────────────────────────────────────────────────────────────
# Revert
# ─────────────────────────────────────────────────────────────────────────────

class TestRevert:
    
    def test_single_revert(self, engine):
        evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        adaptations = engine.process_evidence(evidence)
        
        assert len(adaptations) >= 1
        adaptation_id = adaptations[0].id
        
        # Revert
        success = engine.revert(adaptation_id)
        assert success is True
        
        # Check it's marked as reverted
        reverted = next(a for a in engine.adaptations if a.id == adaptation_id)
        assert reverted.reverted is True
        assert reverted.revert_timestamp is not None
    
    def test_revert_all(self, engine):
        # Create multiple adaptations
        evidence1 = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        evidence2 = parse_http_evidence("nuclei", "api.example.com", "api.example.com", 429)
        
        engine.process_evidence(evidence1)
        engine.process_evidence(evidence2)
        
        count = engine.revert_all()
        assert count >= 2
        
        # All should be reverted
        for a in engine.adaptations:
            assert a.reverted is True


# ─────────────────────────────────────────────────────────────────────────────
# Human-Gated Rules
# ─────────────────────────────────────────────────────────────────────────────

class TestHumanGated:
    
    def test_credential_rule_pending(self, engine):
        evidence = {
            "tool": "trufflehog",
            "target": "api.example.com",
            "finding_type": "credential",
            "credential_type": "AWS_ACCESS_KEY",
        }
        adaptations = engine.process_evidence(evidence)
        
        cred_adaptations = [a for a in adaptations if a.rule_name == "credential-test-proposal"]
        assert len(cred_adaptations) == 1
        assert cred_adaptations[0].gated is True
        assert cred_adaptations[0].approved is None  # Pending
    
    def test_approve_adaptation(self, engine):
        evidence = {
            "tool": "trufflehog",
            "target": "api.example.com",
            "finding_type": "credential",
            "credential_type": "AWS_ACCESS_KEY",
        }
        adaptations = engine.process_evidence(evidence)
        
        cred_adaptation = next(a for a in adaptations if a.rule_name == "credential-test-proposal")
        
        # Approve
        approved = engine.approve_adaptation(cred_adaptation.id)
        assert approved is not None
        assert approved.approved is True
    
    def test_reject_adaptation(self, engine):
        evidence = {
            "tool": "trufflehog",
            "target": "api.example.com",
            "finding_type": "credential",
            "credential_type": "AWS_ACCESS_KEY",
        }
        adaptations = engine.process_evidence(evidence)
        
        cred_adaptation = next(a for a in adaptations if a.rule_name == "credential-test-proposal")
        
        # Reject
        rejected = engine.reject_adaptation(cred_adaptation.id)
        assert rejected is not None
        assert rejected.approved is False


# ─────────────────────────────────────────────────────────────────────────────
# High-Value Findings
# ─────────────────────────────────────────────────────────────────────────────

class TestHighValueFindings:
    
    def test_rce_finding(self, engine):
        evidence = parse_nuclei_evidence(
            target="api.example.com",
            severity="critical",
            matched_templates=["CVE-2024-1234-rce"],
            tags=["rce", "cve"],
        )
        adaptations = engine.process_evidence(evidence)
        
        hv_adaptations = [a for a in adaptations if a.rule_name == "high-value-findings-deep-scan"]
        assert len(hv_adaptations) == 1
        assert hv_adaptations[0].after["deep_scan_flagged"] is True
    
    def test_sqli_finding(self, engine):
        evidence = parse_nuclei_evidence(
            target="web.example.com",
            severity="critical",
            matched_templates=["sqli-login-bypass"],
            tags=["sqli", "auth-bypass"],
        )
        adaptations = engine.process_evidence(evidence)
        
        hv_adaptations = [a for a in adaptations if a.rule_name == "high-value-findings-deep-scan"]
        assert len(hv_adaptations) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Auto-Queue
# ─────────────────────────────────────────────────────────────────────────────

class TestSubdomainAutoQueue:
    
    def test_new_subdomains_queued(self, engine):
        evidence = parse_subfinder_evidence(
            new_domains=["api.example.com", "admin.example.com"],
            existing_queue=["www.example.com"],
        )
        adaptations = engine.process_evidence(evidence)
        
        sub_adaptations = [a for a in adaptations if a.rule_name == "subdomain-auto-queue"]
        assert len(sub_adaptations) == 1
        assert "api.example.com" in sub_adaptations[0].after["new_domains"]
        assert "admin.example.com" in sub_adaptations[0].after["new_domains"]
    
    def test_no_duplicate_queue(self, engine):
        evidence = parse_subfinder_evidence(
            new_domains=["api.example.com"],
            existing_queue=["api.example.com"],
        )
        adaptations = engine.process_evidence(evidence)
        
        sub_adaptations = [a for a in adaptations if a.rule_name == "subdomain-auto-queue"]
        assert len(sub_adaptations) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Scope Boundary
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeBoundary:
    
    def test_out_of_scope_halts(self, engine):
        evidence = {
            "tool": "subfinder",
            "target": "unknown-company.com",
            "scope_match": False,
        }
        adaptations = engine.process_evidence(evidence)
        
        scope_adaptations = [a for a in adaptations if a.rule_name == "scope-boundary-check"]
        assert len(scope_adaptations) == 1
        assert scope_adaptations[0].gated is True
        assert scope_adaptations[0].after["halt"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Audit Trail
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditTrail:
    
    def test_ledger_written(self, engine, tmp_campaign):
        evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        engine.process_evidence(evidence)
        
        ledger_path = tmp_campaign / "evolution" / "adaptations.jsonl"
        assert ledger_path.exists()
        
        with open(ledger_path) as f:
            lines = f.readlines()
        
        assert len(lines) >= 1
        
        record = json.loads(lines[0])
        assert "id" in record
        assert "timestamp" in record
        assert "rule_name" in record
        assert "trigger" in record
        assert "before" in record
        assert "after" in record
        assert "reason" in record
    
    def test_state_persisted(self, engine, tmp_campaign):
        evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        engine.process_evidence(evidence)
        
        state_path = tmp_campaign / "evolution" / "session-state.json"
        assert state_path.exists()
        
        with open(state_path) as f:
            state = json.load(f)
        
        assert state["session_id"] == "test-session"
        assert state["total_count"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Reproducibility
# ─────────────────────────────────────────────────────────────────────────────

class TestReproducibility:
    
    def test_same_evidence_same_adaptations(self, tmp_campaign):
        """Given the same evidence, the same adaptations should fire."""
        
        def run_once():
            engine = EvolutionEngine(
                ledger_dir=tmp_campaign / "evolution" / "run1",
                session_id="repro-test-1",
            )
            engine.register_rule(TechnologyTemplateRule())
            engine.register_rule(WAFThrottleRule())
            
            evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4 PHP/8.2")
            adaptations = engine.process_evidence(evidence)
            return adaptations
        
        # Run twice
        adaptations1 = run_once()
        
        # Second run with fresh engine (simulates restart)
        def run_once_2():
            engine = EvolutionEngine(
                ledger_dir=tmp_campaign / "evolution" / "run2",
                session_id="repro-test-2",
            )
            engine.register_rule(TechnologyTemplateRule())
            engine.register_rule(WAFThrottleRule())
            
            evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4 PHP/8.2")
            adaptations = engine.process_evidence(evidence)
            return adaptations
        
        adaptations2 = run_once_2()
        
        # Should produce same adaptations (excluding IDs/timestamps)
        assert len(adaptations1) == len(adaptations2)
        for a1, a2 in zip(adaptations1, adaptations2):
            assert a1.rule_name == a2.rule_name
            assert a1.scope == a2.scope
            assert a1.scope_id == a2.scope_id
            assert a1.trigger == a2.trigger
            assert a1.after == a2.after


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

class TestSummary:
    
    def test_summary_generation(self, engine):
        # Create some adaptations
        evidence1 = parse_whatweb_evidence("blog.example.com", "WordPress 6.4")
        evidence2 = parse_http_evidence("nuclei", "api.example.com", "api.example.com", 429)
        
        engine.process_evidence(evidence1)
        engine.process_evidence(evidence2)
        
        summary = engine.get_summary()
        
        assert summary["session_id"] == "test-session"
        assert summary["total_adaptations"] >= 2
        assert len(summary["adaptations"]) >= 2
        assert "per_target" in summary
        assert "per_origin" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
