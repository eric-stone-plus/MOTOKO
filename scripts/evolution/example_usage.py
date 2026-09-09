#!/usr/bin/env python3
"""
Example: Using the MOTOKO Evolution Engine in a scan pipeline.

This demonstrates how to integrate controlled self-evolution into unified-scan.py.
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent))

from evolution import (
    EvolutionEngine,
    create_default_engine,
    parse_whatweb_evidence,
    parse_http_evidence,
    parse_nuclei_evidence,
    parse_system_evidence,
    parse_subfinder_evidence,
)


def example_scan_pipeline():
    """Example of how to use the evolution engine in a scan pipeline."""
    
    # 1. Create engine for this campaign
    campaign_dir = Path("/tmp/example-campaign-20260909")
    engine = create_default_engine(campaign_dir, session_id="example-session")
    
    print("=" * 60)
    print("MOTOKO Evolution Engine - Example Pipeline")
    print("=" * 60)
    
    # 2. Simulate scanning a WordPress site
    print("\n[1] Scanning blog.example.com (WordPress)...")
    evidence = parse_whatweb_evidence("blog.example.com", "WordPress 6.4 PHP/8.2 Apache/2.4")
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
        print(f"      Tags: {a.after.get('nuclei_tags', [])}")
    
    # 3. Simulate scanning a Java API
    print("\n[2] Scanning api.example.com (Java/Spring)...")
    evidence = parse_whatweb_evidence("api.example.com", "Spring Boot 3.2 Java/17 Tomcat/10")
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
        print(f"      Tags: {a.after.get('nuclei_tags', [])}")
    
    # 4. Simulate WAF detection
    print("\n[3] Nuclei scan on api.example.com returns 429...")
    evidence = parse_http_evidence("nuclei", "api.example.com", "api.example.com", 429)
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
        print(f"      Throttle: {a.after}")
    
    # 5. Simulate system resource pressure
    print("\n[4] System load spike detected...")
    evidence = parse_system_evidence(load_1m=12.5, mem_available_bytes=3 * 1024**3)
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
    
    # 6. Simulate high-value finding
    print("\n[5] Critical RCE finding on api.example.com...")
    evidence = parse_nuclei_evidence(
        target="api.example.com",
        severity="critical",
        matched_templates=["CVE-2024-1234-rce"],
        tags=["rce", "cve", "spring"],
    )
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
        if a.gated and a.approved is None:
            print(f"      ⚠️  REQUIRES HUMAN APPROVAL")
    
    # 7. Simulate subfinder finding new subdomains
    print("\n[6] Subfinder discovers new subdomains...")
    evidence = parse_subfinder_evidence(
        new_domains=["staging.example.com", "dev.example.com", "admin.example.com"],
        existing_queue=["blog.example.com", "api.example.com"],
    )
    adaptations = engine.process_evidence(evidence)
    
    print(f"    Adaptations: {len(adaptations)}")
    for a in adaptations:
        print(f"    - {a.rule_name}: {a.reason}")
        print(f"      New domains: {a.after.get('new_domains', [])}")
    
    # 8. Show summary
    print("\n" + "=" * 60)
    print("SESSION SUMMARY")
    print("=" * 60)
    summary = engine.get_summary()
    print(f"Session ID: {summary['session_id']}")
    print(f"Total adaptations: {summary['total_adaptations']}")
    print(f"Reverted: {summary['reverted']}")
    print(f"Blocked: {summary['blocked']}")
    print(f"\nPer-target counts:")
    for target, count in summary['per_target'].items():
        print(f"  {target}: {count}")
    print(f"\nPer-origin counts:")
    for origin, count in summary['per_origin'].items():
        print(f"  {origin}: {count}")
    
    # 9. Show audit trail
    print("\n" + "=" * 60)
    print("AUDIT TRAIL (adaptations.jsonl)")
    print("=" * 60)
    ledger_path = campaign_dir / "evolution" / "adaptations.jsonl"
    if ledger_path.exists():
        with open(ledger_path) as f:
            for i, line in enumerate(f, 1):
                print(f"[{i}] {line.strip()[:100]}...")
    
    # 10. Demonstrate revert
    print("\n" + "=" * 60)
    print("REVERT DEMO")
    print("=" * 60)
    print("Reverting all adaptations...")
    count = engine.revert_all()
    print(f"Reverted {count} adaptations")
    
    print("\nDone! All adaptations are logged and reversible.")


if __name__ == "__main__":
    example_scan_pipeline()
