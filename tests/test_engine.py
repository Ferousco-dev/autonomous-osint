"""Unit tests for the Autonomous OSINT Research Engine."""

from pathlib import Path

from osint_engine.classifier import EntityType, classify_input
from osint_engine.report import generate_report
from osint_engine.state import SessionStore
from osint_engine.verifier import score_from_sources


def test_classifier_universal_inputs() -> None:
    assert classify_input("8.8.8.8").primary_type == EntityType.IP_ADDRESS
    assert classify_input("alice@example.com").primary_type == EntityType.EMAIL
    assert classify_input("example.com").primary_type == EntityType.DOMAIN
    assert classify_input("https://example.com/about").primary_type == EntityType.URL
    assert classify_input("octocat/Hello-World").primary_type == EntityType.GITHUB_REPO
    assert classify_input("@torvalds").primary_type == EntityType.USERNAME
    assert classify_input("Acme Labs Inc.").primary_type == EntityType.ORGANIZATION
    single = classify_input("Anthropic")
    assert len(single.recommended_collectors) >= 4
    assert len(single.initial_queries) >= 2


def test_session_dedup_and_report_sections(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "sess1")
    try:
        store.set_meta("session_id", "sess1")
        store.set_meta("subject", "example.com")
        store.set_meta("classification", classify_input("example.com").model_dump())

        assert store.record_search("rdap", "example.com", "ok", 1) is True
        assert store.record_search("rdap", "EXAMPLE.COM", "ok", 1) is False  # deduplicated

        assert store.add_source("https://rdap.org/domain/example.com", title="RDAP", collector="rdap") is True
        assert store.add_source("https://rdap.org/domain/example.com", title="RDAP", collector="rdap") is False

        store.add_entity("example.com", "domain")
        store.add_relationship("example.com", "uses_nameserver", "a.iana-servers.net", evidence_url="https://rdap.org/domain/example.com", confidence="VERY HIGH")
        store.add_finding(
            category="Technical Findings",
            claim="example.com is reserved by IANA.",
            confidence="VERY HIGH",
            source_urls=["https://rdap.org/domain/example.com"],
            rationale="Authoritative RDAP record.",
        )

        report = generate_report(store)
        for section in [
            "## 1. Executive Summary",
            "## 2. Subject Identification",
            "## 3. Background",
            "## 4. Key Findings",
            "## 5. Source Inventory",
            "## 6. Discovered Connections",
            "## 7. Entity Relationship Map",
            "## 8. Timeline of Events",
            "## 9. Technical Findings",
            "## 10. Conflicting Information",
            "## 11. Unverified Claims",
            "## 12. Confidence Assessment",
            "## 13. Research Gaps",
            "## 14. Recommended Next Investigations",
            "## 15. Complete Source References",
        ]:
            assert section in report
    finally:
        store.close()


def test_verifier_scoring() -> None:
    assert score_from_sources(0) == "UNVERIFIED"
    assert score_from_sources(2, has_authoritative=True) == "VERY HIGH"
    assert score_from_sources(3, has_authoritative=False) == "HIGH"
    assert score_from_sources(2, has_conflict=True) == "LOW"
