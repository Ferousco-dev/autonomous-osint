"""15-section structured OSINT intelligence report generator."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .state import SessionStore, utc_now


def _mermaid_id(label: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", label)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned[:40]


def _escape_mermaid(label: str) -> str:
    return label.replace('"', "'").replace("\n", " ")[:60]


def generate_report(store: SessionStore, output_path: Path | None = None) -> str:
    """Render the full 15-section intelligence report from session state."""
    snap = store.export_snapshot()
    meta = snap["meta"]
    subject = meta.get("subject", "Unknown Subject")
    classification = meta.get("classification", {})
    sources: list[dict[str, Any]] = snap["sources"]
    entities: list[dict[str, Any]] = snap["entities"]
    relationships: list[dict[str, Any]] = snap["relationships"]
    findings: list[dict[str, Any]] = snap["findings"]
    searches: list[dict[str, Any]] = snap["searches"]

    def findings_by_cat(cat: str) -> list[dict[str, Any]]:
        return [f for f in findings if f["category"].lower() == cat.lower()]

    def fmt_finding(f: dict[str, Any]) -> str:
        urls = json.loads(f["source_urls_json"] or "[]")
        links = " ".join(f"[source]({u})" for u in urls) if urls else "_no URL recorded_"
        fact_tag = "FACT" if f["is_fact"] else "ASSUMPTION/INFERENCE"
        pub = f" | Published: `{f['published_date']}`" if f["published_date"] else ""
        rationale = f"\n  - *Rationale:* {f['rationale']}" if f["rationale"] else ""
        return (
            f"- **[{f['confidence']} | {fact_tag}]** {f['claim']} ({links})"
            f"{pub} | Accessed: `{f['accessed_at']}`{rationale}"
        )

    # Build Mermaid entity relationship map
    mermaid_lines = ["```mermaid", "flowchart LR"]
    if relationships:
        for rel in relationships[:40]:
            sid = _mermaid_id(rel["source_entity"])
            tid = _mermaid_id(rel["target_entity"])
            slabel = _escape_mermaid(rel["source_entity"])
            tlabel = _escape_mermaid(rel["target_entity"])
            rlabel = _escape_mermaid(rel["relation"])
            mermaid_lines.append(f'    {sid}["{slabel}"] -->|"{rlabel}"| {tid}["{tlabel}"]')
    else:
        sid = _mermaid_id(subject)
        mermaid_lines.append(f'    {sid}["{_escape_mermaid(subject)}"]')
    mermaid_lines.append("```")

    conflicting = [f for f in findings if f.get("conflicts_with")]
    unverified = [f for f in findings if f["confidence"] == "UNVERIFIED"]
    tech_findings = findings_by_cat("Technical Findings")
    timeline_findings = findings_by_cat("Timeline of Events")
    bg_findings = findings_by_cat("Background")
    key_findings = findings_by_cat("Key Findings")
    conn_findings = findings_by_cat("Discovered Connections")

    # Confidence distribution
    conf_counts: dict[str, int] = {}
    for f in findings:
        conf_counts[f["confidence"]] = conf_counts.get(f["confidence"], 0) + 1

    lines: list[str] = [
        f"# OSINT Intelligence Report: {subject}",
        "",
        f"- **Session ID:** `{meta.get('session_id', store.session_dir.name)}`",
        f"- **Generated (UTC):** `{utc_now()}`",
        f"- **Searches Executed:** {len(searches)} | **Sources Recorded:** {len(sources)} | **Entities:** {len(entities)} | **Findings:** {len(findings)}",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        (
            f"This passive Open Source Intelligence (OSINT) investigation examined **{subject}** "
            f"(classified as `{classification.get('primary_type', 'unknown')}`). "
            f"Across {len(searches)} recorded queries and {len(sources)} unique public sources, "
            f"the engine extracted {len(entities)} entities, {len(relationships)} relationships, and {len(findings)} evidence-backed findings."
        ),
        "",
        "## 2. Subject Identification",
        "",
        f"- **Raw Input:** `{classification.get('raw_input', subject)}`",
        f"- **Normalized Identifier:** `{classification.get('normalized', subject)}`",
        f"- **Primary Classification:** `{classification.get('primary_type', 'unknown')}`",
        f"- **Secondary Candidates:** `{', '.join(classification.get('secondary_types', [])) or 'None'}`",
        f"- **Classification Notes:** {classification.get('notes', 'N/A')}",
        "",
        "## 3. Background",
        "",
        *(
            [fmt_finding(f) for f in bg_findings]
            if bg_findings
            else ["_No dedicated background summary recorded yet; see Key Findings._"]
        ),
        "",
        "## 4. Key Findings",
        "",
        *(
            [fmt_finding(f) for f in key_findings]
            if key_findings
            else ["_No key findings recorded yet._"]
        ),
        "",
        "## 5. Source Inventory",
        "",
        "| # | Collector | Type | Title | Published | Accessed (UTC) | URL |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, s in enumerate(sources, start=1):
        title = (s["title"] or "Untitled").replace("|", "-")[:70]
        lines.append(
            f"| {idx} | `{s['collector']}` | `{s['source_type']}` | {title} | {s['published_date'] or '-'} | `{s['accessed_at']}` | [link]({s['url']}) |"
        )
    if not sources:
        lines.append("| - | - | - | _No sources recorded_ | - | - | - |")

    lines.extend(
        [
            "",
            "## 6. Discovered Connections",
            "",
            *(
                [fmt_finding(f) for f in conn_findings]
                if conn_findings
                else [
                    f"- **{r['source_entity']}** —`{r['relation']}`→ **{r['target_entity']}** (`{r['confidence']}`, [evidence]({r['evidence_url']}))"
                    for r in relationships[:25]
                ]
                or ["_No external connections mapped yet._"]
            ),
            "",
            "## 7. Entity Relationship Map",
            "",
            *mermaid_lines,
            "",
            "## 8. Timeline of Events",
            "",
            *(
                [fmt_finding(f) for f in timeline_findings]
                if timeline_findings
                else ["_No dated timeline events extracted yet._"]
            ),
            "",
            "## 9. Technical Findings",
            "",
            *(
                [fmt_finding(f) for f in tech_findings]
                if tech_findings
                else ["_Not applicable or no technical infrastructure data collected._"]
            ),
            "",
            "## 10. Conflicting Information",
            "",
            *(
                [f"- {fmt_finding(f)} (Conflicts with: {f['conflicts_with']})" for f in conflicting]
                if conflicting
                else ["_No conflicting claims detected across collected sources._"]
            ),
            "",
            "## 11. Unverified Claims",
            "",
            *(
                [fmt_finding(f) for f in unverified]
                if unverified
                else ["_No unverified claims logged._"]
            ),
            "",
            "## 12. Confidence Assessment",
            "",
            *(
                [f"- **{level}:** {count} finding(s)" for level, count in sorted(conf_counts.items())]
                if conf_counts
                else ["- _No findings scored yet._"]
            ),
            "",
            "## 13. Research Gaps",
            "",
            "- Platforms requiring authentication, paywalls, or CAPTCHA solving were intentionally not accessed.",
            "- Collectors not executed in this session are excluded from claims (only executed queries are listed in `state.db`).",
            "",
            "## 14. Recommended Next Investigations",
            "",
            *(
                [
                    f"- Pivot on `{ld['target']}` using collector `{ld['collector']}` (depth {ld['depth']}, priority {ld['priority']})."
                    for ld in snap["leads"]
                    if ld["status"] == "pending"
                ][:10]
                or ["- Expand manual/agent web search queries for deeper corroboration of MODERATE/LOW findings."]
            ),
            "",
            "## 15. Complete Source References",
            "",
            *(
                [
                    f"{i}. [{s['title'] or s['url']}]({s['url']}) — Collector: `{s['collector']}`, Accessed: `{s['accessed_at']}`"
                    for i, s in enumerate(sources, start=1)
                ]
                if sources
                else ["_No references recorded._"]
            ),
            "",
        ]
    )

    report_md = "\n".join(lines)
    target_path = output_path or (store.session_dir / "intelligence_report.md")
    target_path.write_text(report_md, encoding="utf-8")
    return report_md
