# 15-Section Intelligence Report Standard

Every completed investigation MUST contain all 15 sections (generated automatically by `osint-engine report <session_id>` and enriched by the analyst):

1. **Executive Summary** — Concise synthesis of key conclusions and overall confidence.
2. **Subject Identification** — Raw input, normalized identifier, primary/secondary classification, disambiguation notes.
3. **Background** — Context, history, and overview from authoritative public sources.
4. **Key Findings** — Prioritized, cited findings with `[CONFIDENCE | FACT/ASSUMPTION]` tags.
5. **Source Inventory** — Structured table of every queried source (collector, type, title, published date, UTC accessed date, URL).
6. **Discovered Connections** — Connected organizations, people, domains, repos, and projects.
7. **Entity Relationship Map** — Mermaid `flowchart LR` diagram of discovered entities and relationships.
8. **Timeline of Events** — Chronological milestones with dates and citations.
9. **Technical Findings** — DNS, RDAP, CT logs, infrastructure, repositories, advisories (when applicable).
10. **Conflicting Information** — Explicit documentation of contradictions across sources.
11. **Unverified Claims** — Claims encountered that lack independent corroboration.
12. **Confidence Assessment** — Breakdown of findings by `VERY HIGH`, `HIGH`, `MODERATE`, `LOW`, `UNVERIFIED`.
13. **Research Gaps** — What could not be verified or accessed (e.g., auth-walled platforms, rate-limited APIs).
14. **Recommended Next Investigations** — Concrete, lawful follow-up leads.
15. **Complete Source References** — Numbered bibliography of all cited URLs with access timestamps.
