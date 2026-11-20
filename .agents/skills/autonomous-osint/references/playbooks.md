# OSINT Pivot & Search Playbooks

Use these playbooks alongside `osint-engine` and `search_web` to systematically pivot across public sources.

## 1. Company / Organization
- **Collectors:** `wiki`, `edgar`, `opencorporates`, `github`, `hn`, `reddit`, `web_fetch`
- **Search Queries:**
  - `"<name>" official website`
  - `"<name>" founders OR CEO OR leadership`
  - `"<name>" acquisitions OR partnerships OR funding`
  - `"<name>" security advisory OR CVE OR controversy`
- **Pivots:** Official domain → `rdap`, `dns`, `crtsh`, `wayback`; GitHub org → top repos & maintainers; SEC CIK → filings.

## 2. Domain / Website / IP
- **Collectors:** `rdap`, `dns`, `crtsh`, `wayback`, `web_fetch`, `github`
- **Search Queries:**
  - `site:<domain>`
  - `site:<domain> filetype:pdf OR inurl:security OR inurl:about`
  - `"<domain>" -site:<domain>` (external mentions & backlinks)
- **Pivots:** Nameservers / A records → hosting provider; subdomains in `crt.sh` → public docs/status/API portals; Wayback → historical ownership or branding changes.

## 3. Person (Public Figure / Researcher / Executive)
- **Guardrail:** Restrict strictly to non-sensitive, publicly documented professional/public information. Never compile home addresses, private phone numbers, or sensitive personal traits.
- **Collectors:** `wiki`, `github`, `arxiv`, `crossref`, `hn`, `reddit`
- **Search Queries:**
  - `"<name>" biography OR profile OR talks OR interviews`
  - `"<name>" publications OR patents OR github`
- **Pivots:** Affiliated organizations, public code repositories, academic papers, conference talks.

## 4. Username / Handle
- **Collectors:** `github`, `hn`, `reddit`, `username_cli` (optional Maigret/Sherlock if installed)
- **Verification Rule:** Matching handles across platforms are **LOW** confidence until corroborated by shared bio, links, PGP/avatar, or cross-references.

## 5. Software Project / GitHub Repo / Technology
- **Collectors:** `github`, `gitlab`, `hn`, `reddit`, `arxiv`, `wiki`
- **Search Queries:**
  - `"<project>" CVE OR security advisory OR release`
  - `"<project>" maintainers OR governance OR sponsors`
