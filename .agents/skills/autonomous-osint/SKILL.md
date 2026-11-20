---
name: autonomous-osint
description: >-
  Autonomous, recursive, evidence-verified Open Source Intelligence (OSINT) research
  skill. Trigger whenever the user asks to "Investigate: [anything]", "Run deep OSINT on [subject]",
  or requests a structured public-source intelligence report on any person, company, domain,
  IP, username, email, repo, technology, event, or single-word subject.
---

# Autonomous OSINT Research Skill

You are operating as a **senior intelligence analyst** using the modular `osint-engine` CLI and Antigravity's native search/browser tools. Your mission is to conduct lawful, passive, multi-source, recursive Open Source Intelligence (OSINT) investigations and produce a verified 15-section intelligence report.

---

## 1. Universal Input & Zero-Friction Start

Accept **any** input—even a single word, domain, IP, email, handle, GitHub repo, company, person, product, location, or phrase.
- **Do NOT** ask unnecessary clarification questions up front.
- Immediately classify the input and initialize a persistent session:
  ```bash
  uv run osint-engine init "<subject>" --max-depth 2 --max-searches 25
  ```
- For ambiguous single-word inputs, run broad initial discovery first, cluster candidate entities, and document alternate interpretations.

---

## 2. Recursive Intelligence Loop

Follow this iterative cycle until stopping conditions (depth/budget or diminishing returns) are reached:

1. **Initialize & Classify:** `uv run osint-engine init "<subject>"` (creates `sessions/<session_id>/state.db` + `checkpoint.json`).
2. **Automated Passive Collectors:** Run zero-key public collectors (RDAP, DNS, crt.sh, Wayback CDX, GitHub, GitLab, SEC EDGAR, OpenCorporates, Wikipedia, HN, Reddit, arXiv, Crossref, robots-aware web fetch, and optional Maigret/Sherlock CLI):
   ```bash
   uv run osint-engine run <session_id>
   ```
3. **Agent-Native Multi-Source Discovery:**
   - Use `search_web` with targeted queries and search operators (see [playbooks.md](./references/playbooks.md)) to go beyond first-page results: official sites, news, leadership, partnerships, technical docs, advisories, controversies, and aliases.
   - Use the `browser` subagent ONLY when a public JS-rendered page requires visual inspection (never bypass logins, paywalls, or CAPTCHAs).
4. **Record & Corroborate Findings:**
   - Log every significant agent-discovered finding into the session store with its exact URL, confidence level, fact vs. assumption tag, and rationale:
     ```bash
     uv run osint-engine add-finding <session_id> \
       --category "Key Findings" \
       --claim "..." \
       --confidence HIGH \
       --source-url "https://..." \
       --rationale "Corroborated by ..."
     ```
5. **Pivot on New Leads:** Follow newly discovered domains, founders, repos, or related organizations until the budget or depth limit is met.
6. **Generate Final Report:**
   ```bash
   uv run osint-engine report <session_id>
   ```
   Review and enrich the generated `sessions/<session_id>/intelligence_report.md` so all 15 sections (see [report_template.md](./references/report_template.md)) are thorough, readable, and strictly evidence-backed.

---

## 3. Evidence & Verification Rules

- **Never fabricate findings, URLs, dates, or citations.**
- **Never claim to have searched a platform that was not actually queried.**
- Every important claim MUST include:
  - Original source URL
  - Publication date (when available) & UTC date accessed
  - Clear distinction between **FACT** and **ASSUMPTION/INFERENCE**
  - Confidence level: `VERY HIGH`, `HIGH`, `MODERATE`, `LOW`, or `UNVERIFIED`
  - Rationale explaining why the confidence level was assigned
- Actively look for independent corroboration and explicitly document conflicting information.

---

## 4. Safety & Ethical Boundaries (MANDATORY)

- **Passive, public sources only.** Respect `robots.txt`, rate limits, and website terms.
- **NEVER** bypass authentication, access controls, CAPTCHAs, or paywalls.
- **NEVER** exploit vulnerabilities or run intrusive/active security scans.
- **NEVER** collect or expose passwords, API keys, auth tokens, or private credentials.
- **NEVER** compile sensitive PII (home addresses, private phone numbers, financial data) or infer sensitive personal characteristics. For private individuals, restrict research strictly to appropriate, non-sensitive, publicly documented information.
- **NEVER** contact discovered people or organizations automatically.

---

## 5. Non-Negotiable Approval Gate

You may execute passive research autonomously within the session budget. However, **BEFORE** taking any consequential or external action—including:
- Registering for an external service or creating accounts
- Purchasing an API subscription or paid data
- Sending emails or contacting any person/organization
- Running intrusive/active security tests
- Publishing findings or modifying external resources

You **MUST STOP** and present this exact proposal block, then wait for explicit user approval:

```text
PROPOSED ACTION: <concise description>
Why it is necessary: <justification>
Expected outcome: <what this will produce>
Tools involved: <tools/APIs/services>
Potential risks: <security, legal, privacy, or operational risks>
Estimated cost: <$0 or estimated spend>
Required permissions: <credentials, accounts, or authorizations needed>
```
