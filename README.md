# Autonomous OSINT Research Engine & Antigravity Skill

A modular, persistent, zero-API-key-first Open Source Intelligence (OSINT) research engine packaged as a reusable Antigravity skill (`.agents/skills/autonomous-osint/SKILL.md`).

## Quick Start

```bash
uv sync
uv run pytest
```

### Triggering via Antigravity
Simply ask:
- `"Investigate: example.com"`
- `"Run deep OSINT on Anthropic"`

### CLI Usage

```bash
# 1. Classify input & initialize persistent session
uv run osint-engine init "example.com" --max-depth 2 --max-searches 25

# 2. Run passive public collectors within budget
uv run osint-engine run <session_id>

# 3. Record additional agent-discovered findings
uv run osint-engine add-finding <session_id> \
  --category "Key Findings" \
  --claim "..." \
  --confidence HIGH \
  --source-url "https://..."

# 4. Generate the 15-section intelligence report
uv run osint-engine report <session_id>
```

## Optional CLI Tools
The `username_cli` collector automatically detects `maigret` or `sherlock` if installed on your `PATH` (e.g., `uv tool install maigret`) and degrades gracefully if not installed.
