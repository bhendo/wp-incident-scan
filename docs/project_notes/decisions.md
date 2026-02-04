# Architectural Decisions

Record of architectural and design decisions for the wp-incident-scan skill.

## Entries

### ADR-001: Multi-Phase Agent Architecture with Pre-Scanner (2025-01-01)

**Context:**
- Need to scan WordPress backups for malware, backdoors, and vulnerabilities
- Bedrock imposes a 4096 max_output token limit per model response
- Scanning involves both mechanical pattern matching and judgment-based analysis

**Decision:**
- Separate mechanical data collection (Python pre-scanner) from AI judgment (sub-agents)
- Pre-scanner outputs structured JSON; sub-agents read JSON and write findings to files
- Sub-agents return only one-line summaries to stay within token limits

**Alternatives Considered:**
- Single monolithic agent -> Rejected: exceeds token limits, no parallelism
- Pure Python scanner without AI -> Rejected: can't do judgment-based false positive filtering

**Consequences:**
- Enables parallel analysis across 10+ specialized agents
- Pre-scanner handles the expensive filesystem traversal once
- Each agent focuses on a narrow domain (PHP backdoors, timestamps, DB content, etc.)
- Complexity of orchestration across multiple phases

### ADR-002: Write Output into Backup Directory (2025-01-01)

**Context:**
- Need somewhere to store prescan JSON, agent findings, and final report
- Want results colocated with the backup for easy reference

**Decision:**
- Write `prescan-data/`, `scan-results/`, and report files directly into the backup root

**Consequences:**
- Simple path management (everything relative to backup root)
- Risk: contaminates forensic evidence (modifies backup timestamps/contents)
- Risk: if pointed at a live WordPress site, writes web-accessible files
- Should consider an alternative output location in the future

### ADR-003: Orchestrator WebSearch for WP Release Dates (2026-02-04)

**Context:**
- Agent 5 needs the WP version's release date to build accurate timelines
- Without it, the agent guesses from training data — which led to BUG-02 (hallucinated date, false zero-day narrative)
- Two options: hardcoded lookup table in the prescan script, or orchestrator WebSearch at runtime

**Decision:**
- Orchestrator performs a WebSearch for the release date at the end of Phase 1, passes it to Agent 5
- Pre-scanner stays offline/deterministic — no network calls, no lookup table to maintain

**Alternatives Considered:**
- Hardcoded `WP_RELEASE_DATES` dict in prescan script -> Rejected: requires manual updates for every new WP release, stale data risk
- Let Agent 5 do the WebSearch itself -> Rejected: adds WebSearch to Agent 5's tool set (unnecessary attack surface), and the orchestrator already knows the version

**Consequences:**
- Release date is always current (WebSearch hits wordpress.org)
- Pre-scanner remains a pure offline tool
- If WebSearch fails, Agent 5 gets "unknown" and skips version-date comparisons (safe fallback)
