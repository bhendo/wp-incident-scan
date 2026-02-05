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

### ADR-004: Wordfence Database for Prescan CVE Lookups (2026-02-04)

**Context:**
- BUG-04: Plugin CVE agents hallucinated CVE IDs at alarming rates (81-100% incorrect) when relying on LLM training knowledge
- CVE agents fabricated plausible-looking IDs, misattributed real CVEs from unrelated software, and invented CVSS scores
- The hallucinated data cascaded into the final report's attack chain analysis, undermining report credibility
- Need a grounded, verifiable CVE data source that doesn't depend on LLM memory

**Decision:**
- Added `prescan/scanners/cve_lookup.py` that fetches and locally caches the Wordfence vulnerability database (full production feed)
- Cache stored at `cache/wordfence-vulns.json` with 24h TTL — refreshed automatically when stale
- Pre-scanner matches detected plugins/themes/core version against the database and outputs `prescan-data/plugin-cves.json`
- Phase 3 agents read CVE data from this file only — WebSearch is prohibited for CVE lookups
- Agents are explicitly instructed: "Do NOT fabricate or guess CVE IDs — use only the data provided from the prescan"

**Alternatives Considered:**
- Runtime WebSearch per plugin -> Rejected: unreliable results, slow (one search per plugin), still requires LLM to parse search results correctly, expands attack surface per TOOL-03
- WPScan API -> Rejected: requires API key for full access, rate-limited free tier
- NVD API -> Rejected: WordPress-specific CVE coverage is inconsistent, slow API, requires keyword mapping from plugin slugs to CPE names
- Patchstack API -> Rejected: requires API key
- Wordfence was chosen because: free unauthenticated API, comprehensive WordPress-specific coverage, single bulk download (no per-plugin queries), includes CVSS scores and affected version ranges

**Consequences:**
- CVE data is verifiable and grounded — eliminates the hallucination vector entirely
- Pre-scanner gains its first network dependency (Wordfence API), but degrades gracefully (reports "unavailable" if fetch fails, agents skip CVE reporting)
- 24h cache means the database is fetched at most once per day, not per scan
- Cache file can be large (~30MB) but is stored outside the backup directory

### ADR-005: Output Directory Isolation (2026-02-05)

**Context:**
- ADR-002 acknowledged that writing output into the backup directory was a known risk
- SEC-03: forensic evidence contamination and live-site exposure

**Decision:**
- Write all output to a sibling directory: `{backup_name}-scan-output/`
- Add `--output-dir` flag to prescan for override
- Prescan includes `output_dir` in JSON index for orchestrator
- Prompts use `{output_root}` (write) separate from `{backup_root}` (read)

**Supersedes:** ADR-002

**Consequences:**
- Backup directory is never modified by the scanner
- Forensic evidence timestamps preserved
- No web-accessible files if pointed at a live site
- Parent directory of backup must be writable (clear error if not)
