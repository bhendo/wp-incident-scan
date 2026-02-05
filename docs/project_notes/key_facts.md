# Key Facts

Project configuration and important reference information for the wp-incident-scan skill.

## Skill Configuration

- **Skill name**: `wp-incident-scan`
- **Entry point**: `SKILL.md`
- **Pre-scanner**: `wp-incident-prescan.py` → `prescan/` package (Python 3, no external dependencies). Entry point shim preserved.
- **Orchestration**: `prompts/` directory (4-phase modular workflow: preamble + phase-1 through phase-4 + error-handling)
- **Model invocation**: Disabled (`disable-model-invocation: true` in SKILL.md)

## Allowed Tools

- `Bash(python3 ~/.claude/skills/wp-incident-scan/wp-incident-prescan.py *)` (prescan script only)
- `Bash(mkdir -p *-scan-output/scan-results)` (output directory only)
- `Bash(cat >> *-scan-output/scan-results/*)` (chunked appends to output only)
- `Read`, `Write`, `Edit`, `Glob`, `Grep`
- `Task` (sub-agents use `subagent_type: "general-purpose"`)
- `WebSearch` (Phase 1: WP version release date lookup)
- `WebFetch` (Phase 3: restricted to `wordpress.org` only for plugin/theme metadata)

## Environment Constraints

- **Bedrock max_output**: 4096 tokens per model response
- **Output budget**: 7,500 chars max per Write tool call (safety margin below ~8K encoding limit). If larger, split across `cat >>` appends with `<<'SCANEOF'` delimiter, each chunk under 7,500 chars.
- Sub-agents must write full findings to files and return only one-line summaries
- Sub-agents use structured tables (not prose) to stay within budget

## Token Limit Mechanics

- The **4096 output token limit** constrains each model response (orchestrator and sub-agents alike)
- The orchestrator reads per-phase files from `prompts/` via the Read tool — this is **input context**, not system prompt
- When launching sub-agents, the orchestrator **composes its own prompts** for Task tool calls — it paraphrases the instructions from the phase files, it does not copy-paste them verbatim
- The modular `prompts/` structure means the orchestrator only loads the current phase's instructions, reducing input tokens by 60-90% per turn
- The output limit is mitigated by the 7,500-char Write budget and chunked-write pattern (see BUG-01/PERF-01)
- The pre-scanner runs as a Python process, not an LLM call — it has no token constraints

## Agent Dependencies

- Agents 1-9 are **fully independent** — no agent depends on another's output
- Phase 2 launches all 9 agents (filesystem, logs, DB) in parallel
- Phase 3 (CVE checks, agents 10-11+) **depends on Phase 2** — it uses a compromise evidence summary compiled from agents 1-9. CVE data comes from prescan `plugin-cves.json` (Wordfence cache), not WebSearch.
- Phase 4 (report) **depends on all prior phases**

## Pre-Scanner Output Structure

Output is written to a sibling directory: `{backup_name}-scan-output/` (SEC-03, ADR-005). Override with `--output-dir`. The prescan includes `_meta.output_dir` in the JSON index for orchestrator consumption. Prompts use `{output_root}` (write) separate from `{backup_root}` (read).

- `wp-prescan-results.json` - Lightweight index (in output root)
- `prescan-data/discovery.json` - WP version, plugins, themes, SQL dumps
- `prescan-data/php-pattern-matches.json` - PHP pattern scan results
- `prescan-data/suspicious-files.json` - Suspicious file locations
- `prescan-data/core-files.json` - Core file contents (truncated at 10KB)
- `prescan-data/theme-functions.json` - Theme functions.php contents
- `prescan-data/timestamps.json` - File modification timestamps
- `prescan-data/error-logs.json` - PHP error log security analysis
- `prescan-data/security-logs.json` - Security plugin log analysis
- `prescan-data/database.json` - SQL dump analysis
- `prescan-data/plugin-cves.json` - CVE data from Wordfence database cache (24h TTL)

## Agent Assignments

- Agent 1: PHP Pattern & Backdoor Analysis
- Agent 2: Suspicious Files & Locations
- Agent 3: Core File Integrity
- Agent 4: Theme & WP-Content Analysis
- Agent 5: Timestamp & Timeline Analysis
- Agent 6: Error Log Analysis
- Agent 7: Security Plugin Log Analysis
- Agent 8: Database Content Analysis
- Agent 9: Database Structural Audit
- Agent 10: WordPress Core CVE Check
- Agents 11+: Plugin CVE Checks (batched 3-4 per agent)
- Final agent: Report compilation
