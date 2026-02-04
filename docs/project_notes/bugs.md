# Bug Log

Track bugs encountered and their solutions for future reference.

## Entries

### BUG-01: Sub-agents exceed 4096 output token limit and fail silently [HIGH]

- **Date**: 2026-02-03
- **Status**: Open
- **Component**: `prompt.md` — all sub-agents, especially Plugin CVE batch agents and Report Compiler
- **Environment**: Bedrock API with `CLAUDE_CODE_MAX_OUTPUT_TOKENS=4096`, `MAX_THINKING_TOKENS=1024`
- **Symptoms**: Agents 15 (Plugin CVE Batch 7), 16 (Plugin CVE Batch 8), and the Final Report Compiler all failed with API errors. The model response exceeded 4096 tokens, truncating mid-JSON and preventing tool calls from executing. Agents that attempted Write tool calls with large report content never completed the write — all work was lost.
- **Root cause**: Each model turn (including thinking + tool call JSON) is capped at 4096 tokens total. With 1024 tokens reserved for thinking, only ~3072 tokens (~8,000-12,000 characters) remain for the visible response. A Write tool call encodes the entire file content in the response JSON, so any report exceeding ~8,000 characters causes truncation. The current prompt says "write findings to file, return a one-line summary" but this doesn't help because the Write call itself is what exceeds the limit — the agent never gets to the summary step.
- **Affected agents**: Plugin CVE batch agents (verbose CVE descriptions), Report Compiler (reads 18 agent files and writes a combined report). All agents are potentially affected.
- **Workaround used**: Plugin CVE agents were retried with stricter instructions to write terse output. Report Compiler was bypassed entirely — the orchestrator wrote the report manually using the Write tool directly (which has the same limit but the report was kept short enough).
- **Fixed**: PERF-01 added a global 7,500-char output budget rule, structured table formats, and `cat >>` chunked-write instructions for all sub-agents. PERF-02 restructured the Report Compiler to write in 5 sequential chunks instead of a single Write call. Both completed 2026-02-03.

### BUG-02: Agent 5 halluccinates WP version installation date [HIGH]

- **Date**: 2026-02-04
- **Status**: Fixed (2026-02-04)
- **Component**: `wp-malware-prescan.py` — `analyze_timestamps()`, `prompt.md` — Agent 5
- **Symptoms**: Report 2 claims "WordPress 6.9 installed" on May 27, 2025, but WP 6.9 was not released until December 2, 2025. Agent 5 also built a "zero-day exploitation" narrative claiming core files were tampered one day after release, when the Dec 3 modifications were likely a routine upgrade to WP 6.9.
- **Root cause**: Agent 5 is instructed to "compare core file modification dates against the WP version's known release date" (prompt.md line 112) but receives NO release date data in `timestamps.json`. The agent relies entirely on LLM training knowledge for the release date, which can be wrong or outdated. No validation exists to catch impossible claims (file timestamps predating the version's release). Additionally, `version.php` reflects the *current* version after upgrades — it does not tell you what version was originally installed.
- **Impact**: The hallucinated timeline cascades into the final report's Compromise Timeline and Likely Entry Points sections, producing a fabricated zero-day narrative that misleads remediation priorities.
- **Fix**: Instead of a prescan lookup table (SCAN-05 was superseded), the orchestrator now performs a WebSearch for the WP version release date at the end of Phase 1 and passes it to Agent 5. Agent 5's prompt (SCAN-06) was rewritten with guardrails: use only the provided date, never guess, understand version.php reflects upgrades not original installs, and flag near-release-date modifications as likely upgrade activity.
