# Bug Log

Track bugs encountered and their solutions for future reference.

## Entries

### BUG-01: Sub-agents exceed 4096 output token limit and fail silently [HIGH]

- **Date**: 2026-02-03
- **Status**: Fixed (2026-02-03)
- **Component**: `prompt.md` — all sub-agents, especially Plugin CVE batch agents and Report Compiler
- **Environment**: Bedrock API with `CLAUDE_CODE_MAX_OUTPUT_TOKENS=4096`, `MAX_THINKING_TOKENS=1024`
- **Symptoms**: Agents 15 (Plugin CVE Batch 7), 16 (Plugin CVE Batch 8), and the Final Report Compiler all failed with API errors. The model response exceeded 4096 tokens, truncating mid-JSON and preventing tool calls from executing. Agents that attempted Write tool calls with large report content never completed the write — all work was lost.
- **Root cause**: Each model turn (including thinking + tool call JSON) is capped at 4096 tokens total. With 1024 tokens reserved for thinking, only ~3072 tokens (~8,000-12,000 characters) remain for the visible response. A Write tool call encodes the entire file content in the response JSON, so any report exceeding ~8,000 characters causes truncation. The current prompt says "write findings to file, return a one-line summary" but this doesn't help because the Write call itself is what exceeds the limit — the agent never gets to the summary step.
- **Affected agents**: Plugin CVE batch agents (verbose CVE descriptions), Report Compiler (reads 18 agent files and writes a combined report). All agents are potentially affected.
- **Workaround used**: Plugin CVE agents were retried with stricter instructions to write terse output. Report Compiler was bypassed entirely — the orchestrator wrote the report manually using the Write tool directly (which has the same limit but the report was kept short enough).
- **Fixed**: PERF-01 added a global 7,500-char output budget rule, structured table formats, and `cat >>` chunked-write instructions for all sub-agents. PERF-02 restructured the Report Compiler to write in 5 sequential chunks instead of a single Write call. Both completed 2026-02-03.

### BUG-03: User email extraction uses wrong capture group index [MEDIUM]

- **Date**: 2026-02-04
- **Status**: Fixed (2026-02-04)
- **Component**: `prescan/scanners/database.py` — user extraction regex (lines 97-106)
- **Symptoms**: Extracted "email" field for users contained the nicename (e.g., `admin`) instead of the actual email address (e.g., `admin@example.com`). Because nicenames don't contain `@`, `redact_email()` returned them unchanged, making it appear as though the `@` symbol had been stripped.
- **Root cause**: Off-by-one error in capture group indexing. The regex captures 5 groups from WordPress `wp_users` INSERT statements matching column order `(ID, user_login, user_pass, user_nicename, user_email)`. The code used `um[3]` (user_nicename) for email and `um[2]` (user_pass) for nicename, instead of `um[4]` and `um[3]` respectively. This also leaked partial password hashes into the `nicename` field.
- **Fix**: Changed `email: redact_email(um[3])` → `redact_email(um[4])` and `nicename: um[2]` → `um[3]`. Added regression tests in `tests/test_database.py`.
- **Prevention**: Test coverage for user extraction with realistic INSERT data.

### BUG-02: Agent 5 halluccinates WP version installation date [HIGH]

- **Date**: 2026-02-04
- **Status**: Fixed (2026-02-04)
- **Component**: `wp-incident-prescan.py` — `analyze_timestamps()`, `prompt.md` — Agent 5
- **Symptoms**: Report 2 claims "WordPress 6.9 installed" on May 27, 2025, but WP 6.9 was not released until December 2, 2025. Agent 5 also built a "zero-day exploitation" narrative claiming core files were tampered one day after release, when the Dec 3 modifications were likely a routine upgrade to WP 6.9.
- **Root cause**: Agent 5 is instructed to "compare core file modification dates against the WP version's known release date" (prompt.md line 112) but receives NO release date data in `timestamps.json`. The agent relies entirely on LLM training knowledge for the release date, which can be wrong or outdated. No validation exists to catch impossible claims (file timestamps predating the version's release). Additionally, `version.php` reflects the *current* version after upgrades — it does not tell you what version was originally installed.
- **Impact**: The hallucinated timeline cascades into the final report's Compromise Timeline and Likely Entry Points sections, producing a fabricated zero-day narrative that misleads remediation priorities.
- **Fix**: Instead of a prescan lookup table (SCAN-05 was superseded), the orchestrator now performs a WebSearch for the WP version release date at the end of Phase 1 and passes it to Agent 5. Agent 5's prompt (SCAN-06) was rewritten with guardrails: use only the provided date, never guess, understand version.php reflects upgrades not original installs, and flag near-release-date modifications as likely upgrade activity.

### BUG-04: Plugin CVE agents hallucinate CVE IDs, misattribute to wrong products [CRITICAL]

- **Date**: 2026-02-04
- **Status**: Fixed (2026-02-04)
- **Component**: Phase 3 Plugin CVE batch agents (`prompts/phase-3-vulns.md`)
- **Symptoms**: Reports contain CVE IDs that are either fabricated or belong to completely unrelated software. In Report 3, only 3 of 16 CVEs (19%) were correctly attributed. In Report 4, 0 of 15 CVEs were fully correct (1 partially correct). Examples of misattribution: CVE-2024-26641 (Linux kernel IPv6 tunneling bug) attributed to Slider Revolution; CVE-2023-6932 (Linux kernel IGMP use-after-free) attributed to WP Mail SMTP; CVE-2022-0772 (Libsndfile buffer overflow) attributed to User Role Editor. Report 4 additionally fabricated 6 "WordPress Core" CVEs (CVE-2024-27956 through 27962) that are actually Patchstack-assigned plugin CVEs for unrelated plugins.
- **Root cause**: CVE batch agents rely entirely on LLM training knowledge to look up CVEs for each plugin. The model "knows" a plugin has had vulnerabilities but fabricates plausible-looking CVE IDs or grabs real CVE IDs from unrelated products. No external verification against NVD, WPScan, or Patchstack APIs occurs. CVSS scores are also fabricated, with hallucinated CVEs almost always assigned 8.0-9.9 to maximize apparent severity.
- **Impact**: Fabricated CVEs cascade into the Vulnerability Assessment, Likely Entry Points, and Compromise Timeline sections. Attack chain hypotheses are built on nonexistent vulnerabilities (e.g., Report 3's primary attack vector relies on CVE-2023-47784 for Slider Revolution, which does not exist for that plugin). This undermines the credibility of the entire report and can mislead remediation priorities.
- **Hallucination patterns observed**:
  - Real CVE IDs mapped to wrong products (most common — ~50% of errors)
  - Completely fabricated CVE IDs that don't exist in NVD (~30% of errors)
  - Correct CVE ID and plugin but wrong vulnerability type or CVSS score (~20% of errors)
  - Suspiciously high CVE sequence numbers (e.g., CVE-2025-60080, CVE-2025-60174)
  - Sequential CVE blocks attributed to one product (e.g., CVE-2024-27956-27962 all claimed as WP Core)
- **Correctly identified CVEs across both reports**: CVE-2023-6933 (Better Search Replace), CVE-2023-48777 (Elementor), CVE-2020-25213 (wp-file-manager) — all well-known, widely-reported vulnerabilities
- **Fix needed**: CVE agents must be grounded against live external data rather than LLM memory. Options: (1) WebSearch or WebFetch against NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX`), WPScan API, or Patchstack API during Phase 3 to verify each CVE before including it. (2) Alternatively, use WebSearch to find real CVEs for each plugin+version combination rather than asking the model to recall them. (3) Add a post-processing validation step that cross-checks all CVE IDs against NVD before the report is finalized.
- **Fix**: Added prescan CVE lookup module (`prescan/scanners/cve_lookup.py`) that fetches and caches the Wordfence vulnerability database locally (24h TTL). The prescan now outputs `prescan-data/plugin-cves.json` with real CVE data for all detected plugins, themes, and WP core. Phase 3 agents read CVE data from this file instead of relying on LLM knowledge. Prompts explicitly state "Do NOT fabricate or guess CVE IDs — use only the data provided from the prescan" and prohibit WebSearch for CVE lookups.
- **Related**: BUG-02 (same class — LLM training knowledge used where external data is needed)

### BUG-06: Heredoc chunked writes can't be auto-approved by allowed-tools glob patterns [HIGH]

- **Date**: 2026-02-05
- **Status**: Fixed (2026-02-05)
- **Component**: `SKILL.md` (allowed-tools), `prompts/preamble.md`, `prompts/phase-2-analysis.md`, `prompts/phase-3-vulns.md`, `prompts/phase-4-report.md`
- **Symptoms**: Every heredoc write command prompts the user for approval during a scan, even with glob patterns in `allowed-tools`. A full scan triggers dozens of approval prompts.
- **Root cause**: The `allowed-tools` `Bash(pattern)` glob uses `*` which does not match newline characters. Heredoc commands are multi-line (the content is part of the command string), so no glob pattern can match them. Additionally, agents emit the file path directly as the command prefix (not `cat >>` as the prompts instruct).
- **Impact**: Scan requires constant manual approval, defeating the purpose of skill-level tool permissions.
- **Attempted fixes**: `Bash(*incident-scan-report.md* <<*)`, `Bash(*-scan-output/scan-results/* <<*)` — neither matches because `*` stops at `\n`.
- **Fix**: Replaced heredoc chunking with Write-to-individual-chunk-files + single-line concatenation. Each chunk is written via the Write tool (already permitted) to numbered `.chunk-NN.md` files, then assembled with a single-line `cat` command that matches the `allowed-tools` glob pattern. Removed heredoc Bash patterns from `allowed-tools`, added two new single-line cat concat patterns. Updated all prompt files (preamble, phase-2, phase-3, phase-4) to use the new chunking approach.

### BUG-05: Email redaction removes actionable information from incident reports [MEDIUM]

- **Date**: 2026-02-04
- **Status**: Fixed (2026-02-04)
- **Component**: `prescan/utils.py` — `redact_email()`, `prescan/scanners/database.py`
- **Symptoms**: Suspicious admin account table in reports shows `@gmail.com` or `@soclogix.com` instead of full email addresses, making it impossible for the site owner to identify or act on specific accounts. When the email's local part is empty after redaction, the entry is indistinguishable from other accounts at the same domain.
- **Root cause**: `redact_email()` was added as part of SEC-04 to prevent sensitive data exposure. However, in an incident response context, the report recipient is the site owner/admin who already has access to this data. Redacting emails works against the report's purpose — identifying exactly which accounts to audit, remove, or contact.
- **Impact**: Degraded report actionability. The "Audit Admin Accounts" recommendation is harder to follow when accounts can't be uniquely identified.
- **Fix**: Removed `redact_email()` function from `prescan/utils.py`, removed its import and call site in `prescan/scanners/database.py`, updated tests in `tests/test_database.py` and `tests/test_utils.py`, and updated the `sensitive_data_notice` in `prescan/scanner.py`. Emails are now passed through unmodified.
