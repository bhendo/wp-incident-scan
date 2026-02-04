# Issues / Work Log

Track work completed on this skill.

## Entries

### 2026-02-03 - Security Review

- **Status**: Completed
- **Description**: Comprehensive security review of all skill files (SKILL.md, prompts/, prescan/)
- **Findings**: 2 High, 4 Medium, 3 Low severity issues identified
- **Notes**: Individual issues logged below.

---

## Remaining Pending Issues

1. **SEC-01** — Prompt injection via scanned content (most complex)
2. **SEC-03** — Backup directory contamination (write output outside backup)
3. **SEC-09** — Command substitution risk in $ARGUMENTS (verification task)

---

### SEC-01: Prompt Injection via Scanned Content [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prompt.md` / all sub-agents
- **Description**: Malicious WordPress backups contain attacker-controlled content that gets fed directly into AI sub-agents as context. The pre-scanner includes file content in JSON output (up to 200 chars per pattern match, up to 10KB for core files and theme functions.php). Agents 2, 3, and 4 are also instructed to use the Read tool to open full adversarial files from disk when content is truncated. A crafted PHP file could contain prompt injection instructions that cause agents to suppress findings, report false results, or misuse tools like WebFetch.
- **Mitigation**: Add explicit adversarial-content warnings to all sub-agent prompts. Consider reducing raw content passed to agents. Restrict tool access per agent (e.g., content-analysis agents don't need WebFetch).

### SEC-02: Symlink Traversal Reads Files Outside Backup [HIGH]

- **Status**: Completed (2026-02-03)
- **Severity**: High
- **Component**: `wp-malware-prescan.py` — `scan_php_patterns()`, `read_core_files()`, `read_theme_functions()`
- **Description**: `scan_php_patterns()` resolves symlinks for loop detection but does not verify the resolved path stays within the backup directory. A crafted backup with symlinks pointing to `/etc/shadow`, `~/.ssh/id_rsa`, or `.env` files would cause the pre-scanner to read those files and include their content in JSON output. `scan_suspicious_files()` reports symlinks outside root but other scan functions still follow and read them.
- **Fix**: After resolving a symlink, check that the resolved path starts with the WordPress root before reading. Apply this check in `scan_php_patterns()`, `read_core_files()`, and `read_theme_functions()`.

### SEC-03: Backup Directory Contamination [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py`, `prompt.md`
- **Description**: The scanner writes output directly into the scanned backup directory (`prescan-data/`, `scan-results/`, `wp-prescan-results.json`, `malware-scan-report.md`). This modifies timestamps and directory structure of forensic evidence. If the user accidentally points the tool at a live WordPress installation, these files would be web-accessible.
- **Fix**: Write output to a separate directory outside the backup (e.g., `/tmp/wp-scan-{hash}/` or a user-specified output path).

### SEC-04: Sensitive Data Exposure in Output Files [MEDIUM]

- **Status**: Completed (2026-02-03)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `read_core_files()`, `scan_sql_dump()`
- **Description**: `read_core_files()` explicitly reads `wp-config.php`, which typically contains database credentials, auth keys, and salts. This content is written to `prescan-data/core-files.json` in plaintext. `database.json` may also contain user password hashes and email addresses. These output files persist on disk after the scan with no cleanup mechanism.
- **Fix**: Added `redact_wp_config()` to replace values of `DB_PASSWORD`, auth keys, and salts with `[REDACTED]` while preserving file structure for malware detection. Added `redact_email()` to partially redact user emails (keeps first char + domain for suspicious domain analysis). Added `sensitive_data_notice` to output metadata warning that files should be treated as confidential. `DB_NAME`, `DB_HOST`, `DB_USER` kept visible for structural analysis.

### SEC-05: No Resource Limits (File Count/Size) [MEDIUM]

- **Status**: Completed (2026-02-03)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py`
- **Description**: No limits on total files scanned (a crafted backup with millions of tiny PHP files would run indefinitely, and `rglob()` is called 4+ times). No limit on individual file size (`php_file.read_text()` reads entire files into memory — a single 2GB PHP file would exhaust memory). SQL line-by-line reading is memory-efficient but a single very long line could still be problematic.
- **Fix**: Added `MAX_FILE_READ_SIZE` (10MB) — files exceeding this are skipped before `read_text()`. Added `MAX_FILE_COUNT` (500K) — scanning stops after this many files in `scan_php_patterns()`, `scan_suspicious_files()`, and `analyze_timestamps()`. Skipped/limit counts are reported in output and stderr.

### SEC-06: Gzip Bomb Vulnerability [MEDIUM]

- **Status**: Completed (2026-02-03)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`
- **Description**: `scan_sql_dump()` opens `.sql.gz` files with `gzip.open()`. A gzip bomb (small compressed file that decompresses to enormous size) would cause the line-by-line reader to run indefinitely. While it won't exhaust memory all at once due to line-by-line reading, it would cause an extremely long-running process.
- **Fix**: Added `MAX_GZIP_DECOMPRESSED_BYTES` (5GB). `scan_sql_dump()` tracks cumulative bytes read from gzipped files and aborts with an error message when the limit is exceeded.

### SEC-07: WebSearch Query Manipulation via Plugin Names [LOW]

- **Status**: Completed (2026-02-03)
- **Severity**: Low
- **Component**: `wp-malware-prescan.py`, `prompt.md` — Agents 8, 9+
- **Description**: Agents 9+ construct WebSearch queries using plugin slugs and version numbers extracted from the backup. A malicious backup could include a plugin with a crafted slug/name designed to produce misleading search results or lead to attacker-controlled content when searched.
- **Fix**: Added `sanitize_slug()`, `sanitize_version()`, and `sanitize_name()` to the pre-scanner. Slugs are restricted to alphanumeric/hyphen/underscore characters and length-limited (100 chars). Versions are validated against a numeric pattern (30 chars max). Names have control characters stripped (200 chars max). Updated `prompt.md` to instruct agents to use only sanitized slugs (never display names) in queries, and to skip plugins with suspicious-looking slugs.

### SEC-08: Potential ReDoS in Regex Patterns [LOW]

- **Status**: Completed (2026-02-03)
- **Severity**: Low
- **Component**: `wp-malware-prescan.py` — `PHP_SUSPICIOUS_PATTERNS`
- **Description**: The pattern `preg_replace_callback\s*\(\s*.*\$` uses `.*` followed by a literal `\$`, which could cause quadratic backtracking on long lines without a `$` character. Impact is limited since lines are processed individually and content is truncated at 200 chars, but crafted input could slow the scanner.
- **Fix**: Replace `.*` with a non-greedy `.*?` or a more specific character class.

### DB-01: Safe-list Filtering Is Per-Line, Not Per-Value [HIGH]

- **Status**: Completed (2026-02-03)
- **Severity**: High
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`, line ~695
- **Description**: The script tag safe-list check (`elementor|rank.?math|...`) runs against the entire SQL line. In mysqldump's extended INSERT format, a single `INSERT INTO wp_options VALUES (...)` line contains thousands of rows. If any option value on the line mentions a safe-listed plugin name (nearly guaranteed on real sites), ALL script tag matches on that line are silently skipped — including genuinely malicious injections like the `4r4r.js` payload found in the original manual scan.
- **Fix**: Instead of checking the entire line against the safe-list, extract a narrow window around each regex match position (e.g., 500 chars) and apply the safe-list only to that window. This ensures legitimate plugin references elsewhere on the same INSERT line don't suppress unrelated malicious matches.

### DB-02: Context Captured From Line Start Instead of Match Position [MEDIUM]

- **Status**: Completed (2026-02-03)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`, line ~704
- **Description**: Match context is `line.strip()[:300]`, which captures the first 300 characters of the SQL line. In extended INSERT format, the malicious content may be tens of thousands of characters into the line. The agent receives a match flagged as "script tag in wp_options" but the context just shows `INSERT INTO wp_options VALUES (1,'siteurl','https://...` — no indication of what the actual payload was or which option it belongs to. This caused the `ihaf_insert_header` injection to be effectively invisible to the analysis agent even if the pattern matched.
- **Fix**: Use `re.search()` match position to capture context centered on the match: `line[max(0, match.start()-150):match.end()+150]`. This ensures the agent sees the actual malicious content and surrounding option name.

### DB-03: Missing High-Risk Injection Options From Extraction List [MEDIUM]

- **Status**: Completed (2026-02-03)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`, `target_options` set (line ~652)
- **Description**: The `target_options` set extracts 11 specific options but misses options commonly abused for script injection. The `ihaf_insert_header`/`ihaf_insert_footer` options (WPCode / Insert Headers and Footers plugin) are prime injection targets because they output directly into every page's `<head>` or footer. Other commonly abused options include custom CSS/JS options and tracking code options from various plugins.
- **Fix**: Add a regex-based extraction pass that captures any option whose name matches injection-prone patterns: `insert_header`, `insert_footer`, `tracking_code`, `custom_css`, `custom_js`, `head_script`, `body_script`, `header_code`, `footer_code`, etc. Extract and include these values in the database JSON so Agent 6 can review them.

### DB-04: No Detection of Whitespace-Obfuscated Payloads [LOW]

- **Status**: Completed (2026-02-04)
- **Severity**: Low
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`
- **Description**: The `4r4r.js` injection was hidden behind ~60 empty `\r\n` lines to push it below the visible area in the WPCode admin textarea. While the `<script>` pattern should catch the tag itself (if DB-01 doesn't suppress it), there's no specific detection for this obfuscation technique. Flagging "active content preceded by excessive whitespace" would catch this class of attack and provide useful context to the analysis agent about the attacker's intent to hide the payload.
- **Fix**: Add a DB_SUSPICIOUS_PATTERNS entry or post-processing check that flags option values containing active content (`<script>`, `<iframe>`, `<?php`, `eval`) preceded by more than 10 consecutive `\r\n` or `\n` sequences. Report the whitespace padding as an additional indicator of malicious intent.

### SCAN-01: No PHP Error Log / Debug Log Scanning [HIGH]

- **Status**: Completed (2026-02-04)
- **Severity**: High
- **Component**: `wp-malware-prescan.py`, `prompt.md`
- **Description**: PHP error logs (`error_log`, `debug.log`, `php-errors.log`) are one of the richest sources of compromise evidence. In the reference scan, error logs revealed: (1) IOC-3 — a `wp_set_password()` injection into wp-config.php line 77, discovered only via a PHP fatal error entry; (2) exact timestamps of 6 auto-login backdoor uses over Dec 23-24; (3) export failure patterns on Dec 22 that established the timeline start. The skill has zero awareness of error logs — neither the pre-scanner nor any agent prompt mentions them. WordPress sites commonly have `debug.log` in `wp-content/`, PHP error logs in the web root or a logs directory, and hosting-specific log paths.
- **Fix**: Add a discovery step to locate common log files (`wp-content/debug.log`, `error_log`, `php-errors.log`, `*.log` in root). Add a pre-scanner section that extracts PHP fatal errors, warnings referencing WP files, authentication-related entries, and file operation entries. Create a new agent (or extend Agent 5 / timestamps) to analyze log entries for compromise evidence and build a timeline.

### SCAN-02: No Wordfence / Security Plugin Log Analysis [HIGH]

- **Status**: Completed (2026-02-04)
- **Severity**: High
- **Component**: `wp-malware-prescan.py`, `prompt.md`
- **Description**: Security plugins like Wordfence write access logs, firewall logs, and attack data to `wp-content/wflogs/`. In the reference scan, Wordfence logs confirmed the `4r4r.js` injection was actively executing (a 404 hit for `/4r4r.js` from IP `159.26.106.157`). Other security plugins (Sucuri, Shield, MalCare) also write logs. The skill doesn't scan any of these directories. These logs can provide IP addresses of attackers, blocked attack attempts, firewall rule changes, and evidence of security plugin tampering.
- **Fix**: Add discovery of `wp-content/wflogs/`, `wp-content/plugins/wordfence/`, and similar security plugin log directories. Extract recent attack data, access logs, firewall events, and configuration changes. Feed to a database/log analysis agent for correlation with other findings.

### SCAN-03: No Multisite / Subsite Detection [MEDIUM]

- **Status**: Completed (2026-02-04)
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`
- **Description**: WordPress multisite installations use `wp_N_*` table prefixes for subsites (e.g., `wp_2_options`, `wp_3_posts`). The pre-scanner only extracts options from the main `_options` table and doesn't detect or analyze subsite tables. In the reference scan, a `wp_2_options` subsite was found with: a suspicious admin email (`92juber.shaikh@gmail.com`) unrelated to any known user, an active `wp-file-manager` v8.0.2 (CVE-2020-25213, CVSS 10.0 unauthenticated RCE), URL misconfiguration, a different theme from the main site, and stale cron jobs from 2019. Abandoned subsites with vulnerable plugins are a common attack vector.
- **Fix**: Detect multisite by checking for `wp_N_options` tables in CREATE TABLE statements. For each subsite found, extract `siteurl`, `home`, `active_plugins`, `template`, `stylesheet`, and admin email from its options table. Report subsites with their plugin inventories so agents can flag abandoned or vulnerable subsite plugins.

### SCAN-04: No @include Detection in wp-config.php [MEDIUM]

- **Status**: Completed (2026-02-04)
- **Severity**: Medium
- **Component**: `prompt.md` — Agent 3 (Core File Integrity)
- **Description**: The `@include` directive in wp-config.php is a classic malware persistence technique — it silently loads external PHP files before WordPress bootstraps. In the reference scan, a `@include` for `bv-preload.php` (MalCare error monitoring preloader) was found in wp-config.php. While this particular instance was legitimate, the same technique is used by WP-VCD and other malware families to load backdoors from wp-content or other non-standard locations. Agent 3 reads wp-config.php content but the prompt doesn't specifically instruct it to flag `@include`, `include`, `require`, or `require_once` directives pointing to non-standard files.
- **Fix**: Add explicit instructions to Agent 3's prompt to flag any `@include`, `include`, `require`, or `require_once` in wp-config.php that references files outside of standard WordPress paths (wp-settings.php is the only expected include). Also consider adding `@include` detection to the PHP pattern scanner for wp-config.php specifically.

### PERF-01: Enforce per-turn output budget for all sub-agents [HIGH]

- **Status**: Completed (2026-02-03)
- **Severity**: High
- **Component**: `prompt.md` — all sub-agent prompt sections
- **Related bug**: BUG-01
- **Description**: The Bedrock environment caps each model response at 4096 tokens total (1024 thinking + ~3072 visible output). A Write tool call encodes the full file content in the response JSON, so any single Write with content exceeding ~8,000 characters will be truncated and fail. The current prompt instructs agents to "write findings to file and return a one-line summary" but doesn't constrain the size of the write itself. Agents with verbose output (Plugin CVE batches, Report Compiler) exceed the limit on the Write call and lose all work.
- **Fix**: Update `prompt.md` with these changes across all agent sections:
  1. Add an explicit rule: "Each Write call's content must be under 8,000 characters. If your report is larger, split it across multiple Bash append operations (`cat >> file << 'EOF'`), each under 8,000 characters."
  2. For Plugin CVE agents: enforce terse table format — one row per CVE with columns (ID, CVSS, Type, Affected Versions, Status). No prose descriptions. Cap at ~6,000 characters per batch report.
  3. For all filesystem/DB agents: specify structured output format (severity-rated table + brief notes) rather than open-ended prose.
  4. Add the character budget and chunked-write instructions to the top-level "Environment constraint" section so every agent prompt inherits it.

### PERF-02: Restructure Report Compiler for chunked output [HIGH]

- **Status**: Completed (2026-02-03)
- **Severity**: High
- **Component**: `prompt.md` — Phase 5 (Report Compiler agent)
- **Related bug**: BUG-01
- **Description**: The Report Compiler reads 18 agent report files and writes a single combined `malware-scan-report.md`. This combined report far exceeds what can fit in a single Write call (~8,000 chars). The orchestrator has the same 4096 token limit, so moving compilation out of a sub-agent doesn't help. The compiler (or orchestrator) must write the report incrementally across multiple turns.
- **Fix**: Restructure the Report Compiler instructions to write the report in sections using Bash append:
  1. First turn: Write report header + Summary table (`cat > file << 'EOF'`)
  2. Subsequent turns: Append each section (`cat >> file << 'EOF'`): Vulnerability Assessment, Likely Entry Points, Plugin Inventory, Detailed Findings (one append per agent category), Compromise Timeline, Recommendations
  3. Each append must stay under 8,000 characters
  4. If a section (e.g., Detailed Findings) is too large for one append, split it across multiple appends
  5. Final turn: return one-line summary with verdict and finding counts
  6. Alternative approach: have the orchestrator compile the report itself across multiple turns instead of delegating to a sub-agent, avoiding the overhead of agent prompt in the token budget

### SCAN-05: Add WP Version Release Date to Prescan Data [HIGH]

- **Status**: Superseded (2026-02-04)
- **Severity**: High
- **Related bug**: BUG-02
- **Component**: `wp-malware-prescan.py` — `analyze_timestamps()`
- **Description**: Agent 5 is instructed to compare core file timestamps against the WP version's release date, but `timestamps.json` contains only the version string — no release date. The agent must guess the release date from training data, which led to BUG-02 (hallucinated WP 6.9 installation date 6 months before release). Additionally, `version.php` reflects the current version after upgrades, not the originally installed version, but nothing in the prescan data communicates this distinction.
- **Original fix**: Add a hardcoded `WP_RELEASE_DATES` dictionary to the prescan script.
- **Superseded by**: Orchestrator WebSearch approach — Phase 1 of `prompt.md` now performs a WebSearch for the WP version release date, keeping the prescan script offline/deterministic. The release date is passed to Agent 5 in the prompt.

### SCAN-06: Agent 5 Prompt Guardrails for Version/Timeline Claims [HIGH]

- **Status**: Completed (2026-02-04)
- **Severity**: High
- **Related bug**: BUG-02
- **Component**: `prompt.md` — Agent 5 (Timestamp & Timeline Analysis)
- **Description**: Agent 5's prompt says "compare core file modification dates against the WP version's known release date" but provides no guardrails against impossible conclusions. The agent claimed WP 6.9 was installed May 27, 2025 (6 months before release) and built a zero-day narrative around it. The prompt needs explicit rules: (1) never claim a WP version was installed before its release date, (2) if earliest file timestamps predate the version's release, the site was likely upgraded from an earlier version, (3) core file modifications near the version's release date may indicate a routine upgrade rather than tampering.
- **Fix**: Add explicit instructions to Agent 5's prompt section:
  1. "Use `wp_version_release_date` from the JSON — do NOT guess release dates"
  2. "If core file timestamps predate the release date, state the site was running an earlier WP version and was later upgraded"
  3. "Core file modifications within 7 days of the release date should be flagged as 'likely upgrade activity' rather than tampering"
  4. "Do NOT claim a specific WP version was installed on a date before its release"

### REFACTOR-01: Modularize prompt.md into per-phase files [MEDIUM]

- **Status**: Completed (2026-02-04)
- **Summary**: Split monolithic `prompt.md` into `prompts/` directory (preamble + 4 phase files + error-handling). Merged old Phases 2+3 into single parallel phase. 60-90% input token reduction per turn.

### REFACTOR-02: Modularize wp-malware-prescan.py into package [MEDIUM]

- **Status**: Completed (2026-02-04)
- **Summary**: Extracted into `prescan/` package (constants, utils, discovery, 7 scanner modules, orchestration). Entry point shim preserved. Verified identical output against baseline.

### SEC-09: Command Substitution Risk in $ARGUMENTS [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `SKILL.md`
- **Description**: `SKILL.md` uses `$ARGUMENTS` in a bash command: `python3 ~/.claude/skills/wp-malware-scan/wp-malware-prescan.py "$ARGUMENTS"`. Double quotes prevent word splitting and glob expansion, but a path containing backticks or `$()` could still trigger shell command substitution. In practice, Claude Code's Bash tool likely handles this safely, but it's worth verifying.
- **Mitigation**: Verify Claude Code's handling of `$ARGUMENTS` expansion, or pass the path via a mechanism that avoids shell interpretation.
