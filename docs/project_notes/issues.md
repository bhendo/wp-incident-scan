# Issues / Work Log

Track work completed on this skill. Completed issue details archived in `issues-archive.md`.

## Entries

### 2026-02-03 - Security Review

- **Status**: Completed
- **Description**: Comprehensive security review of all skill files (SKILL.md, prompts/, prescan/)
- **Findings**: 2 High, 4 Medium, 3 Low severity issues identified
- **Resolved**: SEC-02 (#2), SEC-04 (#4), SEC-05 (#5), SEC-06 (#6), SEC-07 (#7), SEC-08 (#8), DB-01 (#10), DB-02 (#11), DB-03 (#12)

### 2026-02-03 - Performance Fixes

- **Status**: Completed
- **Description**: Fixed output token budget issues causing agent truncation
- **Resolved**: PERF-01 (#20), PERF-02 (#21)

### 2026-02-04 - Agent Renumbering

- **Status**: Completed
- **Description**: Renumbered agents sequentially, removing 5b/5c suffixes: 5b->6, 5c->7, 6->8, 7->9, 8->10, 9+->11+. Updated 6 files.

### 2026-02-04 - BUG-03 Fix: User Email Extraction Off-by-One

- **Status**: Completed
- **Description**: Fixed capture group indexing bug in `prescan/scanners/database.py`. Added test infrastructure and regression tests.

### 2026-02-04 - BUG-05: Review and Remove Unnecessary Data Redaction (#61)

- **Status**: Completed
- **Description**: Removed counterproductive email redaction from incident reports. Reviewed all redaction across codebase.

### 2026-02-04 - Agent 5 Mass File Event Classification (#62, #63)

- **Status**: Completed
- **Description**: Enriched prescan cluster data with distributions. Added classification rules to Agent 5 prompt. Tests added.

### 2026-02-04 - Feature Gap Analysis

- **Status**: Completed
- **Description**: Identified 18 feature gaps (5 High, 8 Medium, 5 Low). GAP-01 through GAP-18 (#40-#57).

### 2026-02-04 - Security Review #2

- **Status**: Completed
- **Description**: Second security review. 16 unique issues (4 High, 7 Medium, 5 Low).
- **Resolved**: TOOL-01 through TOOL-04 (#24-#27), PATH-01 through PATH-03 (#28-#30), MEM-01 (#31), AGENT-01 through AGENT-03 (#32-#34), INFO-01 through INFO-03 (#35-#37), LIMIT-01 (#38), LIMIT-02 (#39)

### 2026-02-04 - Refactoring

- **Status**: Completed
- **Description**: REFACTOR-01 (#22, prompt.md -> prompts/ directory), REFACTOR-02 (#23, prescan.py -> prescan/ package)

### 2026-02-04 - Scanner Improvements

- **Status**: Completed
- **Description**: DB-04 (#13, whitespace obfuscation detection), SCAN-01 (#14, error log scanning), SCAN-02 (#15, Wordfence log scanning), SCAN-03 (#16, multisite detection), SCAN-04 (#17, @include detection), SCAN-06 (#19, Agent 5 guardrails). SCAN-05 (#18) superseded by orchestrator WebSearch approach.

### 2026-02-04 - CVE Prescan Lookup (#60, #64-#68)

- **Status**: Completed
- **Description**: Added Wordfence CVE database cache for prescan plugin/theme vulnerability lookup.

### 2026-02-05 - Archive Completed Issues

- **Status**: Completed
- **Description**: Moved completed issue details to `issues-archive.md` to reduce context overhead.

---

## Remaining Pending Issues

1. **SEC-01** (#1) — Prompt injection via scanned content (most complex)
2. **SEC-03** (#3) — Backup directory contamination (write output outside backup)
3. **SEC-09** (#9) — Command substitution risk in $ARGUMENTS (verification task)
4. **GAP-01** (#40) — No JavaScript malware detection (skimmers, redirects, cryptominers) [HIGH]
5. **GAP-02** (#41) — No mu-plugins or drop-in file scanning [HIGH]
6. **GAP-03** (#42) — No core file hash verification against wordpress.org checksums [HIGH]
7. **GAP-04** (#43) — No network IOC extraction (URLs, domains, IPs from malicious code) [HIGH]
8. **GAP-05** (#44) — No web server access log analysis (Apache/Nginx) [HIGH]
9. **GAP-06** (#45) — No file entropy analysis for obfuscation detection [MEDIUM]
10. **GAP-07** (#46) — No image/media polyglot detection beyond .ico files [MEDIUM]
11. **GAP-08** (#47) — No user role/capability tampering detection [MEDIUM]
12. **GAP-09** (#48) — No cron job callback analysis [MEDIUM]
13. **GAP-10** (#49) — No file encoding anomaly detection (BOM, UTF-16, null bytes) [LOW]
14. **GAP-11** (#50) — No delta/comparison scanning between two backups [MEDIUM]
15. **GAP-12** (#51) — No plugin/theme file inventory comparison against wordpress.org [MEDIUM]
16. **GAP-13** (#52) — No machine-readable (JSON) report output [LOW]
17. **GAP-14** (#53) — No YARA rule support [LOW]
18. **GAP-15** (#54) — No scan resumability after partial failure [LOW]
19. **GAP-16** (#55) — No known malware hash database [MEDIUM]
20. **GAP-17** (#56) — No remediation file manifest [MEDIUM]
21. **GAP-18** (#57) — No `.user.ini` / `php.ini` auto_prepend_file scanning [MEDIUM]

---

### SEC-01 (#1): Prompt Injection via Scanned Content [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prompt.md` / all sub-agents
- **Description**: Malicious WordPress backups contain attacker-controlled content that gets fed directly into AI sub-agents as context. The pre-scanner includes file content in JSON output (up to 200 chars per pattern match, up to 10KB for core files and theme functions.php). Agents 2, 3, and 4 are also instructed to use the Read tool to open full adversarial files from disk when content is truncated. A crafted PHP file could contain prompt injection instructions that cause agents to suppress findings, report false results, or misuse tools like WebFetch.
- **Mitigation**: Add explicit adversarial-content warnings to all sub-agent prompts. Consider reducing raw content passed to agents. Restrict tool access per agent (e.g., content-analysis agents don't need WebFetch).

### SEC-03 (#3): Backup Directory Contamination [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `wp-incident-prescan.py`, `prompt.md`
- **Description**: The scanner writes output directly into the scanned backup directory (`prescan-data/`, `scan-results/`, `wp-prescan-results.json`, `incident-scan-report.md`). This modifies timestamps and directory structure of forensic evidence. If the user accidentally points the tool at a live WordPress installation, these files would be web-accessible.
- **Fix**: Write output to a separate directory outside the backup (e.g., `/tmp/wp-scan-{hash}/` or a user-specified output path).

### SEC-09 (#9): Command Substitution Risk in $ARGUMENTS [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `SKILL.md`
- **Description**: `SKILL.md` uses `$ARGUMENTS` in a bash command: `python3 ~/.claude/skills/wp-incident-scan/wp-incident-prescan.py "$ARGUMENTS"`. Double quotes prevent word splitting and glob expansion, but a path containing backticks or `$()` could still trigger shell command substitution. In practice, Claude Code's Bash tool likely handles this safely, but it's worth verifying.
- **Mitigation**: Verify Claude Code's handling of `$ARGUMENTS` expansion, or pass the path via a mechanism that avoids shell interpretation.

### GAP-01 (#40): No JavaScript Malware Detection [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prescan/scanners/php_patterns.py`, `prompts/phase-2-analysis.md`
- **Description**: Only PHP files are pattern-scanned. JS-based attacks are increasingly common in WordPress: credit card skimmers (Magecart-style) injected into WooCommerce checkout JS, malicious redirects via injected `<script>` in theme JS files, cryptominers loaded via modified JS assets, and SEO spam injectors. The pre-scanner should scan `.js` files for suspicious patterns (eval, document.write, String.fromCharCode, obfuscated variable names, external script loading, fetch/XMLHttpRequest to unknown domains). A dedicated agent or extension to Agent 1 would analyze flagged JS files.
- **Fix**: Add a JS pattern scanner module (`prescan/scanners/js_patterns.py`) with patterns for eval, document.write, String.fromCharCode, atob, unescape, obfuscated variable chains, external domain references, and known skimmer signatures. Output to `prescan-data/js-pattern-matches.json`. Extend Agent 1 or add a new agent to analyze JS findings.

### GAP-02 (#41): No mu-plugins or Drop-in File Scanning [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prescan/scanners/suspicious_files.py`, `prompts/phase-2-analysis.md`
- **Description**: `wp-content/mu-plugins/` files are auto-loaded on every request with no activation step — a prime malware hiding spot. WordPress drop-in files (`object-cache.php`, `advanced-cache.php`, `db.php`, `maintenance.php` in `wp-content/`) are also auto-loaded and commonly abused for persistence. Neither directory gets specific attention from any agent.
- **Fix**: (1) Add mu-plugins enumeration to discovery module. (2) Add drop-in detection for known filenames in `wp-content/`. (3) Read contents (truncated) into prescan output. (4) Extend Agent 2 or Agent 3 prompt to review.

### GAP-03 (#42): No Core File Hash Verification [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prescan/scanners/core_files.py`, `prompts/phase-2-analysis.md`
- **Description**: Never verifies files against known-good checksums. WordPress provides an API (`https://api.wordpress.org/core/checksums/1.0/?version=X.Y&locale=en_US`) that returns MD5 hashes for every core file. Would instantly flag modified, added, or missing core files with zero false positives.
- **Fix**: Fetch checksums from WordPress API, compute MD5 hashes of `wp-admin/` and `wp-includes/` files, compare. Output to `prescan-data/core-integrity.json`.

### GAP-04 (#43): No Network IOC Extraction [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prescan/scanners/php_patterns.py`, `prescan/scanners/database.py`, `prompts/phase-4-report.md`
- **Description**: Malicious code contains URLs, domains, and IP addresses (C2 servers, exfiltration endpoints, external script sources). The skill doesn't extract these as Indicators of Compromise.
- **Fix**: Post-processing pass to extract URLs/domains/IPs from pattern-matched content. Output to `prescan-data/network-iocs.json`. Add IOC summary section to final report.

### GAP-05 (#44): No Web Server Access Log Analysis [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prescan/discovery.py`, `prescan/scanners/`, `prompts/phase-2-analysis.md`
- **Description**: Apache/Nginx access logs reveal exploit requests, brute force patterns, file uploads, attacker IPs, timing of first compromise, and requests to malware paths. Not currently scanned.
- **Fix**: Add access log discovery and new scanner module (`prescan/scanners/access_logs.py`). Parse combined log format, extract suspicious requests. Output to `prescan-data/access-logs.json`.

### GAP-06 (#45): No File Entropy Analysis [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/php_patterns.py`
- **Description**: Obfuscated PHP has measurably higher Shannon entropy (>6.0 bits/byte) than normal code (4.5-5.5). Would flag obfuscated files that bypass pattern matching.
- **Fix**: Add Shannon entropy calculation to PHP pattern scanner. Flag files with entropy > 6.0 bits/byte.

### GAP-07 (#46): No Image/Media Polyglot Detection Beyond .ico [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/suspicious_files.py`
- **Description**: Attackers embed PHP in EXIF metadata of images or create polyglot files. Only `.ico` files currently checked.
- **Fix**: Check `.jpg`, `.png`, `.gif`, `.bmp`, `.svg` in uploads for PHP tags. Check `.svg` for `<script` tags.

### GAP-08 (#47): No User Role/Capability Tampering Detection [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/database.py`, `prompts/phase-2-analysis.md` — Agent 9
- **Description**: No detection of custom roles with elevated capabilities, modified capability arrays, or hidden admin accounts.
- **Fix**: Extract `wp_user_roles` option. Instruct Agent 9 to compare against WordPress defaults and flag anomalies.

### GAP-09 (#48): No Cron Job Callback Analysis [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/database.py`, `prompts/phase-2-analysis.md` — Agent 9
- **Description**: Cron entries extracted but callbacks not analyzed. Malware commonly installs WP-Cron jobs for re-infection, spam, C2 communication.
- **Fix**: Instruct Agent 9 to cross-reference cron callbacks against known WP core/plugin hooks. Flag unknown callbacks and frequent recurrence.

### GAP-10 (#49): No File Encoding Anomaly Detection [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `prescan/scanners/php_patterns.py`
- **Description**: BOM markers, UTF-16, or null bytes can evade UTF-8 pattern scanners. PHP still executes these files.
- **Fix**: Check first bytes for BOM markers and null bytes. Flag as "encoding_anomaly" category.

### GAP-11 (#50): No Delta/Comparison Scanning Between Two Backups [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: Architecture — new mode
- **Description**: No ability to compare pre-compromise vs. post-compromise backups. Significant architectural addition.
- **Fix**: Optional second backup argument. New module for file tree comparison. Output to `prescan-data/delta-analysis.json`.

### GAP-12 (#51): No Plugin/Theme File Inventory Comparison Against wordpress.org [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/`, `prompts/phase-3-vulns.md`
- **Description**: No file-level integrity check for plugins/themes. Attackers hide files inside legitimate plugin directories.
- **Fix**: Fetch plugin checksums from `downloads.wordpress.org/plugin-checksums/{slug}/{version}.json`. Compare against actual files.

### GAP-13 (#52): No Machine-Readable (JSON) Report Output [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `prompts/phase-4-report.md`
- **Description**: Final report is Markdown only. JSON output would enable integration with ticketing/SIEM systems.
- **Fix**: Add parallel JSON output in Phase 4.

### GAP-14 (#53): No YARA Rule Support [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `prescan/scanners/php_patterns.py`
- **Description**: No support for industry-standard YARA malware signatures.
- **Fix**: Optional `yara-python` integration with `--yara-rules` argument. Graceful fallback to regex-only.

### GAP-15 (#54): No Scan Resumability After Partial Failure [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `prompts/preamble.md`, `prompts/error-handling.md`
- **Description**: Partial scan failure requires full restart. Pre-scan data persists but agent analysis must redo.
- **Fix**: Check for existing output files and skip completed steps. Add `--resume` flag.

### GAP-16 (#55): No Known Malware Hash Database [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/php_patterns.py`
- **Description**: No file hash comparison against known WordPress webshells (WSO, FilesMan, b374k, c99, r57, Alfa Shell).
- **Fix**: Bundle `known-malware-hashes.json`. Compute hashes during PHP scanning. Report exact matches with malware family name.

### GAP-17 (#56): No Remediation File Manifest [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prompts/phase-4-report.md`
- **Description**: Report lists findings but no structured list of specific cleanup actions (files to delete, restore, DB rows to clean, credentials to rotate).
- **Fix**: Add "Remediation Manifest" section to final report with actionable items referencing their source findings.

### GAP-18 (#57): No `.user.ini` / `php.ini` Auto-Prepend Scanning [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `prescan/scanners/core_files.py`, `prescan/scanners/suspicious_files.py`
- **Description**: `.user.ini` can set `auto_prepend_file`/`auto_append_file` to silently load malware. Not currently scanned. `.htaccess` scanner covers Apache equivalent but misses nginx/PHP-FPM setups.
- **Fix**: Enumerate `.user.ini` and `php.ini` via rglob. Flag `auto_prepend_file`, `auto_append_file`, `include_path`, `open_basedir` directives. Cross-reference targets with suspicious files.
