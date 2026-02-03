# Issues / Work Log

Track work completed on this skill.

## Entries

### 2026-02-03 - Security Review

- **Status**: Completed
- **Description**: Comprehensive security review of all skill files (SKILL.md, prompt.md, wp-malware-prescan.py)
- **Findings**: 2 High, 4 Medium, 3 Low severity issues identified
- **Notes**: Individual issues logged below.

---

## Remediation Order

Prioritized fix order for remaining pending issues:

1. **SEC-05 + SEC-06** — Resource limits & gzip bomb (tackle together)
2. **SEC-07** — WebSearch query manipulation (plugin slug sanitization)
3. **SEC-04** — Sensitive data exposure (credential redaction)
4. **SEC-09** — Command substitution risk (verification task)
5. **SEC-03** — Backup directory contamination (do before SEC-04 if output paths change; otherwise after)
6. **SEC-01** — Prompt injection (most complex, do last)

**Notes**: SEC-03 should ideally precede SEC-04 since output location affects cleanup strategy, but SEC-03 has a wider blast radius. If SEC-03 is deferred, SEC-04 can still be done standalone. SEC-05/SEC-06 are grouped because both are resource-limit hardening in the same file.

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

### SEC-09: Command Substitution Risk in $ARGUMENTS [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `SKILL.md`
- **Description**: `SKILL.md` uses `$ARGUMENTS` in a bash command: `python3 ~/.claude/skills/wp-malware-scan/wp-malware-prescan.py "$ARGUMENTS"`. Double quotes prevent word splitting and glob expansion, but a path containing backticks or `$()` could still trigger shell command substitution. In practice, Claude Code's Bash tool likely handles this safely, but it's worth verifying.
- **Mitigation**: Verify Claude Code's handling of `$ARGUMENTS` expansion, or pass the path via a mechanism that avoids shell interpretation.
