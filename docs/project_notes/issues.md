# Issues / Work Log

Track work completed on this skill.

## Entries

### 2026-02-03 - Security Review

- **Status**: Completed
- **Description**: Comprehensive security review of all skill files (SKILL.md, prompt.md, wp-malware-prescan.py)
- **Findings**: 2 High, 4 Medium, 3 Low severity issues identified
- **Notes**: Individual issues logged below.

---

### SEC-01: Prompt Injection via Scanned Content [HIGH]

- **Status**: Pending
- **Severity**: High
- **Component**: `prompt.md` / all sub-agents
- **Description**: Malicious WordPress backups contain attacker-controlled content that gets fed directly into AI sub-agents as context. The pre-scanner includes file content in JSON output (up to 200 chars per pattern match, up to 10KB for core files and theme functions.php). Agents 2, 3, and 4 are also instructed to use the Read tool to open full adversarial files from disk when content is truncated. A crafted PHP file could contain prompt injection instructions that cause agents to suppress findings, report false results, or misuse tools like WebFetch.
- **Mitigation**: Add explicit adversarial-content warnings to all sub-agent prompts. Consider reducing raw content passed to agents. Restrict tool access per agent (e.g., content-analysis agents don't need WebFetch).

### SEC-02: Symlink Traversal Reads Files Outside Backup [HIGH]

- **Status**: Pending
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

- **Status**: Pending
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `read_core_files()`
- **Description**: `read_core_files()` explicitly reads `wp-config.php`, which typically contains database credentials, auth keys, and salts. This content is written to `prescan-data/core-files.json` in plaintext. `database.json` may also contain user password hashes and email addresses. These output files persist on disk after the scan with no cleanup mechanism.
- **Mitigation**: Consider redacting known credential patterns from core file output. Add a cleanup step or warning about sensitive data in output files.

### SEC-05: No Resource Limits (File Count/Size) [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py`
- **Description**: No limits on total files scanned (a crafted backup with millions of tiny PHP files would run indefinitely, and `rglob()` is called 4+ times). No limit on individual file size (`php_file.read_text()` reads entire files into memory — a single 2GB PHP file would exhaust memory). SQL line-by-line reading is memory-efficient but a single very long line could still be problematic.
- **Fix**: Add a file size limit before `read_text()` (e.g., skip files > 10MB). Consider a total file count limit or timeout.

### SEC-06: Gzip Bomb Vulnerability [MEDIUM]

- **Status**: Pending
- **Severity**: Medium
- **Component**: `wp-malware-prescan.py` — `scan_sql_dump()`
- **Description**: `scan_sql_dump()` opens `.sql.gz` files with `gzip.open()`. A gzip bomb (small compressed file that decompresses to enormous size) would cause the line-by-line reader to run indefinitely. While it won't exhaust memory all at once due to line-by-line reading, it would cause an extremely long-running process.
- **Fix**: Track bytes read from gzipped files and abort after a reasonable limit (e.g., 5GB decompressed).

### SEC-07: WebSearch Query Manipulation via Plugin Names [LOW]

- **Status**: Pending
- **Severity**: Low
- **Component**: `prompt.md` — Agents 9+
- **Description**: Agents 9+ construct WebSearch queries using plugin slugs and version numbers extracted from the backup. A malicious backup could include a plugin with a crafted slug/name designed to produce misleading search results or lead to attacker-controlled content when searched.
- **Mitigation**: Sanitize plugin slugs before using in search queries. Consider limiting slug length and character set.

### SEC-08: Potential ReDoS in Regex Patterns [LOW]

- **Status**: Pending
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
