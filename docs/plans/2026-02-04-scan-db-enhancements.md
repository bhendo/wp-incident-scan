# SCAN & DB Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Wordfence/security-plugin log scanning (SCAN-02), multisite detection (SCAN-03), wp-config.php @include detection (SCAN-04), and whitespace-obfuscated payload detection (DB-04) to the pre-scanner and agent prompts.

**Architecture:** Each issue touches two layers: (1) the Python pre-scanner (`prescan/`) that collects data, and (2) the agent prompts (`prompts/`) that instruct AI sub-agents how to analyze it. SCAN-04 is prompt-only (no prescan changes). DB-04 and SCAN-03 extend existing scanner modules. SCAN-02 adds a new scanner module following the `error_logs.py` pattern.

**Tech Stack:** Python 3 (no external deps), Markdown prompt files

---

## Task 1: DB-04 — Whitespace-obfuscated payload detection

**Files:**
- Modify: `prescan/constants.py:98-110` (add pattern to `DB_SUSPICIOUS_PATTERNS`)
- Modify: `prescan/scanners/database.py:72-92` (add post-match whitespace check)
- Modify: `prompts/phase-2-analysis.md:119-129` (update Agent 6 instructions)

This is the simplest change — a new pattern + context annotation in the existing DB scanner.

**Step 1: Add whitespace-obfuscation pattern to constants**

In `prescan/constants.py`, add a new entry to `DB_SUSPICIOUS_PATTERNS` after the existing entries (after line 110):

```python
# Whitespace-obfuscated payloads (DB-04): active content hidden behind
# excessive blank lines to push it below visible area in admin UIs
(r'(?:\r?\n\s*){10,}(?:<script|<iframe|<\?php|\beval\s*\()', 'whitespace-obfuscated payload'),
```

**Step 2: Run pre-scanner against a test backup to verify no crash**

Run: `python3 /Users/bhenderson/.claude/skills/wp-malware-scan/wp-malware-prescan.py /path/to/test-backup 2>&1 | tail -5`
Expected: Completes without error. New pattern may or may not match (depends on test data).

**Step 3: Update Agent 6 prompt to handle the new pattern**

In `prompts/phase-2-analysis.md`, in the Agent 6 section, add instruction 5 (renumber existing 5 to 6):

```markdown
5. For matches labeled `whitespace-obfuscated payload`, note that the attacker used excessive blank lines (`\r\n` padding) to hide active content below the visible area of admin textareas (e.g., WPCode/Insert Headers and Footers). This is a strong indicator of malicious intent — rate at least HIGH.
```

**Step 4: Commit**

```bash
git add prescan/constants.py prescan/scanners/database.py prompts/phase-2-analysis.md
git commit -m "feat: detect whitespace-obfuscated payloads in SQL dumps (DB-04)"
```

---

## Task 2: SCAN-04 — @include detection in wp-config.php

**Files:**
- Modify: `prompts/phase-2-analysis.md:39-50` (update Agent 3 instructions)

This is prompt-only — no prescan changes needed. Agent 3 already reads wp-config.php content from `core-files.json`; it just needs explicit instructions to flag non-standard includes.

**Step 1: Update Agent 3 instructions**

In `prompts/phase-2-analysis.md`, replace the Agent 3 instructions (lines 44-50) with:

```markdown
Instructions for agent:
1. Read the input JSON file (contains full/truncated contents of core WP files and all .htaccess files)
2. Review each core file for injected code, suspicious includes/requires, malicious redirects, or unauthorized modifications
3. Compare against expected WordPress core file structure
4. Check .htaccess files for malicious rewrite rules, redirects, or PHP execution directives in uploads
5. **wp-config.php @include audit**: Flag ANY `@include`, `include`, `require`, or `require_once` directive in wp-config.php. The ONLY expected include is `wp-settings.php` (at the bottom). All others are suspicious — especially `@include` of files in wp-content/, wp-includes/, or with non-PHP extensions (.ico, .jpg, .png). Common legitimate exception: `bv-preload.php` (MalCare/BlogVault error monitoring) — flag as INFO, not HIGH. Common malware: WP-VCD uses `@include` to load backdoors from wp-content or theme directories.
6. If any file was truncated, use the Read tool to read the full file from disk for complete analysis
7. Write per-file verdict (CLEAN / SUSPICIOUS) with quoted suspicious lines to the output file
```

**Step 2: Commit**

```bash
git add prompts/phase-2-analysis.md
git commit -m "feat: add @include detection instructions for Agent 3 (SCAN-04)"
```

---

## Task 3: SCAN-03 — Multisite/subsite detection in SQL dumps

**Files:**
- Modify: `prescan/scanners/database.py:17-33,62-70,115-147` (add multisite detection + subsite option extraction)
- Modify: `prescan/constants.py:234-237` (no changes needed, `STANDARD_WP_TABLES` already exists)
- Modify: `prompts/phase-2-analysis.md:131-142` (update Agent 7 instructions)
- Modify: `prompts/phase-4-report.md:71-87` (add Multisite subsection to Chunk 4)

**Step 1: Add multisite detection to database scanner**

In `prescan/scanners/database.py`, add a `subsites` key to the results dict (after line 32):

```python
    results = {
        'content_matches': [],
        'users': [],
        'admin_users': [],
        'options': {},
        'create_tables': [],
        'cron_data': None,
        'snippets': [],
        'subsites': {},  # SCAN-03: {site_id: {siteurl, home, active_plugins, ...}}
    }
```

**Step 2: Add subsite table detection in the CREATE TABLE / INSERT tracking section**

In `prescan/scanners/database.py`, after the existing `create_m` block (line 66), add detection for multisite `wp_N_options` tables. Then in the options extraction section (after line 147), add subsite option extraction.

Add a regex and extraction block. After the `current_table` tracking at line 70:

```python
                # SCAN-03: Detect multisite subsite options tables
                subsite_m = re.match(r'wp_(\d+)_options', current_table)
                if subsite_m and '_options' in current_table and 'INSERT' in line.upper():
                    site_id = subsite_m.group(1)
                    if site_id not in results['subsites']:
                        results['subsites'][site_id] = {}
                    subsite_target = {'siteurl', 'home', 'active_plugins', 'template', 'stylesheet', 'admin_email'}
                    for opt_name in subsite_target:
                        if opt_name in line:
                            opt_match = re.search(
                                rf"'{re.escape(opt_name)}'\s*,\s*'(.*?)'(?:\s*,\s*'(?:yes|no)')?",
                                line, re.I
                            )
                            if opt_match:
                                val = opt_match.group(1)
                                if len(val) > 2000:
                                    results['subsites'][site_id][opt_name] = val[:2000] + f'... [TRUNCATED]'
                                else:
                                    results['subsites'][site_id][opt_name] = val
```

**Step 3: Update Agent 7 instructions for multisite awareness**

In `prompts/phase-2-analysis.md`, replace the Agent 7 instructions (lines 137-142) with:

```markdown
Instructions for agent:
1. Read both input files. Focus on `users`, `admin_users`, `options`, `cron_data`, `create_tables`, and `subsites` from the database JSON
2. Review all admin accounts and flag suspicious ones (random usernames, suspicious email domains, recently created)
3. Check siteurl/home for hijacking, active_plugins for unknown plugins, template/stylesheet for theme tampering
4. Parse the cron data and flag unrecognized scheduled events
5. Compare the CREATE TABLE list against standard WP tables plus known plugin tables, flag unknown tables
6. **Multisite audit**: If `subsites` is non-empty, this is a WordPress multisite installation. For each subsite:
   - Flag admin_email addresses that don't match the main site's known users
   - Check active_plugins for vulnerable or abandoned plugins (cross-reference with main site plugin inventory from discovery.json)
   - Flag subsites where siteurl/home differ significantly from the main site (possible hijacking)
   - Note subsites with different themes from the main site (may indicate abandonment)
   - Abandoned subsites with outdated plugins are a common initial attack vector — rate as at least MEDIUM
7. Write findings grouped by category with severity ratings to the output file
```

**Step 4: Update report template**

In `prompts/phase-4-report.md`, in the Chunk 4 section (line 87), add after Database Structure:

```markdown
### Multisite Analysis
[If subsites were detected: condensed findings from agent 7 multisite audit. If no subsites: "Single-site installation — no multisite analysis needed."]
```

**Step 5: Commit**

```bash
git add prescan/scanners/database.py prompts/phase-2-analysis.md prompts/phase-4-report.md
git commit -m "feat: detect and audit multisite subsites in SQL dumps (SCAN-03)"
```

---

## Task 4: SCAN-02 — Wordfence/security plugin log scanning

**Files:**
- Create: `prescan/scanners/security_logs.py` (new scanner module)
- Modify: `prescan/constants.py` (add security log constants)
- Modify: `prescan/discovery.py` (add `discover_security_log_dirs()`)
- Modify: `prescan/scanner.py:115-120` (call new scanner, write section)
- Modify: `prompts/phase-2-analysis.md:84-115` (add Agent 5c after Agent 5b)
- Modify: `prompts/phase-4-report.md:71-87` (add Security Plugin Logs subsection)
- Modify: `docs/project_notes/key_facts.md:57-67` (add Agent 5c to assignments)

This is the largest task. It follows the same pattern as `error_logs.py` + `discover_log_files()`.

### Step 1: Add constants for security plugin log scanning

In `prescan/constants.py`, add a new section after the error log patterns (after line 221):

```python
# ---------------------------------------------------------------------------
# Security plugin log patterns (SCAN-02)
# ---------------------------------------------------------------------------

MAX_SECURITY_LOG_FILES = 100
MAX_SECURITY_LOG_READ_BYTES = 5 * 1024 * 1024  # 5MB per file
MAX_SECURITY_LOG_TOTAL_BYTES = 30 * 1024 * 1024  # 30MB total
MAX_SECURITY_LOG_ENTRIES = 500  # Max entries to include in output

# Known security plugin log directories (relative to wp-content/)
SECURITY_LOG_DIRS = [
    'wflogs',                           # Wordfence
    'plugins/wordfence/tmp',            # Wordfence tmp
    'uploads/sucuri',                   # Sucuri
    'plugins/sucuri-scanner/logs',      # Sucuri scanner
    'uploads/shield',                   # Shield Security
    'plugins/better-wp-security/logs',  # iThemes/SolidWP Security
    'uploads/mainwp',                   # MainWP
    'plugins/all-in-one-wp-security-and-firewall/logs',  # AIOS
]

# Patterns to extract from security plugin logs
SECURITY_LOG_PATTERNS = {
    'blocked_attack': [
        (r'blocked.*(?:sql|xss|rfi|lfi|rce|traversal)', 'blocked_attack'),
        (r'firewall.*block', 'firewall_block'),
        (r'waf.*block', 'waf_block'),
    ],
    'login_attempt': [
        (r'login.*(?:fail|invalid|locked|blocked)', 'failed_login'),
        (r'brute.?force', 'brute_force'),
        (r'lockout', 'lockout'),
    ],
    'file_change': [
        (r'file.*(?:modif|chang|added|deleted)', 'file_change'),
        (r'integrity.*(?:fail|changed)', 'integrity_check'),
    ],
    'malware_detection': [
        (r'malware.*(?:found|detected|scan)', 'malware_found'),
        (r'suspicious.*(?:file|code)', 'suspicious_detected'),
        (r'quarantin', 'quarantine'),
    ],
    'config_change': [
        (r'(?:option|setting|config).*(?:changed|updated|modified)', 'config_change'),
        (r'firewall.*(?:enabled|disabled|mode)', 'firewall_config'),
    ],
}
```

### Step 2: Add discovery function for security log directories

In `prescan/discovery.py`, add a new function after `discover_log_files()` (after line 154):

```python
def discover_security_log_dirs(wp_root: Path) -> list[dict]:
    """Discover Wordfence, Sucuri, and other security plugin log directories.

    Returns list of dicts with path, rel_path, plugin_name, file_count, total_size.
    """
    from prescan.constants import SECURITY_LOG_DIRS

    wp_content = wp_root / 'wp-content'
    if not wp_content.is_dir():
        return []

    found = []
    for rel_dir in SECURITY_LOG_DIRS:
        candidate = wp_content / rel_dir
        if not candidate.is_dir():
            continue
        resolved = candidate.resolve()
        wp_root_resolved = str(wp_root.resolve())
        if not is_within_root(resolved, wp_root_resolved):
            continue

        # Identify which plugin this belongs to
        plugin_name = rel_dir.split('/')[0]
        if plugin_name == 'wflogs':
            plugin_name = 'wordfence'
        elif plugin_name == 'uploads':
            # uploads/sucuri, uploads/shield, etc.
            plugin_name = rel_dir.split('/')[1] if '/' in rel_dir else 'unknown'

        files = []
        total_size = 0
        try:
            for f in sorted(candidate.rglob('*')):
                if f.is_file() and is_within_root(f.resolve(), wp_root_resolved):
                    try:
                        size = f.stat().st_size
                        files.append({
                            'path': str(f),
                            'rel_path': str(f.relative_to(wp_root)),
                            'size': size,
                            'name': f.name,
                        })
                        total_size += size
                    except OSError:
                        continue
        except (PermissionError, OSError):
            continue

        if files:
            found.append({
                'dir_path': str(candidate),
                'rel_path': str(candidate.relative_to(wp_root)),
                'plugin_name': plugin_name,
                'file_count': len(files),
                'total_size': total_size,
                'files': files,
            })

    return found
```

Also add the import for `SECURITY_LOG_DIRS` at the top of the file (update the constants import block).

### Step 3: Create the security log scanner module

Create `prescan/scanners/security_logs.py`:

```python
"""Scan Wordfence, Sucuri, and other security plugin logs for attack evidence."""

import re
import sys
from collections import defaultdict
from pathlib import Path

from prescan.constants import (
    MAX_FILE_READ_SIZE,
    MAX_SECURITY_LOG_ENTRIES,
    MAX_SECURITY_LOG_READ_BYTES,
    MAX_SECURITY_LOG_TOTAL_BYTES,
    SECURITY_LOG_PATTERNS,
)
from prescan.discovery import discover_security_log_dirs


def scan_security_logs(wp_root: Path) -> dict:
    """Discover and scan security plugin log directories."""
    log_dirs = discover_security_log_dirs(wp_root)

    result = {
        'dirs_found': len(log_dirs),
        'dirs': [],
        'total_bytes_read': 0,
        'entries_by_category': defaultdict(list),
        'ip_addresses': defaultdict(int),
    }

    if not log_dirs:
        return result

    total_bytes = 0
    entry_count = 0

    for dir_info in log_dirs:
        dir_record = {
            'rel_path': dir_info['rel_path'],
            'plugin_name': dir_info['plugin_name'],
            'file_count': dir_info['file_count'],
            'total_size': dir_info['total_size'],
            'files_scanned': 0,
            'entries_found': 0,
        }

        for file_info in dir_info['files']:
            if total_bytes >= MAX_SECURITY_LOG_TOTAL_BYTES:
                break
            if entry_count >= MAX_SECURITY_LOG_ENTRIES:
                break

            file_path = Path(file_info['path'])
            file_size = file_info['size']

            if file_size > MAX_FILE_READ_SIZE:
                continue
            if file_size == 0:
                continue

            try:
                if file_size > MAX_SECURITY_LOG_READ_BYTES:
                    with open(file_path, 'rb') as f:
                        f.seek(file_size - MAX_SECURITY_LOG_READ_BYTES)
                        f.readline()  # skip partial line
                        raw = f.read().decode('utf-8', errors='replace')
                    bytes_read = MAX_SECURITY_LOG_READ_BYTES
                else:
                    raw = file_path.read_text(errors='replace')
                    bytes_read = file_size

                total_bytes += bytes_read
            except (PermissionError, OSError):
                continue

            dir_record['files_scanned'] += 1

            for line in raw.split('\n'):
                if not line.strip():
                    continue
                if entry_count >= MAX_SECURITY_LOG_ENTRIES:
                    break

                for category, patterns in SECURITY_LOG_PATTERNS.items():
                    matched = False
                    for pat_re, pat_name in patterns:
                        if re.search(pat_re, line, re.I):
                            entry = {
                                'log_dir': dir_info['rel_path'],
                                'plugin': dir_info['plugin_name'],
                                'file': file_info['rel_path'],
                                'pattern': pat_name,
                                'content': line.strip()[:500],
                            }

                            # Extract IP addresses
                            ip_match = re.search(
                                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line
                            )
                            if ip_match:
                                ip = ip_match.group(1)
                                entry['ip'] = ip
                                result['ip_addresses'][ip] += 1

                            result['entries_by_category'][category].append(entry)
                            entry_count += 1
                            dir_record['entries_found'] += 1
                            matched = True
                            break
                    if matched:
                        break

        result['dirs'].append(dir_record)

    result['total_bytes_read'] = total_bytes
    result['entries_by_category'] = dict(result['entries_by_category'])
    result['ip_addresses'] = dict(
        sorted(result['ip_addresses'].items(), key=lambda x: x[1], reverse=True)[:50]
    )

    return result
```

### Step 4: Wire the new scanner into the orchestrator

In `prescan/scanner.py`, add the import (after line 20):

```python
from prescan.scanners.security_logs import scan_security_logs
```

Then add the scan call after error_logs (after line 120, before the database section):

```python
    print('[*] Scanning security plugin logs...', file=sys.stderr)
    security_logs = scan_security_logs(wp_root)
    sec_entries = sum(len(v) for v in security_logs['entries_by_category'].values())
    print(f'    {security_logs["dirs_found"]} security log dirs found, '
          f'{sec_entries} entries extracted', file=sys.stderr)
    write_section(data_dir, 'security-logs', security_logs)
```

Update the `section_files` dict (after line 137):

```python
        'security_logs': 'prescan-data/security-logs.json',
```

Update the `summary` dict (after line 168):

```python
            'security_log_dirs_found': security_logs['dirs_found'],
            'security_log_entries': sec_entries,
```

### Step 5: Run pre-scanner to verify it works

Run: `python3 /Users/bhenderson/.claude/skills/wp-malware-scan/wp-malware-prescan.py /path/to/test-backup 2>&1 | tail -10`
Expected: Shows "Scanning security plugin logs..." line. Completes without error. `prescan-data/security-logs.json` is created.

### Step 6: Add Agent 5c prompt to phase-2-analysis.md

In `prompts/phase-2-analysis.md`, add a new agent section after Agent 5b (after the `---` on line 117, before Agent 6):

```markdown
### Agent 5c: Security Plugin Log Analysis

**Input file**: `{backup_root}/prescan-data/security-logs.json`
**Output file**: `{backup_root}/scan-results/agent-5c-security-logs.md`

Instructions for agent:
1. Read the input JSON file. If `dirs_found` is 0, write a brief "No security plugin logs found" report and return
2. Review `entries_by_category` for evidence of attacks that may have succeeded — especially `malware_detection` and `file_change` entries
3. Check `ip_addresses` for IPs appearing across multiple attack categories — these are likely the attacker's IPs
4. Cross-reference `login_attempt` entries with `blocked_attack` entries — a successful login followed by blocked attacks from the same IP suggests the attacker had credentials
5. For `config_change` entries, flag any firewall disabling or security feature modifications — attackers often disable security plugins after gaining access
6. Note which security plugins were active — their presence means the site had *some* defense, and the logs may reveal what the attacker did *despite* those defenses
7. Write findings table + IP summary + brief analysis, target under 6,000 chars

**Output format**:
```
# Agent 5c: Security Plugin Log Analysis

## Security Plugin Inventory

| Plugin | Log Directory | Files | Total Size |
|--------|--------------|-------|------------|

## Attack Evidence

| # | Severity | Category | Plugin | Pattern | IP | Detail |
|---|----------|----------|--------|---------|-----|--------|

## Top Attacker IPs

| IP Address | Hit Count | Categories |
|------------|-----------|------------|

## Notes
[Brief analysis — attack patterns, timeline correlation, defense gaps]
```
```

### Step 7: Update report template for security plugin logs

In `prompts/phase-4-report.md`, in Chunk 4 (line 80), add after Error Log Analysis:

```markdown
### Security Plugin Logs
[Condensed key findings from agent 5c — attack evidence, attacker IPs, defense gaps. If no security logs: "No security plugin logs found."]
```

Also update the Summary table in Chunk 1 (add a row after Error Log Analysis):

```markdown
| Security Plugin Logs | ... | ... | ... |
```

### Step 8: Update key_facts.md with new agent

In `docs/project_notes/key_facts.md`, add after Agent 5b line:

```markdown
- Agent 5c: Security Plugin Log Analysis
```

### Step 9: Commit

```bash
git add prescan/scanners/security_logs.py prescan/constants.py prescan/discovery.py prescan/scanner.py prompts/phase-2-analysis.md prompts/phase-4-report.md docs/project_notes/key_facts.md
git commit -m "feat: scan Wordfence/Sucuri/security plugin logs (SCAN-02)"
```

---

## Task 5: Update project memory

**Files:**
- Modify: `docs/project_notes/issues.md` (mark SCAN-02, SCAN-03, SCAN-04, DB-04 as completed)

**Step 1: Update issue statuses**

Mark each issue as Completed with today's date (2026-02-04):
- DB-04: Status → Completed (2026-02-04)
- SCAN-02: Status → Completed (2026-02-04)
- SCAN-03: Status → Completed (2026-02-04)
- SCAN-04: Status → Completed (2026-02-04)

Remove these four items from the "Remaining Pending Issues" list at the top.

**Step 2: Commit**

```bash
git add docs/project_notes/issues.md
git commit -m "docs: mark SCAN-02, SCAN-03, SCAN-04, DB-04 as completed"
```
