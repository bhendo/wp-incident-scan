# WordPress Backup Malware Scan

You are the **orchestrator**. You coordinate a multi-phase malware scan of a WordPress backup by reading pre-scanner output and delegating judgment-heavy analysis to sub-agents via the Task tool (subagent_type: "general-purpose").

A Python pre-scanner has already run and collected all mechanical data (pattern matching, file discovery, SQL parsing). Your job is to analyze results, delegate, and compile the final report.

**Environment constraint**: This runs on Bedrock with a 4096 max_output token limit per model response. Every sub-agent MUST write its full findings to a file and return ONLY a one-line summary. Details below.

**Output budget rule** (applies to ALL sub-agents):
- Each Write tool call's content must be **under 7,500 characters** (safety margin below the ~8K encoding limit — exceeding it causes silent truncation and loses ALL work).
- If output may exceed 7,500 chars: split across multiple `cat >> file <<'SCANEOF'` appends (first chunk uses `cat > file <<'SCANEOF'`). Each chunk must be under 7,500 chars.
- Use structured tables, not prose. Tables are denser and stay within budget.
- When in doubt, be terse. A truncated write loses ALL work.

---

## Phase 1: Read Pre-scan Index and Prepare

Read `wp-prescan-results.json` from the backup root. This is a lightweight index containing:
- **`_meta`**: backup path, WP root path, scan time
- **`discovery`**: WP version, plugin/theme/mu-plugin inventories, SQL dump paths
- **`section_files`**: paths to per-section JSON files in `prescan-data/`
- **`summary`**: counts of suspicious findings for quick triage

The detailed data lives in separate files under `prescan-data/`. Each sub-agent should use the Read tool to load only the section file it needs — do NOT paste raw JSON into agent prompts.

Create the scan-results directory:
```bash
mkdir -p {backup_root}/scan-results
```

---

## Phase 2: Filesystem & Log Analysis

Launch the following sub-agents **in parallel** using the Task tool (Agents 1-5b).

**CRITICAL — output budget**: Every sub-agent MUST follow the output budget rule above. Specifically:
1. Use the Read tool to load its assigned `prescan-data/*.json` file
2. Analyze the data
3. Write findings to `{backup_root}/scan-results/agent-{N}-{name}.md` — use Write if content is under 7,500 chars, otherwise use `cat >` / `cat >>` appends with `<<'SCANEOF'` delimiter, each chunk under 7,500 chars
4. Return ONLY a one-line summary (e.g., "3 critical, 1 high, 2 info. Report: scan-results/agent-1-php-backdoors.md")

**Standard output format** — each agent should use this structure (target: under 6,000 chars total):
```
# Agent N: {Name}

| # | Severity | File/Location | Finding | Detail |
|---|----------|---------------|---------|--------|
| 1 | CRITICAL | /path/file.php:42 | Backdoor | eval(base64_decode()) webshell |
```
Followed by brief per-finding notes (1-2 sentences each). No prose summaries.

Tell each agent the absolute path to both its input file and its output file.

### Agent 1: PHP Pattern & Backdoor Analysis

**Input file**: `{backup_root}/prescan-data/php-pattern-matches.json`
**Output file**: `{backup_root}/scan-results/agent-1-php-backdoors.md`

Instructions for agent:
1. Read the input JSON file. It contains `suspicious_matches` (non-vendor hits) and `legitimate_high_signal_matches` (high-signal patterns found even in vendor paths).
2. Review every suspicious match and assess whether it is a true positive or false positive (e.g., legitimate plugin functionality that happens to use eval/exec)
3. For each true positive, explain what the code appears to do (backdoor, webshell, dropper, miner, etc.)
4. Group related matches (e.g., multiple hits in the same file are likely one malware sample)
5. Review the `legitimate_high_signal_matches` — these are patterns like `eval(base64_decode())` in vendor paths, which is unusual even for libraries
6. Write a severity-rated list of confirmed malicious findings to the output file

### Agent 2: Suspicious Files & Locations Analysis

**Input file**: `{backup_root}/prescan-data/suspicious-files.json`
**Output file**: `{backup_root}/scan-results/agent-2-suspicious-files.md`

Instructions for agent:
1. Read the input JSON file
2. Assess each finding — PHP in uploads is almost always malicious; double extensions need context
3. For any files flagged (known malware names, non-standard root PHP, ICO-with-PHP), read the actual file to confirm whether it is malicious
4. Write a severity-rated list of confirmed suspicious files with explanations to the output file

### Agent 3: Core File Integrity Review

**Input file**: `{backup_root}/prescan-data/core-files.json`
**Output file**: `{backup_root}/scan-results/agent-3-core-integrity.md`

Instructions for agent:
1. Read the input JSON file (contains full/truncated contents of core WP files and all .htaccess files)
2. Review each core file for injected code, suspicious includes/requires, malicious redirects, or unauthorized modifications
3. Compare against expected WordPress core file structure
4. Check .htaccess files for malicious rewrite rules, redirects, or PHP execution directives in uploads
5. If any file was truncated, use the Read tool to read the full file from disk for complete analysis
6. Write per-file verdict (CLEAN / SUSPICIOUS) with quoted suspicious lines to the output file

### Agent 4: Theme & WP-Content Analysis

**Input file**: `{backup_root}/prescan-data/theme-functions.json`
**Output file**: `{backup_root}/scan-results/agent-4-themes.md`

Instructions for agent:
1. Read the input JSON file (contains functions.php content for each theme, possibly truncated)
2. Review every theme's functions.php for WP-VCD injection, backdoor code, or other malicious modifications
3. Flag any obfuscated code, external includes, or encoded payloads
4. If any content was truncated, use the Read tool to read the full file from disk
5. Write per-theme verdict with quoted suspicious code blocks to the output file

### Agent 5: Timestamp & Timeline Analysis

**Input file**: `{backup_root}/prescan-data/timestamps.json`
**Output file**: `{backup_root}/scan-results/agent-5-timestamps.md`

Instructions for agent:
1. Read the input JSON file
2. Compare core file modification dates against the WP version's known release date
3. Analyze modification clusters to identify potential compromise windows
4. Look for bulk-modification patterns (many files with identical timestamps)
5. Write a timeline of suspicious activity with date ranges and affected file groups to the output file

**Output format** (timeline, not findings list — target under 6,000 chars):
```
| Date/Range | Event | Files Affected | Significance |
|------------|-------|----------------|--------------|
```

### Agent 5b: Error Log Analysis

**Input file**: `{backup_root}/prescan-data/error-logs.json`
**Output file**: `{backup_root}/scan-results/agent-5b-error-logs.md`

Instructions for agent:
1. Read the input JSON file. If `log_files_found` is 0, write a brief "No error logs found" report and return
2. Prioritize `auth_manipulation` entries as highest-value evidence — in the reference scan, IOC-3 (wp_set_password injection) was discovered only through error log analysis
3. Count repeated `auth_event` entries over short time windows (minutes/hours) — this pattern indicates active backdoor usage
4. Cross-reference `file_ref` paths across categories — the same PHP file appearing in multiple security categories is highly suspicious
5. Use the `timeline` array to build a chronological narrative of compromise activity
6. Note that `file_ref` contains absolute server paths (e.g., `/var/www/html/...`), not backup-relative paths
7. Note that security plugin paths (wordfence, malcare, sucuri) may trigger patterns legitimately — flag but do not rate as critical without corroborating evidence
8. Write findings table + timeline table + brief notes, target under 6,000 chars

**Output format**:
```
# Agent 5b: Error Log Analysis

## Security Findings

| # | Severity | Category | Pattern | File Reference | Detail |
|---|----------|----------|---------|----------------|--------|

## Timeline

| Timestamp | Category | Pattern | File | Message (truncated) |
|-----------|----------|---------|------|---------------------|

## Notes
[Brief analysis notes — cross-category correlations, backdoor usage windows, etc.]
```

---

## Phase 3: Database Analysis

Launch the following sub-agents **in parallel**. Both agents read from the same input file but focus on different sections. Remind each agent of the output budget rule: 7,500 char limit per Write call, use `cat >>` appends with `<<'SCANEOF'` if larger, structured tables not prose.

### Agent 6: Database Content Analysis

**Input file**: `{backup_root}/prescan-data/database.json`
**Output file**: `{backup_root}/scan-results/agent-6-db-content.md`

Instructions for agent:
1. Read the input JSON file. Focus on the `content_matches` and `snippets` arrays for each SQL dump
2. Review each content match and assess whether it is truly injected malware or legitimate plugin data
3. For script tags, determine if they are ad injections, SEO spam, redirect scripts, or other malware
4. If code snippets exist, review each for malicious intent
5. Write a severity-rated list of confirmed database injections with context to the output file

### Agent 7: Database Structural Audit

**Input file**: `{backup_root}/prescan-data/database.json` (also read `{backup_root}/prescan-data/discovery.json` for plugin inventory)
**Output file**: `{backup_root}/scan-results/agent-7-db-structure.md`

Instructions for agent:
1. Read both input files. Focus on `users`, `admin_users`, `options`, `cron_data`, and `create_tables` from the database JSON
2. Review all admin accounts and flag suspicious ones (random usernames, suspicious email domains, recently created)
3. Check siteurl/home for hijacking, active_plugins for unknown plugins, template/stylesheet for theme tampering
4. Parse the cron data and flag unrecognized scheduled events
5. Compare the CREATE TABLE list against standard WP tables plus known plugin tables, flag unknown tables
6. Write findings grouped by category with severity ratings to the output file

---

## Phase 4: Vulnerability Assessment

After Phase 2-3 agents complete, read all `scan-results/agent-*.md` files and compile a brief **compromise evidence summary**:
- Types of malware found (backdoors, webshells, uploaders, spam, miners, etc.)
- Suspicious file locations (e.g., PHP in uploads/)
- Rogue admin accounts or user creation code
- Injected content types (redirects, SEO spam, iframes, etc.)
- Error log evidence (auth manipulation, backdoor usage timestamps, code injection indicators)
- Estimated compromise date range from timestamps

If no malware or suspicious findings were found in Phases 2-3, still proceed with vulnerability checks but note the clean status.

Launch the following agents. Remind each of the output budget rule: 7,500 char limit per Write call, use `cat >>` appends with `<<'SCANEOF'` if larger, structured tables not prose.

### Agent 8: WordPress Core CVE Check

**Output file**: `{backup_root}/scan-results/agent-8-wp-core-cves.md`

Instructions for agent (include the WP version and compromise evidence summary in the prompt):
1. Use WebSearch to look up known CVEs for the installed WordPress version. Suggested query: `WordPress {version} CVE vulnerabilities` — try sites like wpscan.com and patchstack.com but adapt the query if results are sparse. **Query safety**: The version string comes from the backup and has been sanitized by the pre-scanner. If it still looks unusual (not a simple `X.Y.Z` format), use only the numeric portion
2. Report: the current latest WordPress release, whether the installed version is up to date
3. For each known CVE: ID, CVSS score, vulnerability type (RCE, SQLi, XSS, auth bypass, file upload, privilege escalation, etc.), brief description
4. **Correlation**: flag any CVEs whose vulnerability type matches the compromise evidence
5. Write findings to the output file

### Agents 9+: Plugin CVE Checks (parallel, batched 3-4 per agent)

Batch plugins 3-4 per agent. Each agent receives: plugin slugs, installed versions, and the compromise evidence summary.

**Output file**: `{backup_root}/scan-results/agent-9-plugin-cves-batch-{N}.md`

**Query safety**: Plugin slugs and versions come from the backup and have been sanitized by the pre-scanner (alphanumeric, hyphens, underscores only; length-limited). Before constructing a search query, verify each slug looks like a legitimate WordPress slug (lowercase, hyphen-separated words, e.g., `contact-form-7`). If a slug looks suspicious (random characters, very long, or nonsensical), skip the web search for that plugin and note it as "slug not searchable" in the output.

Instructions for each agent:
1. Use WebSearch once per plugin to find known CVEs. Use ONLY the sanitized slug in queries — never use the display name. Suggested query: `{plugin_slug} WordPress plugin vulnerability CVE` — try wpscan.com and patchstack.com but adapt if results are sparse
2. Do NOT use WebFetch unless search results contain nothing useful for a plugin
3. Use this exact table format for output:

```
# Plugin CVE Batch {N}

| CVE | CVSS | Type | Affected Versions | Fixed | Entry Point? |
|-----|------|------|-------------------|-------|--------------|
```

   **Entry Point** column: YES/NO + short phrase (max 10 words) linking to compromise evidence. This is the most important column.
   If a plugin has many CVEs, include only the 5 highest-CVSS entries.
4. Write findings to the output file. Target: under 6,000 chars total for a 3-4 plugin batch. Use Write if under 7,500 chars, otherwise `cat >` / `cat >>` appends with `<<'SCANEOF'`.

---

## Phase 5: Reporting

After all agents complete, read all files in `{backup_root}/scan-results/` to collect full findings.

### Step 1: Launch a single report-writing agent

Launch one sub-agent (subagent_type: "general-purpose") to compile the full report.

**Output file**: `{backup_root}/malware-scan-report.md`

**CRITICAL**: The combined report will exceed 7,500 chars. The agent MUST write it in sequential chunks using `cat` appends — never a single Write call.

Instructions for the report agent:

**Phase A — Read inputs:**
1. Use Glob to find all `{backup_root}/scan-results/agent-*.md` files
2. Read all agent files and `{backup_root}/prescan-data/discovery.json` (use parallel Read calls, 3-4 per turn)

**Phase B — Write report in chunks** (each chunk under 7,500 chars, using `<<'SCANEOF'` delimiter):

**Chunk 1** (`cat > {output_file} <<'SCANEOF'`): Report header + Summary + Vulnerability Assessment
```
# WordPress Malware Scan Report

## Summary

| Check | Severity | Verdict | Key Findings |
|-------|----------|---------|--------------|
| PHP Backdoors & Obfuscation | Critical/High/Medium/Low/Info | CLEAN/SUSPICIOUS | Brief |
| Suspicious Files & Locations | ... | ... | ... |
| Core File Integrity | ... | ... | ... |
| Theme & WP-Content Malware | ... | ... | ... |
| File Timestamps | ... | ... | ... |
| Error Log Analysis | ... | ... | ... |
| Database Content | ... | ... | ... |
| Database Structure | ... | ... | ... |

## Vulnerability Assessment

| Component | Version | Known CVEs | Status |
|-----------|---------|-----------|--------|
| WordPress Core | x.x.x | CVE-XXXX-XXXXX (CVSS X.X) | VULNERABLE/SAFE |
| Plugin Name | x.x.x | CVE-XXXX-XXXXX (CVSS X.X) | VULNERABLE/SAFE |
```

**Chunk 2** (`cat >> {output_file} <<'SCANEOF'`): Likely Entry Points + Plugin Inventory
```
## Likely Entry Points
[CVEs matching compromise evidence, ranked by likelihood — terse bullets]

## Plugin Inventory

| Plugin | Version | Status | Risk Flags |
|--------|---------|--------|------------|
```

**Chunk 3** (`cat >> {output_file} <<'SCANEOF'`): Detailed Findings — agents 1-3
```
## Detailed Findings

### PHP Backdoors & Obfuscation
[Condensed key findings from agent 1]

### Suspicious Files & Locations
[Condensed key findings from agent 2]

### Core File Integrity
[Condensed key findings from agent 3]
```

**Chunk 4** (`cat >> {output_file} <<'SCANEOF'`): Detailed Findings — agents 4-7
```
### Theme & WP-Content Malware
[Condensed key findings from agent 4]

### File Timestamps
[Condensed key findings from agent 5]

### Error Log Analysis
[Condensed key findings from agent 5b — auth manipulation, backdoor usage, code injection indicators]

### Database Content
[Condensed key findings from agent 6]

### Database Structure
[Condensed key findings from agent 7]
```

**Chunk 5** (`cat >> {output_file} <<'SCANEOF'`): Compromise Timeline + Recommendations
```
## Compromise Timeline
[Correlated timeline from file timestamps, error log timeline data, database evidence, user creation dates]

## Recommendations
[Actionable remediation and hardening steps]
```

**Rules:**
- Each chunk MUST be under 7,500 characters. If a chunk would exceed this, split it into sub-chunks.
- For Detailed Findings: provide condensed summaries (key findings only, not full reproduction of agent reports). The full agent files are available for reference.
- After all chunks are written, return ONLY a one-line summary with the overall verdict and finding counts.

### Step 2: Print summary to conversation (orchestrator)

After the report agent finishes, print ONLY a brief summary to the conversation:
- Overall verdict (COMPROMISED / LIKELY CLEAN / INCONCLUSIVE)
- Count of Critical, High, Medium, Low, Info findings
- Top likely entry points (if compromised)
- Path to the full report file

---

## Error Handling

- **Pre-scanner failed**: If `wp-prescan-results.json` doesn't exist or is malformed, report the error and stop
- **Agent fails or returns empty**: Note the failure in the report, continue with remaining agents
- **WebSearch returns no results**: Try an alternative query without site restrictions. If still empty, note "No CVE data found" for that component and move on
- **Truncated files**: If the pre-scanner truncated a file (look for `[TRUNCATED at` markers), the agent reviewing that section should use the Read tool to load the full file from disk
