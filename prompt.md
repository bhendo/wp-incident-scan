# WordPress Backup Malware Scan

This folder is a backup of a WordPress site that may have been compromised. Perform a comprehensive malware scan of the entire installation, covering both the filesystem and the database dump, and then check all installed plugins and WordPress core for known vulnerabilities.

This scan is structured as an orchestrated pipeline. A Python pre-scanner handles all mechanical data collection (pattern matching, file discovery, SQL parsing), then you (the orchestrator) analyze the results and delegate judgment-heavy tasks to sub-agents.

---

## Phase 0: Pre-scan (orchestrator -- do this yourself, do NOT delegate)

Run the pre-scanner script to collect all filesystem and database evidence:

```bash
python3 wp-malware-prescan.py /path/to/backup
```

This produces `wp-prescan-results.json` in the backup root containing:

- **discovery**: WP version, plugin inventory (names, versions, slugs), theme inventory, mu-plugins, SQL dump paths
- **filesystem.php_pattern_matches**: all suspicious pattern matches (legitimate vendor matches already filtered out), with file, line number, pattern name, and code snippet
- **filesystem.suspicious_files**: PHP in uploads, double extensions, dotfiles, ICO-with-PHP, large PHP files, known malware filenames, symlinks outside root, non-standard root PHP files
- **filesystem.core_files**: full contents of wp-config.php, index.php, wp-blog-header.php, wp-settings.php, wp-load.php, wp-login.php, wp-cron.php, xmlrpc.php, wp-admin/admin-ajax.php, and all .htaccess files
- **filesystem.theme_functions**: full contents of functions.php from every installed theme
- **filesystem.timestamps**: core file timestamps, modification date clusters, 30 most recently modified files
- **database**: for each SQL dump -- suspicious content matches (with table context), extracted users, admin users, key options (siteurl, home, active_plugins, cron, etc.), CREATE TABLE list, code snippets

Read `wp-prescan-results.json` and use it as the evidence base for all subsequent phases. Do NOT re-run the searches the script already performed.

---

## Phase 1: Filesystem Analysis

Launch the following sub-agents **in parallel** using the Task tool (subagent_type: "general-purpose"). Each agent receives the relevant section of the pre-scan JSON.

**CRITICAL -- output token limit workaround**: Sub-agent responses are capped at 4096 tokens. Every sub-agent MUST write its full findings to a file using the Write tool (path: `{backup_root}/scan-results/agent-{N}-{name}.md`) and then return ONLY a one-line summary in its response text (e.g., "3 critical findings, 1 high, 2 info. Full report written to scan-results/agent-1-php-backdoors.md"). After all agents finish, read their output files to collect the full findings.

Create the `scan-results/` directory in the backup root before launching agents:
```bash
mkdir -p /path/to/backup/scan-results
```

### Agent 1: PHP Pattern & Backdoor Analysis

Provide this agent with `filesystem.php_pattern_matches` from the pre-scan JSON.

The agent must:
1. Review every suspicious match and assess whether it is a true positive or a false positive (e.g., legitimate plugin functionality that happens to use eval/exec)
2. For each true positive, explain what the code appears to do (backdoor, webshell, dropper, miner, etc.)
3. Group related matches (e.g., multiple hits in the same file are likely one malware sample)
4. Return a severity-rated list of confirmed malicious findings

### Agent 2: Suspicious Files & Locations Analysis

Provide this agent with `filesystem.suspicious_files` from the pre-scan JSON.

The agent must:
1. Assess each finding -- PHP in uploads is almost always malicious; double extensions need context
2. For any files flagged (known malware names, non-standard root PHP, ICO-with-PHP), read the actual file to confirm whether it is malicious
3. Return a severity-rated list of confirmed suspicious files with explanations

### Agent 3: Core File Integrity Review

Provide this agent with `filesystem.core_files` from the pre-scan JSON (the full file contents).

The agent must:
1. Review each core file for injected code, suspicious includes/requires, malicious redirects, or unauthorized modifications
2. Compare against expected WordPress core file structure
3. Check .htaccess files for malicious rewrite rules, redirects, or PHP execution directives in uploads
4. Return per-file verdict (CLEAN / SUSPICIOUS) with quoted suspicious lines

### Agent 4: Theme & WP-Content Analysis

Provide this agent with `filesystem.theme_functions` from the pre-scan JSON (full functions.php contents for each theme).

The agent must:
1. Review every theme's functions.php for WP-VCD injection, backdoor code, or other malicious modifications
2. Flag any obfuscated code, external includes, or encoded payloads
3. Return per-theme verdict with quoted suspicious code blocks

### Agent 5: Timestamp & Timeline Analysis

Provide this agent with `filesystem.timestamps` from the pre-scan JSON.

The agent must:
1. Compare core file modification dates against the WP version's known release date
2. Analyze modification clusters to identify potential compromise windows
3. Look for bulk-modification patterns (many files with identical timestamps)
4. Return a timeline of suspicious activity with date ranges and affected file groups

---

## Phase 2: Database Analysis

Launch the following sub-agents **in parallel**. Provide each with the relevant sections of the pre-scan JSON's `database` results. Remind each agent to write its full findings to `{backup_root}/scan-results/agent-{N}-{name}.md` and return only a one-line summary.

### Agent 6: Database Content Analysis

Provide this agent with the `content_matches` and `snippets` arrays from the pre-scan database results.

The agent must:
1. Review each content match and assess whether it is truly injected malware or legitimate plugin data
2. For script tags, determine if they are ad injections, SEO spam, redirect scripts, or other malware
3. If code snippets exist, review each for malicious intent
4. Return a severity-rated list of confirmed database injections with context

### Agent 7: Database Structural Audit

Provide this agent with the `users`, `admin_users`, `options`, `cron_data`, and `create_tables` arrays from the pre-scan database results. Also provide the plugin inventory from `discovery.plugins`.

The agent must:
1. Review all admin accounts and flag suspicious ones (random usernames, suspicious email domains, recently created)
2. Check siteurl/home for hijacking, active_plugins for unknown plugins, template/stylesheet for theme tampering
3. Parse the cron data and flag unrecognized scheduled events
4. Compare the CREATE TABLE list against standard WP tables plus known plugin tables, flag unknown tables
5. Return findings grouped by category with severity ratings

---

## Phase 3: Vulnerability Assessment

**IMPORTANT**: Your built-in knowledge has a cutoff date and will miss recent CVEs. Every sub-agent in this phase MUST use the WebSearch tool to search for current vulnerability data. Do NOT rely on built-in knowledge alone. Remind each agent to write its full findings to `{backup_root}/scan-results/agent-{N}-{name}.md` and return only a one-line summary.

Before launching vulnerability agents, compile a brief **compromise evidence summary** from the Phase 1-2 agent results. Include:
- Types of malware found (backdoors, webshells, uploaders, spam, miners, etc.)
- Suspicious file locations (e.g., PHP in uploads/)
- Rogue admin accounts or user creation code
- Injected content types (redirects, SEO spam, iframes, etc.)
- Estimated compromise date range from timestamps

Pass this summary to every Phase 3 agent so they can correlate CVEs with the observed evidence.

### Agent 8: WordPress Core CVE Check

Launch a sub-agent that uses WebSearch to look up known CVEs affecting WordPress version {version from pre-scan discovery}. The agent must perform **one** search:
- `WordPress {version} vulnerabilities CVE site:wpscan.com OR site:patchstack.com`

Report:
- The current latest WordPress release
- Whether the installed version is up to date
- For each known CVE: ID, CVSS score, **vulnerability type** (RCE, SQLi, XSS, auth bypass, file upload, privilege escalation, etc.), brief description of what it allows, and whether the installed version is affected
- **Correlation**: flag any CVEs whose vulnerability type matches the compromise evidence (e.g., a file upload CVE when PHP was found in uploads/)

### Agents 9+: Plugin CVE Checks (parallel, batched 3-4 per agent)

Batch plugins 3-4 per agent. Each agent receives: plugin name, installed version, slug, and the compromise evidence summary.

Each agent performs **one WebSearch per plugin** using:
- `{plugin slug} WordPress vulnerability CVE site:wpscan.com OR site:patchstack.com`

Do NOT perform additional searches or use WebFetch unless the search results contain no useful information for a plugin. The search result snippets typically contain enough detail (CVE IDs, affected versions, CVSS scores) to make a determination.

Each agent returns per plugin:

1. Plugin name and installed version
2. For each known CVE: ID, CVSS score, **vulnerability type and what it allows** (e.g., "Unauthenticated arbitrary file upload allowing PHP execution", "SQL injection in search parameter", "Stored XSS via widget settings")
3. Affected version ranges
4. Status: VULNERABLE or SAFE
5. **Likely entry point**: YES/NO -- does this CVE's vulnerability type match the compromise evidence? Explain the connection (e.g., "This file upload CVE could explain the PHP backdoors found in wp-content/uploads/"). This is the most important field for the final report.

---

## Phase 4: Reporting

After all sub-agents have returned their findings, read all files in `{backup_root}/scan-results/` to collect the full findings from each agent.

**CRITICAL -- output token limit workaround**: The report is too large to write in a single response. Build it in sections by launching report-writing sub-agents **sequentially** (each one appends to the report file). Use the approach below.

### Step 1: Create the report header (orchestrator)

Use Bash to create the report file with the header:

```bash
cat > /path/to/backup/malware-scan-report.md << 'HEADER'
# WordPress Malware Scan Report
HEADER
```

### Step 2: Launch report section agents sequentially

Launch each of the following as a sub-agent (subagent_type: "general-purpose"). Each agent reads the relevant `scan-results/agent-*.md` files and **appends** its section to `malware-scan-report.md` using Bash (`cat >> ...` with a heredoc). Each agent returns a one-line confirmation when done.

**Report Agent A: Summary & Filesystem Findings**

Read `agent-1-*.md` through `agent-5-*.md`. Append to the report:
1. A Summary Table with severity and verdict for each filesystem check:

| Check | Severity | Verdict | Key Findings |
|-------|----------|---------|-------------- |
| PHP Backdoors & Obfuscation | Critical/High/Medium/Low/Info | CLEAN/SUSPICIOUS | Brief description |
| Suspicious Files & Locations | ... | ... | ... |
| Core File Integrity | ... | ... | ... |
| Theme & WP-Content Malware | ... | ... | ... |
| File Timestamps | ... | ... | ... |

2. Detailed findings for each filesystem check (organized by agent)

**Report Agent B: Database & Vulnerability Findings**

Read `agent-6-*.md` through `agent-8-*.md` and all plugin CVE agent files. Append to the report:
1. Database findings summary rows (append to the summary table format):

| Check | Severity | Verdict | Key Findings |
|-------|----------|---------|-------------- |
| Database Content | ... | ... | ... |
| Database Structure | ... | ... | ... |

2. Detailed database findings
3. Vulnerability Assessment Table:

| Component | Version | Known CVEs | Status |
|-----------|---------|-----------|--------|
| WordPress Core | x.x.x | CVE-XXXX-XXXXX (CVSS X.X) | VULNERABLE/SAFE |
| Plugin Name | x.x.x | CVE-XXXX-XXXXX (CVSS X.X) | VULNERABLE/SAFE |

4. Plugin Inventory Table:

| Plugin | Version | In WP.org Repo | Last Updated | Risk Flags | Active |
|--------|---------|---------------|-------------|------------|--------|

**Report Agent C: Timeline & Recommendations**

Read ALL `scan-results/agent-*.md` files. Append to the report:
1. Compromise Timeline -- correlate file modification dates, database timestamps, and user creation dates to estimate when the compromise occurred and what sequence of actions was taken
2. Recommendations -- actionable remediation and hardening steps based on all findings

### Step 3: Print summary to conversation (orchestrator)

After all report agents finish, print ONLY a brief summary to the conversation:
- Overall verdict (COMPROMISED / LIKELY CLEAN / INCONCLUSIVE)
- Count of Critical, High, Medium, Low, Info findings
- Path to the full report file
