## Phase 4: Reporting

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
| Security Plugin Logs | ... | ... | ... |
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

### Security Plugin Logs
[Condensed key findings from agent 5c — attack evidence, attacker IPs, defense gaps. If no security logs: "No security plugin logs found."]

### Database Content
[Condensed key findings from agent 6]

### Database Structure
[Condensed key findings from agent 7]

### Multisite Analysis
[If subsites were detected: condensed findings from agent 7 multisite audit. If no subsites: "Single-site installation — no multisite analysis needed."]
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
