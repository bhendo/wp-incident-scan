# wp-incident-scan

A Claude Code skill that scans WordPress backups for malware, backdoors, and known vulnerabilities. It combines a Python pre-scanner (fast, deterministic pattern matching) with multi-agent AI analysis (judgment-based triage and CVE lookups) to produce a structured incident report.

You point it at a WordPress backup directory and it produces a Markdown report covering: PHP backdoors, suspicious files, core file integrity, theme injections, file timeline analysis, error log forensics, security plugin logs, database injections, structural anomalies, and known CVEs for installed plugins and WordPress core.

## Prerequisites

- **Python 3.9+** — no external dependencies, uses only the standard library
- **Claude Code** configured with a Claude model provider

### Bedrock configuration

This skill is designed to work within Amazon Bedrock's 4096 max output token constraint. Sub-agents write findings to files rather than returning them inline, and large reports are written in sequential chunks. To configure Claude Code with Amazon Bedrock, see the [Bedrock setup guide](https://code.claude.com/docs/en/amazon-bedrock#2-configure-aws-credentials).

## Installation

Clone this repo into your Claude Code skills directory:

```
git clone <repo-url> ~/.claude/skills/wp-incident-scan
```

## Usage

From Claude Code, invoke the skill with a path to a WordPress backup:

```
/wp-incident-scan /path/to/wordpress/backup
```

Claude acts as the orchestrator — it runs the pre-scanner, reads the structured prompts, launches parallel sub-agents for analysis, performs CVE lookups, and compiles a final report at `{backup_root}/incident-scan-report.md`.

## How It Works

The scan runs in four phases, orchestrated by Claude:

1. **Pre-scan** — A Python script traverses the backup filesystem and collects structured data: PHP pattern matches, suspicious files, core file contents, theme code, timestamps, error logs, security plugin logs, and database analysis. Output is written as JSON to `prescan-data/`.

2. **Analysis (Agents 1-9)** — Claude launches up to 9 sub-agents in parallel, each analyzing a specific domain (PHP backdoors, suspicious file locations, core integrity, themes, timeline, error logs, security plugin logs, database content, database structure). Each agent reads its JSON input, writes findings to `scan-results/`, and returns a one-line summary.

3. **Vulnerability assessment (Agents 10+)** — After analysis completes, CVE lookup agents search for known vulnerabilities in the installed WordPress version and plugins, correlating against the compromise evidence from Phase 2.

4. **Report** — A report agent compiles all findings into a structured Markdown report with severity ratings, a compromise timeline, likely entry points, and remediation recommendations.

## Output

The scan writes all output into the backup directory:

| Path | Contents |
|------|----------|
| `prescan-data/*.json` | Raw pre-scanner data (9 JSON files) |
| `scan-results/agent-*.md` | Individual agent findings |
| `incident-scan-report.md` | Final compiled report |

The report includes a summary table with per-category severity ratings, a vulnerability assessment with CVE matches, likely entry points, a plugin inventory, detailed findings per agent, a correlated compromise timeline, and remediation recommendations.

**Note:** The scan writes into the backup directory itself. Do not point this at a live WordPress installation — the written files would be web-accessible. For forensic preservation, work on a copy of the backup.
