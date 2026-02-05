---
name: wp-incident-scan
description: Scan a WordPress backup for malware, backdoors, and known vulnerabilities
allowed-tools: Bash(python3 ~/.claude/skills/wp-incident-scan/wp-incident-prescan.py *), Bash(mkdir -p *-scan-output/scan-results), Bash(cat *-scan-output/scan-results/*.chunk-*.md > *-scan-output/scan-results/*.md), Bash(cat *-scan-output/scan-results/report.chunk-*.md > *-scan-output/incident-scan-report.md), Read, Write, Edit, Glob, Grep, Task, WebSearch, WebFetch
argument-hint: /path/to/wordpress/backup
disable-model-invocation: true
---

# WordPress Incident Scan

Scan the WordPress backup at the path provided by the user: `$ARGUMENTS`

If no path was provided, ask the user for the path to the WordPress backup directory.

## Step 1: Run the pre-scanner

```bash
python3 ~/.claude/skills/wp-incident-scan/wp-incident-prescan.py "$ARGUMENTS"
```

The prescan prints the path to `wp-prescan-results.json` on stdout. Read that file and extract `_meta.output_dir` — this is where all scan output will be written. Use this as `{output_root}` when reading prompts. The backup path (`$ARGUMENTS`) remains `{backup_root}`.

## Step 2: Follow the modular scan prompts

The scan instructions are split into per-phase files under `prompts/`. Read them sequentially:

1. Read [prompts/preamble.md](prompts/preamble.md) — shared constraints and output format. Keep these rules in context throughout all phases.
2. Read and execute [prompts/phase-1-prepare.md](prompts/phase-1-prepare.md) — read the prescan index, create output dir, look up WP version release date.
3. Read and execute [prompts/phase-2-analysis.md](prompts/phase-2-analysis.md) — launch agents 1-7 in parallel (filesystem, logs, and database analysis).
4. After Phase 2 agents complete, read and execute [prompts/phase-3-vulns.md](prompts/phase-3-vulns.md) — launch CVE check agents.
5. After Phase 3 agents complete, read and execute [prompts/phase-4-report.md](prompts/phase-4-report.md) — compile final report.
6. On any error, read [prompts/error-handling.md](prompts/error-handling.md) for recovery instructions.

Each agent should read its corresponding per-section JSON file from the `prescan-data/` directory rather than receiving raw JSON in its prompt.
