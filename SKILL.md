---
name: wp-malware-scan
description: Scan a WordPress backup for malware, backdoors, and known vulnerabilities
allowed-tools: Bash(python3 *), Bash(mkdir *), Bash(cat *), Read, Write, Edit, Glob, Grep, Task, WebSearch, WebFetch
argument-hint: /path/to/wordpress/backup
disable-model-invocation: true
---

# WordPress Malware Scan

Scan the WordPress backup at the path provided by the user: `$ARGUMENTS`

If no path was provided, ask the user for the path to the WordPress backup directory.

## Step 1: Run the pre-scanner

```bash
python3 ~/.claude/skills/wp-malware-scan/wp-malware-prescan.py "$ARGUMENTS"
```

## Step 2: Follow the scan prompt

Read and follow all instructions in [prompt.md](prompt.md), starting from Phase 1. The pre-scanner has already been run -- read the `wp-prescan-results.json` index file it produced, then continue from there. Each agent should read its corresponding per-section JSON file from the `prescan-data/` directory rather than receiving raw JSON in its prompt.
