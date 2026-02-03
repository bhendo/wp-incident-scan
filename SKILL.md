---
name: wp-malware-scan
description: Scan a WordPress backup for malware, backdoors, and known vulnerabilities
allowed-tools: Bash(python3 *), Bash(mkdir *), Bash(cat *)
argument-hint: /path/to/wordpress/backup
---

# WordPress Malware Scan

Scan the WordPress backup at the path provided by the user: `$ARGUMENTS`

If no path was provided, ask the user for the path to the WordPress backup directory.

## Step 1: Run the pre-scanner

```bash
python3 ~/.claude/skills/wp-malware-scan/wp-malware-prescan.py $ARGUMENTS
```

## Step 2: Follow the scan prompt

Read and follow all instructions in [prompt.md](prompt.md), starting from Phase 0. The pre-scanner has already been run -- read the `wp-prescan-results.json` file it produced and continue from there.
