## Phase 1: Read Pre-scan Index and Prepare

Read `wp-prescan-results.json` from the output directory (`{output_root}/wp-prescan-results.json`). This is a lightweight index containing:
- **`_meta`**: backup path, WP root path, scan time
- **`discovery`**: WP version, plugin/theme/mu-plugin inventories, SQL dump paths
- **`section_files`**: paths to per-section JSON files in `prescan-data/`
- **`summary`**: counts of suspicious findings for quick triage

The detailed data lives in separate files under `prescan-data/`. Each sub-agent should use the Read tool to load only the section file it needs — do NOT paste raw JSON into agent prompts.

Create the scan-results directory:
```bash
mkdir -p {output_root}/scan-results
```

**WP Version Release Date Lookup**: Use WebSearch to find the official release date of the WordPress version identified above. Suggested query: `WordPress {version} release date site:wordpress.org`. Extract the exact release date. You will pass this to Agent 5 in Phase 2. If no result is found, note the release date as "unknown".
