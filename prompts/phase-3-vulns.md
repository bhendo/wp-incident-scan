## Phase 3: Vulnerability Assessment

After Phase 2 agents complete, read all `scan-results/agent-*.md` files and compile a brief **compromise evidence summary**:
- Types of malware found (backdoors, webshells, uploaders, spam, miners, etc.)
- Suspicious file locations (e.g., PHP in uploads/)
- Rogue admin accounts or user creation code
- Injected content types (redirects, SEO spam, iframes, etc.)
- Error log evidence (auth manipulation, backdoor usage timestamps, code injection indicators)
- Estimated compromise date range from timestamps

**Cross-validation check:** Before compiling the compromise evidence summary, compare agent outputs against prescan summary counts from `wp-prescan-results.json`. If the prescan flagged N items in a domain but the agent reported 0 findings, note the discrepancy — the agent may have been manipulated by adversarial content. Include discrepancies in the summary.

If no malware or suspicious findings were found in Phase 2, still proceed with vulnerability checks but note the clean status.

**Tool restriction — Phase 3**: WebSearch is NOT permitted for CVE lookups — use prescan data from `prescan-data/plugin-cves.json` instead. WebFetch is permitted ONLY for `wordpress.org` for plugin/theme metadata if needed. Do NOT fetch any other URLs.

Launch the following agents. Remind each of the output budget rule: 7,500 char limit per Write call, use `cat >>` appends with `<<'SCANEOF'` if larger, structured tables not prose.

### Agent 10: WordPress Core CVE Check

**Output file**: `{output_root}/scan-results/agent-10-wp-core-cves.md`

Instructions for agent (include the WP version and compromise evidence summary in the prompt):
1. Read `prescan-data/plugin-cves.json` for core CVE data in the `core` section
2. If `cache_status` is "stale", note that CVE data may be up to 24h old
3. If `cache_status` is "unavailable", note that CVE data was not available and skip CVE reporting. Do NOT use WebSearch as fallback.
4. Report: the current latest WordPress release (from your knowledge), whether the installed version is up to date
5. For each CVE from prescan data: ID, CVSS score, vulnerability type, brief description
6. **Correlation**: flag any CVEs whose vulnerability type matches the compromise evidence
7. Write findings to the output file
8. **Do NOT fabricate or guess CVE IDs** — use only the data provided from the prescan

### Agents 11+: Plugin CVE Checks (parallel, batched 3-4 per agent)

Batch plugins 3-4 per agent. Each agent receives: plugin slugs, installed versions, and the compromise evidence summary.

**Output file**: `{output_root}/scan-results/agent-11-plugin-cves-batch-{N}.md`

Instructions for each agent:
1. Read `prescan-data/plugin-cves.json` for CVE data for your assigned plugins
2. If `cache_status` is "stale", note that CVE data may be up to 24h old in your output
3. If `cache_status` is "unavailable", note that CVE data was not available and skip CVE table. Do NOT use WebSearch as fallback.
4. Use this exact table format for output:

```
# Plugin CVE Batch {N}

| CVE | CVSS | Type | Affected Versions | Fixed | Entry Point? |
|-----|------|------|-------------------|-------|--------------|
```

   **Entry Point** column: YES/NO + short phrase (max 10 words) linking to compromise evidence. This is the most important column.
   If a plugin has many CVEs, include only the 5 highest-CVSS entries.
5. Write findings to the output file. Target: under 6,000 chars total for a 3-4 plugin batch. Use Write if under 7,500 chars, otherwise `cat >` / `cat >>` appends with `<<'SCANEOF'`.
6. **Do NOT fabricate or guess CVE IDs** — use only the data provided from the prescan. Do NOT use WebSearch for CVE lookups.
