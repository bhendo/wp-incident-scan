## Phase 3: Vulnerability Assessment

After Phase 2 agents complete, read all `scan-results/agent-*.md` files and compile a brief **compromise evidence summary**:
- Types of malware found (backdoors, webshells, uploaders, spam, miners, etc.)
- Suspicious file locations (e.g., PHP in uploads/)
- Rogue admin accounts or user creation code
- Injected content types (redirects, SEO spam, iframes, etc.)
- Error log evidence (auth manipulation, backdoor usage timestamps, code injection indicators)
- Estimated compromise date range from timestamps

If no malware or suspicious findings were found in Phase 2, still proceed with vulnerability checks but note the clean status.

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
