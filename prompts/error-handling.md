## Error Handling

- **Pre-scanner failed**: If `wp-prescan-results.json` doesn't exist or is malformed, report the error and stop
- **Agent fails or returns empty**: Note the failure in the report, continue with remaining agents
- **WebSearch returns no results**: Try an alternative query without site restrictions. If still empty, note "No CVE data found" for that component and move on
- **Truncated files**: If the pre-scanner truncated a file (look for `[TRUNCATED at` markers), the agent reviewing that section should use the Read tool to load the full file from disk
