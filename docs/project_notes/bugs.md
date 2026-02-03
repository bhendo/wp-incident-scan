# Bug Log

Track bugs encountered and their solutions for future reference.

## Entries

### BUG-01: Sub-agents exceed 4096 output token limit and fail silently [HIGH]

- **Date**: 2026-02-03
- **Status**: Open
- **Component**: `prompt.md` — all sub-agents, especially Plugin CVE batch agents and Report Compiler
- **Environment**: Bedrock API with `CLAUDE_CODE_MAX_OUTPUT_TOKENS=4096`, `MAX_THINKING_TOKENS=1024`
- **Symptoms**: Agents 15 (Plugin CVE Batch 7), 16 (Plugin CVE Batch 8), and the Final Report Compiler all failed with API errors. The model response exceeded 4096 tokens, truncating mid-JSON and preventing tool calls from executing. Agents that attempted Write tool calls with large report content never completed the write — all work was lost.
- **Root cause**: Each model turn (including thinking + tool call JSON) is capped at 4096 tokens total. With 1024 tokens reserved for thinking, only ~3072 tokens (~8,000-12,000 characters) remain for the visible response. A Write tool call encodes the entire file content in the response JSON, so any report exceeding ~8,000 characters causes truncation. The current prompt says "write findings to file, return a one-line summary" but this doesn't help because the Write call itself is what exceeds the limit — the agent never gets to the summary step.
- **Affected agents**: Plugin CVE batch agents (verbose CVE descriptions), Report Compiler (reads 18 agent files and writes a combined report). All agents are potentially affected.
- **Workaround used**: Plugin CVE agents were retried with stricter instructions to write terse output. Report Compiler was bypassed entirely — the orchestrator wrote the report manually using the Write tool directly (which has the same limit but the report was kept short enough).
- **Partial fix**: PERF-01 (completed 2026-02-03) added a global 7,500-char output budget rule, structured table formats, and `cat >>` chunked-write instructions for all sub-agents. PERF-02 (pending) will restructure the Report Compiler for chunked output.
