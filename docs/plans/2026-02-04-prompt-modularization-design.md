# Prompt Modularization Design

## Problem

`prompt.md` is a 361-line monolithic file loaded entirely into the orchestrator's input context for every turn of a multi-phase scan session. Most content is irrelevant to the current phase — e.g., Phase 5 report formatting instructions consume tokens while the orchestrator is launching Phase 2 agents.

## Approach

Split prompt.md into per-phase files with a shared preamble. The orchestrator reads only `preamble.md` + the current phase file, reducing input tokens by ~60-90% per turn. Merge current Phases 2+3 since agents 1-7 have no dependencies on each other and can all launch in parallel.

## File Structure

```
prompts/
  preamble.md           — env constraints, output budget rule, standard output
                          format template, chunked-write instructions, one-line
                          summary return rule (~15 lines, ~150 tokens)
  phase-1-prepare.md    — read prescan index, create scan-results dir, WP version
                          release date lookup (~20 lines)
  phase-2-analysis.md   — agents 1-7: PHP patterns, suspicious files, core
                          integrity, themes, timestamps, error logs, DB content,
                          DB structure — all launched in parallel (~155 lines)
  phase-3-vulns.md      — agents 8-9+: WP core CVEs, plugin CVE batches. Depends
                          on Phase 2 results for compromise evidence summary (~50 lines)
  phase-4-report.md     — report compiler agent with chunked output template,
                          orchestrator summary print (~110 lines)
  error-handling.md     — error scenarios and recovery (~7 lines)
```

## SKILL.md Changes

Update Step 2 to instruct the orchestrator:

1. Read `prompts/preamble.md` (once, keep in context throughout)
2. Read and execute `prompts/phase-1-prepare.md`
3. Read and execute `prompts/phase-2-analysis.md` (launch agents 1-7 in parallel)
4. After Phase 2 agents complete, read and execute `prompts/phase-3-vulns.md`
5. After Phase 3 agents complete, read and execute `prompts/phase-4-report.md`
6. On any error, read `prompts/error-handling.md`

## Key Design Decisions

- **Per-phase granularity, not per-agent**: Agents within a phase launch in parallel in a single orchestrator turn, so the orchestrator needs all agent definitions for that phase at once. Per-agent files would require multiple Read calls with no token savings.
- **Merged Phases 2+3**: Current Phase 3 (DB agents 6-7) has no dependency on Phase 2 (filesystem agents 1-5b). Merging them lets all 7 agents run in parallel, reducing total scan latency.
- **Shared preamble**: Extracts the output budget rule (currently repeated 5 times), standard output format template, and chunked-write instructions into one file read once.
- **prompt.md deleted**: Replaced entirely by the `prompts/` directory.

## Token Impact

| Phase | Current (full prompt.md) | After split (preamble + phase) |
|-------|--------------------------|-------------------------------|
| Phase 1 | ~3,600 tokens | ~170 tokens |
| Phase 2 | ~3,600 tokens | ~1,350 tokens |
| Phase 3 | ~3,600 tokens | ~650 tokens |
| Phase 4 | ~3,600 tokens | ~1,100 tokens |
| Phase 5 | ~3,600 tokens | ~260 tokens |
