# wp-incident-scan

WordPress backup incident scanner skill for Claude Code. Scans backups for malware, backdoors, and known vulnerabilities using a Python pre-scanner and multi-agent AI analysis.

## Project Memory System

This project maintains institutional knowledge in `docs/project_notes/` for consistency across sessions.

### Memory Files

- **bugs.md** - Bug log with dates, solutions, and prevention notes
- **decisions.md** - Architectural Decision Records (ADRs) with context and trade-offs
- **key_facts.md** - Project configuration, environment constraints, agent assignments
- **issues.md** - Work log with descriptions and status

### Memory-Aware Protocols

**Before proposing architectural changes:**
- Check `docs/project_notes/decisions.md` for existing decisions
- Verify the proposed approach doesn't conflict with past choices
- If it does conflict, acknowledge the existing decision and explain why a change is warranted

**When encountering errors or bugs:**
- Search `docs/project_notes/bugs.md` for similar issues
- Apply known solutions if found
- Document new bugs and solutions when resolved

**When looking up project configuration:**
- Check `docs/project_notes/key_facts.md` for environment constraints, agent assignments, output structure
- Prefer documented facts over assumptions

**When completing work:**
- Log completed work in `docs/project_notes/issues.md`
- Include date, brief description, and status

**When user requests memory updates:**
- Update the appropriate memory file (bugs, decisions, key_facts, or issues)
- Follow the established format and style (bullet lists, dates, concise entries)
