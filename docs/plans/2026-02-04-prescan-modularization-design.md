# Pre-scanner Modularization Design

## Problem

`wp-malware-prescan.py` is a 1302-line monolithic script. All constants, helpers, scanners, and orchestration live in one file. This makes it hard to navigate, test individual scan functions, and extend with new scan sections (SCAN-02, SCAN-03, etc.) without the file growing further.

## Approach

Extract the script into a `prescan/` package with modules organized by responsibility. Keep the existing `wp-malware-prescan.py` as a thin entry point so SKILL.md doesn't change.

## File Structure

```
wp-malware-scan/
  wp-malware-prescan.py          — 3-line entry point shim (unchanged path)
  prescan/
    __init__.py                  — exports main()
    scanner.py                   — main() orchestration: discovery → scans → output (~150 lines)
    constants.py                 — all pattern lists, config values, limits, known
                                   filenames, table sets (~230 lines)
    utils.py                     — is_legitimate_path, is_within_root, truncate_content,
                                   redact_wp_config, redact_email, sanitize_slug/version/name,
                                   write_section (~80 lines)
    discovery.py                 — find_wp_root, get_wp_version, get_plugin_info,
                                   get_theme_info, find_sql_dumps, discover_log_files (~120 lines)
    scanners/
      __init__.py
      php_patterns.py            — scan_php_patterns (~85 lines)
      suspicious_files.py        — scan_suspicious_files (~100 lines)
      core_files.py              — read_core_files (~40 lines)
      themes.py                  — read_theme_functions (~20 lines)
      timestamps.py              — analyze_timestamps (~55 lines)
      error_logs.py              — parse_log_entry, scan_error_logs (~175 lines)
      database.py                — scan_sql_dump (~150 lines)
```

## Entry Point

`wp-malware-prescan.py` becomes:

```python
#!/usr/bin/env python3
from prescan import main
main()
```

SKILL.md continues to call `python3 ~/.claude/skills/wp-malware-scan/wp-malware-prescan.py "$ARGUMENTS"` — no change needed.

## Module Boundaries

- **constants.py**: All `UPPER_CASE` globals — pattern lists, regex objects, sets, limits. No functions. Every other module imports from here.
- **utils.py**: Pure helper functions with no scan logic. Used by multiple scanners.
- **discovery.py**: Functions that locate things (WP root, plugins, themes, SQL dumps, log files) but don't analyze content.
- **scanners/*.py**: Each module exports a single scan function (or two for error_logs). Each takes `wp_root` (and sometimes additional args) and returns a dict of findings. Each is independently testable.
- **scanner.py**: Calls discovery, then each scanner, then writes output. Same flow as current `main()`.

## Key Design Decisions

- **Thin entry point shim**: Preserves the existing invocation path. No changes to SKILL.md.
- **`scanners/` subpackage**: Groups the 7 scan modules together, keeping the top-level `prescan/` package clean. Each scanner is a clear unit of work.
- **Constants separated from code**: Pattern lists are ~230 lines of data. Isolating them makes both the patterns and the scan logic easier to read and modify.
- **No class hierarchy**: Functions are the right abstraction here. Each scanner is a single function, not an object. No need for a `BaseScanner` class.

## Testability

Each scanner module can be unit tested by:
1. Creating a minimal fixture directory with known files
2. Calling the scanner function directly
3. Asserting on the returned dict structure

`constants.py` patterns can be tested with targeted regex match/no-match assertions.

## Migration

Purely mechanical refactoring — move code, add imports, verify output is identical. Run the script against an existing backup and diff the JSON output before/after to confirm no behavioral changes.
