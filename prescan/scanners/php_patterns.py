"""Scan PHP files for suspicious patterns (backdoors, obfuscation, webshells)."""

import re
import sys
from pathlib import Path

from prescan.constants import (
    HIGH_SIGNAL_PATTERNS,
    MAX_FILE_COUNT,
    MAX_FILE_READ_SIZE,
    PHP_EXTENSIONS,
    PHP_SUSPICIOUS_PATTERNS,
    PROGRESS_INTERVAL,
)
from prescan.utils import is_legitimate_path, is_within_root


def scan_php_patterns(wp_root: Path) -> dict:
    """Scan all PHP-like files for suspicious patterns. Classify as legitimate or suspicious."""
    suspicious = []
    legitimate_count = 0
    legitimate_high_signal = []
    files_scanned = 0
    seen_paths = set()
    wp_root_resolved = str(wp_root.resolve())

    skipped_large = 0
    limit_reached = False

    for ext in PHP_EXTENSIONS:
        if limit_reached:
            break
        for php_file in wp_root.rglob(ext):
            try:
                resolved = php_file.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved in seen_paths:
                continue
            if not is_within_root(resolved, wp_root_resolved):
                continue
            seen_paths.add(resolved)

            files_scanned += 1
            if files_scanned % PROGRESS_INTERVAL == 0:
                print(f'    ... {files_scanned} files scanned', file=sys.stderr)
            if files_scanned > MAX_FILE_COUNT:
                print(f'    [!] File count limit reached ({MAX_FILE_COUNT}). Stopping PHP pattern scan.', file=sys.stderr)
                limit_reached = True
                break

            try:
                file_size = php_file.stat().st_size
                if file_size > MAX_FILE_READ_SIZE:
                    skipped_large += 1
                    continue
            except OSError:
                continue

            try:
                content = php_file.read_text(errors='replace')
            except (PermissionError, OSError):
                continue

            rel = str(php_file.relative_to(wp_root))
            is_legit = is_legitimate_path(rel)

            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern, label in PHP_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line):
                        if is_legit:
                            legitimate_count += 1
                            if label in HIGH_SIGNAL_PATTERNS:
                                legitimate_high_signal.append({
                                    'file': rel,
                                    'line': line_num,
                                    'pattern': label,
                                    'content': line.strip()[:200],
                                    'note': 'HIGH-SIGNAL match in vendor/library path — unusual, review recommended',
                                })
                        else:
                            suspicious.append({
                                'file': rel,
                                'line': line_num,
                                'pattern': label,
                                'content': line.strip()[:200],
                            })

    if skipped_large:
        print(f'    [!] Skipped {skipped_large} files exceeding {MAX_FILE_READ_SIZE // (1024 * 1024)}MB size limit', file=sys.stderr)

    return {
        'files_scanned': files_scanned,
        'files_skipped_too_large': skipped_large,
        'file_count_limit_reached': limit_reached,
        'legitimate_matches_omitted': legitimate_count,
        'legitimate_high_signal_matches': legitimate_high_signal,
        'suspicious_matches': suspicious,
    }
