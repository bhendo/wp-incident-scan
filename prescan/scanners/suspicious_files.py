"""Scan for suspicious file locations, names, and attributes."""

import os
import re
import sys
from pathlib import Path

from prescan.constants import (
    KNOWN_MALWARE_FILENAMES,
    MAX_FILE_COUNT,
    PHP_EXTENSIONS,
    PROGRESS_INTERVAL,
    STANDARD_ROOT_PHP,
)


def scan_suspicious_files(wp_root: Path) -> dict:
    """Scan for PHP in uploads, double extensions, known malware names, etc."""
    results = {
        'php_in_uploads': [],
        'double_extensions': [],
        'hidden_dotfiles': [],
        'ico_with_php': [],
        'large_php_files': [],
        'known_malware_names': [],
        'symlinks_outside_root': [],
        'non_standard_root_php': [],
    }

    wp_root_str = str(wp_root.resolve())

    # PHP in uploads (all executable PHP extensions)
    uploads = wp_root / 'wp-content' / 'uploads'
    if uploads.exists():
        for ext in PHP_EXTENSIONS:
            for f in uploads.rglob(ext):
                rel = str(f.relative_to(wp_root))
                if rel not in results['php_in_uploads']:
                    results['php_in_uploads'].append(rel)

    # All files scan
    files_checked = 0
    seen_paths = set()
    for f in wp_root.rglob('*'):
        if f.is_symlink():
            try:
                resolved = f.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)

        if not f.is_file() and not f.is_symlink():
            continue

        files_checked += 1
        if files_checked % PROGRESS_INTERVAL == 0:
            print(f'    ... {files_checked} files checked for suspicious attributes', file=sys.stderr)
        if files_checked > MAX_FILE_COUNT:
            print(f'    [!] File count limit reached ({MAX_FILE_COUNT}). Stopping suspicious file scan.', file=sys.stderr)
            break

        name = f.name
        rel = str(f.relative_to(wp_root))

        # Double extensions
        if name.count('.') >= 2:
            lower = name.lower()
            if re.search(r'\.ph(?:p[57]?|tml|ar)\.\w+$', lower):
                results['double_extensions'].append(rel)
            elif re.search(r'\.(jpg|jpeg|png|gif|bmp|svg|ico|pdf|doc|txt|zip|css|js)\.(ph(?:p[57]?|tml|ar))$', lower):
                results['double_extensions'].append(rel)

        # Hidden dotfiles (not .htaccess)
        if name.startswith('.') and name != '.htaccess':
            results['hidden_dotfiles'].append(rel)

        # .ico with PHP
        if name.endswith('.ico'):
            try:
                head = f.read_bytes()[:256]
                if b'<?php' in head or b'eval(' in head:
                    results['ico_with_php'].append(rel)
            except Exception:
                pass

        # Large PHP
        if name.endswith('.php'):
            try:
                size = f.stat().st_size
                if size > 500_000:
                    results['large_php_files'].append({'file': rel, 'size_kb': round(size / 1024)})
            except Exception:
                pass

        # Known malware filenames
        if name.lower() in KNOWN_MALWARE_FILENAMES:
            results['known_malware_names'].append(rel)

        # Symlinks outside root
        if f.is_symlink():
            try:
                target = str(f.resolve())
                if not (target == wp_root_str or target.startswith(wp_root_str + os.sep)):
                    results['symlinks_outside_root'].append({'link': rel, 'target': target})
            except Exception:
                pass

    # Non-standard root PHP
    for f in wp_root.glob('*.php'):
        if f.name not in STANDARD_ROOT_PHP:
            results['non_standard_root_php'].append(f.name)

    return results
