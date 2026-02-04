"""Scan Wordfence, Sucuri, and other security plugin logs for attack evidence."""

import re
from collections import defaultdict
from pathlib import Path

from prescan.constants import (
    MAX_FILE_READ_SIZE,
    MAX_SECURITY_LOG_ENTRIES,
    MAX_SECURITY_LOG_READ_BYTES,
    MAX_SECURITY_LOG_TOTAL_BYTES,
    SECURITY_LOG_PATTERNS,
)
from prescan.discovery import discover_security_log_dirs


def scan_security_logs(wp_root: Path) -> dict:
    """Discover and scan security plugin log directories."""
    log_dirs = discover_security_log_dirs(wp_root)

    result = {
        'dirs_found': len(log_dirs),
        'dirs': [],
        'total_bytes_read': 0,
        'entries_by_category': defaultdict(list),
        'ip_addresses': defaultdict(int),
    }

    if not log_dirs:
        return result

    total_bytes = 0
    entry_count = 0

    for dir_info in log_dirs:
        dir_record = {
            'rel_path': dir_info['rel_path'],
            'plugin_name': dir_info['plugin_name'],
            'file_count': dir_info['file_count'],
            'total_size': dir_info['total_size'],
            'files_scanned': 0,
            'entries_found': 0,
        }

        for file_info in dir_info['files']:
            if total_bytes >= MAX_SECURITY_LOG_TOTAL_BYTES:
                break
            if entry_count >= MAX_SECURITY_LOG_ENTRIES:
                break

            file_path = Path(file_info['path'])
            file_size = file_info['size']

            if file_size > MAX_FILE_READ_SIZE:
                continue
            if file_size == 0:
                continue

            try:
                if file_size > MAX_SECURITY_LOG_READ_BYTES:
                    with open(file_path, 'rb') as f:
                        f.seek(file_size - MAX_SECURITY_LOG_READ_BYTES)
                        f.readline()  # skip partial line
                        raw = f.read().decode('utf-8', errors='replace')
                    bytes_read = MAX_SECURITY_LOG_READ_BYTES
                else:
                    raw = file_path.read_text(errors='replace')
                    bytes_read = file_size

                total_bytes += bytes_read
            except (PermissionError, OSError):
                continue

            dir_record['files_scanned'] += 1

            for line in raw.split('\n'):
                if not line.strip():
                    continue
                if entry_count >= MAX_SECURITY_LOG_ENTRIES:
                    break

                for category, patterns in SECURITY_LOG_PATTERNS.items():
                    matched = False
                    for pat_re, pat_name in patterns:
                        if re.search(pat_re, line, re.I):
                            entry = {
                                'log_dir': dir_info['rel_path'],
                                'plugin': dir_info['plugin_name'],
                                'file': file_info['rel_path'],
                                'pattern': pat_name,
                                'content': line.strip()[:500],
                            }

                            # Extract IP addresses
                            ip_match = re.search(
                                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line
                            )
                            if ip_match:
                                ip = ip_match.group(1)
                                entry['ip'] = ip
                                result['ip_addresses'][ip] += 1

                            result['entries_by_category'][category].append(entry)
                            entry_count += 1
                            dir_record['entries_found'] += 1
                            matched = True
                            break
                    if matched:
                        break

        result['dirs'].append(dir_record)

    result['total_bytes_read'] = total_bytes
    result['entries_by_category'] = dict(result['entries_by_category'])
    result['ip_addresses'] = dict(
        sorted(result['ip_addresses'].items(), key=lambda x: x[1], reverse=True)[:50]
    )

    return result
