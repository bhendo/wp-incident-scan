"""Parse and scan PHP error logs for security-relevant entries."""

import re
from collections import defaultdict
from pathlib import Path

from prescan.constants import (
    LOG_FILE_REF_RE,
    LOG_LEVEL_RE,
    LOG_SECURITY_PATTERNS,
    LOG_TIMESTAMP_RE,
    MAX_FILE_READ_SIZE,
    MAX_LOG_ENTRIES,
    MAX_LOG_ENTRIES_PER_CATEGORY,
    MAX_LOG_READ_BYTES,
    MAX_LOG_TIMELINE_EVENTS,
    MAX_TOTAL_LOG_BYTES,
)
from prescan.discovery import discover_log_files


def parse_log_entry(line: str) -> dict | None:
    """Parse a single log line into structured components.

    Returns None for unparseable lines.
    """
    if not line.strip():
        return None

    entry = {'raw': line.strip()[:500]}

    # Extract timestamp
    ts_match = LOG_TIMESTAMP_RE.search(line)
    if ts_match:
        entry['timestamp'] = ts_match.group(1) or ts_match.group(2)
    else:
        entry['timestamp'] = None

    # Extract error level
    level_match = LOG_LEVEL_RE.search(line)
    if level_match:
        entry['level'] = level_match.group(1).strip().lower().replace(' ', '_')
    else:
        entry['level'] = None

    # Extract file reference
    file_match = LOG_FILE_REF_RE.search(line)
    if file_match:
        entry['file_ref'] = file_match.group(1)
        entry['line_ref'] = int(file_match.group(2))
    else:
        entry['file_ref'] = None
        entry['line_ref'] = None

    # Must have at least a timestamp or level to be considered a valid entry
    if entry['timestamp'] is None and entry['level'] is None:
        return None

    entry['message'] = line.strip()[:500]
    return entry


def scan_error_logs(wp_root: Path) -> dict:
    """Discover and scan PHP error logs for security-relevant entries."""
    log_files = discover_log_files(wp_root)

    result = {
        'log_files_found': len(log_files),
        'log_files': [],
        'total_bytes_read': 0,
        'entries_by_category': defaultdict(list),
        'error_level_counts': defaultdict(int),
        'timeline': [],
    }

    if not log_files:
        return result

    total_bytes_read = 0
    seen_entries = set()

    for log_info in log_files:
        if total_bytes_read >= MAX_TOTAL_LOG_BYTES:
            break

        log_path = Path(log_info['path'])
        file_size = log_info['size']
        file_record = {
            'file': log_info['rel_path'],
            'size': file_size,
            'tail_only': False,
            'entries_parsed': 0,
            'security_hits': 0,
            'error_levels': defaultdict(int),
            'status': 'scanned',
        }

        if file_size > MAX_FILE_READ_SIZE:
            file_record['status'] = 'skipped_too_large'
            result['log_files'].append(file_record)
            continue

        try:
            if file_size > MAX_LOG_READ_BYTES:
                file_record['tail_only'] = True
                with open(log_path, 'rb') as f:
                    f.seek(file_size - MAX_LOG_READ_BYTES)
                    f.readline()
                    raw = f.read().decode('utf-8', errors='replace')
                bytes_this_file = MAX_LOG_READ_BYTES
            else:
                raw = log_path.read_text(errors='replace')
                bytes_this_file = file_size

            total_bytes_read += bytes_this_file
        except (PermissionError, OSError) as e:
            file_record['status'] = f'error: {e}'
            result['log_files'].append(file_record)
            continue

        entries_parsed = 0
        security_hits = 0

        for line in raw.split('\n'):
            if entries_parsed >= MAX_LOG_ENTRIES:
                break

            entry = parse_log_entry(line)
            if entry is None:
                continue

            entries_parsed += 1

            if entry['level']:
                file_record['error_levels'][entry['level']] += 1
                result['error_level_counts'][entry['level']] += 1

            matched = False
            for category, patterns in LOG_SECURITY_PATTERNS.items():
                if matched:
                    break
                for pat_re, pat_name in patterns:
                    if re.search(pat_re, line, re.I):
                        dedup_key = (entry['file_ref'], entry.get('line_ref'), pat_name)
                        if dedup_key in seen_entries:
                            break
                        seen_entries.add(dedup_key)

                        security_hits += 1

                        sec_entry = {
                            'log_file': log_info['rel_path'],
                            'timestamp': entry['timestamp'],
                            'level': entry['level'],
                            'pattern': pat_name,
                            'message': entry['message'],
                            'file_ref': entry['file_ref'],
                            'line_ref': entry['line_ref'],
                        }

                        if len(result['entries_by_category'][category]) < MAX_LOG_ENTRIES_PER_CATEGORY:
                            result['entries_by_category'][category].append(sec_entry)

                        if entry['timestamp'] and len(result['timeline']) < MAX_LOG_TIMELINE_EVENTS:
                            result['timeline'].append({
                                'timestamp': entry['timestamp'],
                                'category': category,
                                'pattern': pat_name,
                                'file_ref': entry['file_ref'],
                                'message': entry['message'],
                            })

                        matched = True
                        break

        file_record['entries_parsed'] = entries_parsed
        file_record['security_hits'] = security_hits
        file_record['error_levels'] = dict(file_record['error_levels'])
        result['log_files'].append(file_record)

    result['total_bytes_read'] = total_bytes_read
    result['entries_by_category'] = dict(result['entries_by_category'])
    result['error_level_counts'] = dict(result['error_level_counts'])

    result['timeline'].sort(key=lambda x: x.get('timestamp') or '')

    return result
