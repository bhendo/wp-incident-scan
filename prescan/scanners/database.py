"""Scan SQL dumps for suspicious patterns and extract structural data."""

import gzip
import os
import re
import sys
from pathlib import Path

from prescan.constants import (
    DB_SUSPICIOUS_PATTERNS,
    INJECTION_OPTION_RE,
    MAX_GZIP_DECOMPRESSED_BYTES,
)
from prescan.utils import redact_email


def scan_sql_dump(dump_path: str) -> dict:
    """Scan SQL dump for suspicious patterns and extract structural data.

    Note: User extraction assumes standard mysqldump column order
    (ID, user_login, user_pass, user_nicename, user_email, ...).
    Non-standard column ordering or multi-line INSERT statements may
    cause incomplete extraction. Cross-reference with usermeta for accuracy.
    """
    results = {
        'content_matches': [],
        'users': [],
        'admin_users': [],
        'options': {},
        'create_tables': [],
        'cron_data': None,
        'snippets': [],
        'subsites': {},
    }

    target_options = {
        'siteurl', 'home', 'template', 'stylesheet', 'active_plugins',
        'rewrite_rules', 'wp_cd_code', 'wp_cd_key', 'widget_text',
        'widget_custom_html', 'cron',
    }

    is_gzipped = dump_path.endswith('.gz')
    opener = gzip.open if is_gzipped else open

    try:
        with opener(dump_path, 'rt', errors='replace') as f:
            current_table = ''
            bytes_read = 0
            for line_num, line in enumerate(f, 1):
                if line_num % 50000 == 0:
                    print(f'    ... {line_num} lines processed in {os.path.basename(dump_path)}', file=sys.stderr)

                if is_gzipped:
                    bytes_read += len(line)
                    if bytes_read > MAX_GZIP_DECOMPRESSED_BYTES:
                        results['error'] = (
                            f'Aborted: decompressed size exceeded {MAX_GZIP_DECOMPRESSED_BYTES // (1024 * 1024 * 1024)}GB limit '
                            f'(possible gzip bomb). Processed {line_num} lines before stopping.'
                        )
                        print(f'    [!] {results["error"]}', file=sys.stderr)
                        break

                # Track current table context
                create_m = re.match(r'CREATE TABLE.*?`(\w+)`', line, re.I)
                if create_m:
                    results['create_tables'].append(create_m.group(1))
                    current_table = create_m.group(1)

                insert_m = re.match(r'INSERT INTO\s+`?(\w+)`?', line, re.I)
                if insert_m:
                    current_table = insert_m.group(1)

                # Suspicious content patterns
                for pattern, label in DB_SUSPICIOUS_PATTERNS:
                    for match in re.finditer(pattern, line, re.I):
                        if label == 'script tag':
                            ws = max(0, match.start() - 250)
                            we = min(len(line), match.end() + 250)
                            if re.search(
                                r'(elementor|google.*site.*kit|microsoft.*clarity'
                                r'|rank.?math|woocommerce|jetpack|monsterinsights)',
                                line[ws:we], re.I
                            ):
                                continue

                        cs = max(0, match.start() - 150)
                        ce = min(len(line), match.end() + 150)
                        results['content_matches'].append({
                            'line': line_num,
                            'table': current_table,
                            'pattern': label,
                            'context': line[cs:ce].strip(),
                        })

                # User extraction
                if re.search(r'_users', current_table, re.I) and 'INSERT' in line.upper():
                    user_matches = re.findall(
                        r"\((\d+),'([^']*?)','([^']*?)','([^']*?)','([^']*?)'",
                        line
                    )
                    for um in user_matches:
                        results['users'].append({
                            'id': um[0], 'login': um[1],
                            'email': redact_email(um[4]),
                            'nicename': um[3],
                        })

                # Admin role detection
                if 'administrator' in line and '_usermeta' in current_table and 'capabilities' in line:
                    cap_matches = re.findall(r"(\d+),'[^']*capabilities','([^']*)'", line) or \
                                  re.findall(r"\((\d+),\s*\d+,\s*'[^']*capabilities',\s*'([^']*)'", line)
                    for cm in cap_matches:
                        if 'administrator' in cm[1]:
                            results['admin_users'].append({'user_id': cm[0], 'capabilities': cm[1][:200]})

                # Options extraction
                if '_options' in current_table and 'INSERT' in line.upper():
                    for opt_name in target_options:
                        if opt_name in line:
                            opt_match = re.search(
                                rf"'{re.escape(opt_name)}'\s*,\s*'(.*?)'(?:\s*,\s*'(?:yes|no)')?",
                                line, re.I
                            )
                            if opt_match:
                                val = opt_match.group(1)
                                if opt_name == 'cron':
                                    results['cron_data'] = val[:5000]
                                elif len(val) > 2000:
                                    results['options'][opt_name] = val[:2000] + f'... [TRUNCATED, total {len(val)} chars]'
                                else:
                                    results['options'][opt_name] = val

                    # DB-03: Extract injection-prone options by name pattern
                    if INJECTION_OPTION_RE.search(line):
                        for inj_match in re.finditer(
                            r"'(\w*(?:" + INJECTION_OPTION_RE.pattern + r")\w*)'"
                            r"\s*,\s*'(.*?)'",
                            line, re.I
                        ):
                            opt_name = inj_match.group(1)
                            if opt_name not in results['options']:
                                val = inj_match.group(2)
                                if len(val) > 2000:
                                    results['options'][opt_name] = (
                                        val[:2000] + f'... [TRUNCATED, total {len(val)} chars]'
                                    )
                                else:
                                    results['options'][opt_name] = val

                # SCAN-03: Detect multisite subsite options tables
                subsite_m = re.match(r'wp_(\d+)_options', current_table)
                if subsite_m and '_options' in current_table and 'INSERT' in line.upper():
                    site_id = subsite_m.group(1)
                    if site_id not in results['subsites']:
                        results['subsites'][site_id] = {}
                    subsite_target = {'siteurl', 'home', 'active_plugins', 'template', 'stylesheet', 'admin_email'}
                    for opt_name in subsite_target:
                        if opt_name in line:
                            opt_match = re.search(
                                rf"'{re.escape(opt_name)}'\s*,\s*'(.*?)'(?:\s*,\s*'(?:yes|no)')?",
                                line, re.I
                            )
                            if opt_match:
                                val = opt_match.group(1)
                                if len(val) > 2000:
                                    results['subsites'][site_id][opt_name] = val[:2000] + f'... [TRUNCATED]'
                                else:
                                    results['subsites'][site_id][opt_name] = val

                # Code snippets table
                if '_snippets' in current_table and 'INSERT' in line.upper():
                    results['snippets'].append({
                        'line': line_num,
                        'content': line.strip()[:1000],
                    })

    except Exception as e:
        results['error'] = str(e)

    return results
