"""
Main orchestration: discovery -> scans -> output.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from prescan.discovery import (
    find_sql_dumps,
    find_wp_root,
    get_plugin_info,
    get_theme_info,
    get_wp_version,
)
from prescan.scanners.core_files import read_core_files
from prescan.scanners.database import scan_sql_dump
from prescan.scanners.error_logs import scan_error_logs
from prescan.scanners.security_logs import scan_security_logs
from prescan.scanners.php_patterns import scan_php_patterns
from prescan.scanners.suspicious_files import scan_suspicious_files
from prescan.scanners.themes import read_theme_functions
from prescan.scanners.timestamps import analyze_timestamps
from prescan.utils import write_section


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} /path/to/wordpress/backup', file=sys.stderr)
        sys.exit(1)

    backup_path = Path(sys.argv[1]).resolve()
    if not backup_path.is_dir():
        print(f'Error: {backup_path} is not a directory', file=sys.stderr)
        sys.exit(1)

    print(f'[*] Scanning backup at: {backup_path}', file=sys.stderr)

    # Create prescan-data directory for per-section output
    data_dir = backup_path / 'prescan-data'
    data_dir.mkdir(exist_ok=True)

    # Discovery
    print('[*] Discovery...', file=sys.stderr)
    wp_root = find_wp_root(backup_path)
    if not wp_root:
        print('Error: Could not find WordPress root (no wp-includes/version.php)', file=sys.stderr)
        sys.exit(1)
    print(f'    WordPress root: {wp_root}', file=sys.stderr)

    wp_version = get_wp_version(wp_root)
    print(f'    WordPress version: {wp_version}', file=sys.stderr)

    plugins = []
    plugins_dir = wp_root / 'wp-content' / 'plugins'
    if plugins_dir.exists():
        for d in sorted(plugins_dir.iterdir()):
            if d.is_dir():
                plugins.append(get_plugin_info(d))
    print(f'    Plugins found: {len(plugins)}', file=sys.stderr)

    themes = []
    themes_dir = wp_root / 'wp-content' / 'themes'
    if themes_dir.exists():
        for d in sorted(themes_dir.iterdir()):
            if d.is_dir():
                themes.append(get_theme_info(d))
    print(f'    Themes found: {len(themes)}', file=sys.stderr)

    mu_plugins = []
    mu_dir = wp_root / 'wp-content' / 'mu-plugins'
    if mu_dir.exists():
        for f in sorted(mu_dir.glob('*.php')):
            mu_plugins.append(f.name)
    print(f'    MU-Plugins found: {len(mu_plugins)}', file=sys.stderr)

    sql_dumps = find_sql_dumps(backup_path)
    print(f'    SQL dumps found: {len(sql_dumps)}', file=sys.stderr)

    discovery = {
        'wp_version': wp_version,
        'plugins': plugins,
        'themes': themes,
        'mu_plugins': mu_plugins,
        'sql_dumps': sql_dumps,
    }
    write_section(data_dir, 'discovery', discovery)

    # Filesystem scans
    print('[*] Scanning PHP patterns...', file=sys.stderr)
    php_patterns = scan_php_patterns(wp_root)
    print(f'    {php_patterns["files_scanned"]} files scanned, '
          f'{len(php_patterns["suspicious_matches"])} suspicious, '
          f'{php_patterns["legitimate_matches_omitted"]} legitimate (omitted), '
          f'{len(php_patterns["legitimate_high_signal_matches"])} high-signal in vendor paths', file=sys.stderr)
    write_section(data_dir, 'php-pattern-matches', php_patterns)

    print('[*] Scanning for suspicious files...', file=sys.stderr)
    suspicious_files = scan_suspicious_files(wp_root)
    write_section(data_dir, 'suspicious-files', suspicious_files)

    print('[*] Reading core files...', file=sys.stderr)
    core_files = read_core_files(wp_root)
    write_section(data_dir, 'core-files', core_files)

    print('[*] Reading theme functions.php files...', file=sys.stderr)
    theme_functions = read_theme_functions(wp_root, themes)
    write_section(data_dir, 'theme-functions', theme_functions)

    print('[*] Analyzing timestamps...', file=sys.stderr)
    timestamps = analyze_timestamps(wp_root, wp_version)
    write_section(data_dir, 'timestamps', timestamps)

    print('[*] Scanning PHP error logs...', file=sys.stderr)
    error_logs = scan_error_logs(wp_root)
    total_security = sum(len(v) for v in error_logs['entries_by_category'].values())
    print(f'    {error_logs["log_files_found"]} log files found, '
          f'{total_security} security-relevant entries', file=sys.stderr)
    write_section(data_dir, 'error-logs', error_logs)

    print('[*] Scanning security plugin logs...', file=sys.stderr)
    security_logs = scan_security_logs(wp_root)
    sec_entries = sum(len(v) for v in security_logs['entries_by_category'].values())
    print(f'    {security_logs["dirs_found"]} security log dirs found, '
          f'{sec_entries} entries extracted', file=sys.stderr)
    write_section(data_dir, 'security-logs', security_logs)

    # Database scans
    db_results = {}
    for i, dump in enumerate(sql_dumps):
        print(f'[*] Scanning SQL dump: {dump}...', file=sys.stderr)
        db_results[dump] = scan_sql_dump(dump)
    write_section(data_dir, 'database', db_results)

    # Write index file (lightweight — just metadata and file references)
    section_files = {
        'discovery': 'prescan-data/discovery.json',
        'php_pattern_matches': 'prescan-data/php-pattern-matches.json',
        'suspicious_files': 'prescan-data/suspicious-files.json',
        'core_files': 'prescan-data/core-files.json',
        'theme_functions': 'prescan-data/theme-functions.json',
        'timestamps': 'prescan-data/timestamps.json',
        'error_logs': 'prescan-data/error-logs.json',
        'security_logs': 'prescan-data/security-logs.json',
        'database': 'prescan-data/database.json',
    }

    index = {
        '_meta': {
            'scan_time': datetime.now().isoformat(),
            'backup_path': str(backup_path),
            'wp_root': str(wp_root),
            'sensitive_data_notice': (
                'Output files may contain fragments of sensitive data in pattern matches '
                'and content snippets (e.g., partial credentials, email fragments, password hashes). '
                'DB_PASSWORD, auth keys, and salts are redacted from wp-config.php. User emails are '
                'partially redacted. Treat all output files as confidential and delete after analysis.'
            ),
        },
        'discovery': discovery,
        'section_files': section_files,
        'summary': {
            'wp_version': wp_version,
            'plugin_count': len(plugins),
            'theme_count': len(themes),
            'mu_plugin_count': len(mu_plugins),
            'sql_dump_count': len(sql_dumps),
            'php_files_scanned': php_patterns['files_scanned'],
            'suspicious_pattern_matches': len(php_patterns['suspicious_matches']),
            'high_signal_vendor_matches': len(php_patterns['legitimate_high_signal_matches']),
            'php_in_uploads': len(suspicious_files['php_in_uploads']),
            'known_malware_filenames': len(suspicious_files['known_malware_names']),
            'non_standard_root_php': len(suspicious_files['non_standard_root_php']),
            'error_log_files_found': error_logs['log_files_found'],
            'error_log_security_entries': total_security,
            'security_log_dirs_found': security_logs['dirs_found'],
            'security_log_entries': sec_entries,
        },
    }

    out_path = backup_path / 'wp-prescan-results.json'
    with open(out_path, 'w') as f:
        json.dump(index, f, indent=2, default=str)

    print(f'[*] Done. Index written to: {out_path}', file=sys.stderr)
    print(f'[*] Section data written to: {data_dir}/', file=sys.stderr)
    print(str(out_path))
