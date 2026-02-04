"""Collect file modification timestamps and find anomalies."""

import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from prescan.constants import CORE_FILES_TO_INSPECT, MAX_FILE_COUNT, PROGRESS_INTERVAL


def analyze_timestamps(wp_root: Path, wp_version: str) -> dict:
    """Collect file modification timestamps and find anomalies."""
    timestamps = defaultdict(list)
    core_mtimes = {}

    # Core files
    for relpath in CORE_FILES_TO_INSPECT:
        fpath = wp_root / relpath
        if fpath.exists():
            try:
                mtime = fpath.stat().st_mtime
                dt = datetime.fromtimestamp(mtime)
                core_mtimes[relpath] = dt.isoformat()
            except Exception:
                pass

    # Collect all file timestamps grouped by date
    all_mtimes = []
    files_checked = 0
    for f in wp_root.rglob('*'):
        if not f.is_file():
            continue
        files_checked += 1
        if files_checked % PROGRESS_INTERVAL == 0:
            print(f'    ... {files_checked} files checked for timestamps', file=sys.stderr)
        if files_checked > MAX_FILE_COUNT:
            print(f'    [!] File count limit reached ({MAX_FILE_COUNT}). Stopping timestamp analysis.', file=sys.stderr)
            break
        try:
            mtime = f.stat().st_mtime
            dt = datetime.fromtimestamp(mtime)
            rel = str(f.relative_to(wp_root))
            date_key = dt.strftime('%Y-%m-%d')
            timestamps[date_key].append(rel)
            all_mtimes.append((dt.isoformat(), rel))
        except Exception:
            pass

    # Find dates with unusual clusters (more than 50 files modified)
    total_files = len(all_mtimes)
    clusters = {}
    for date, files in sorted(timestamps.items()):
        if len(files) > 50:
            # Directory distribution: bucket by first 2 path segments
            dir_counter = Counter()
            ext_counter = Counter()
            for f in files:
                # Use forward slash for consistency (prescan stores paths with /)
                parts = f.replace(os.sep, '/').split('/')
                # parts[:-1] is the directory path, take up to 2 segments
                dir_parts = parts[:-1]
                if len(dir_parts) >= 2:
                    dir_bucket = '/'.join(dir_parts[:2])
                elif len(dir_parts) == 1:
                    dir_bucket = dir_parts[0]
                else:
                    dir_bucket = '(root)'
                dir_counter[dir_bucket] += 1
                ext = os.path.splitext(f)[1].lower()
                if ext:
                    ext_counter[ext] += 1
                else:
                    ext_counter['(no ext)'] += 1
            clusters[date] = {
                'count': len(files),
                'pct_of_total': round(len(files) / total_files * 100, 1) if total_files else 0,
                'sample_files': files[:20],
                'dir_distribution': dict(dir_counter.most_common(10)),
                'ext_distribution': dict(ext_counter.most_common(10)),
            }

    # Find the most recent modifications (top 30)
    all_mtimes.sort(reverse=True)
    recent = [{'timestamp': ts, 'file': f} for ts, f in all_mtimes[:30]]

    return {
        'wp_version': wp_version,
        'core_file_timestamps': core_mtimes,
        'modification_clusters': clusters,
        'most_recent_modifications': recent,
        'total_files': len(all_mtimes),
    }
