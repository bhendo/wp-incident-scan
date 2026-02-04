"""Collect file modification timestamps and find anomalies."""

import sys
from collections import defaultdict
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
    clusters = {}
    for date, files in sorted(timestamps.items()):
        if len(files) > 50:
            clusters[date] = {'count': len(files), 'sample_files': files[:20]}

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
