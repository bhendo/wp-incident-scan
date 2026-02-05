"""CVE lookup using locally-cached Wordfence vulnerability database."""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

WORDFENCE_API_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production'
CACHE_TTL_HOURS = 24


def get_cache_path() -> Path:
    """Return path to the Wordfence vulnerability cache file."""
    project_root = Path(__file__).parent.parent.parent
    return project_root / 'cache' / 'wordfence-vulns.json'


def get_cache_age_hours(cache_path: Path) -> float | None:
    """Return cache age in hours, or None if cache doesn't exist."""
    if not cache_path.exists():
        return None
    mtime = cache_path.stat().st_mtime
    age_seconds = time.time() - mtime
    return age_seconds / 3600


def _fetch_from_api() -> dict | None:
    """Fetch vulnerability database from Wordfence API. Returns None on failure."""
    try:
        print('[*] Fetching Wordfence vulnerability database...', file=sys.stderr)
        req = urllib.request.Request(
            WORDFENCE_API_URL,
            headers={'User-Agent': 'wp-incident-scan/0.1'}
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode('utf-8'))
            print(f'    Fetched {len(data)} vulnerabilities', file=sys.stderr)
            return data
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError) as e:
        print(f'    [!] Failed to fetch Wordfence database: {e}', file=sys.stderr)
        return None


def load_or_refresh_cache() -> tuple[dict | None, str]:
    """Load vulnerability cache, refreshing if stale.

    Returns:
        Tuple of (cache_data, status) where status is 'fresh', 'stale', or 'unavailable'
    """
    cache_path = get_cache_path()
    age_hours = get_cache_age_hours(cache_path)

    # Fresh cache exists - use it
    if age_hours is not None and age_hours < CACHE_TTL_HOURS:
        try:
            with open(cache_path) as f:
                return json.load(f), 'fresh'
        except (json.JSONDecodeError, OSError) as e:
            print(f'    [!] Corrupted fresh cache, re-fetching: {e}', file=sys.stderr)

    # Need to fetch (missing or stale)
    new_data = _fetch_from_api()

    if new_data is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(cache_path, 'w') as f:
                json.dump(new_data, f)
        except OSError as e:
            print(f'    [!] Failed to write cache file: {e}', file=sys.stderr)
        return new_data, 'fresh'

    # Fetch failed - try stale cache
    if age_hours is not None:
        print(f'    [!] Using stale cache ({age_hours:.1f}h old)', file=sys.stderr)
        try:
            with open(cache_path) as f:
                return json.load(f), 'stale'
        except (json.JSONDecodeError, OSError) as e:
            print(f'    [!] Stale cache also unreadable: {e}', file=sys.stderr)

    # No cache, no network
    print('    [!] No CVE data available (no cache, network failed)', file=sys.stderr)
    return None, 'unavailable'


def parse_version(version_str: str | None) -> tuple[int, ...]:
    """Parse version string into tuple of integers for comparison.

    Examples:
        '1.2.3' -> (1, 2, 3)
        '5.0' -> (5, 0)
        '1.2.3-beta' -> (1, 2, 3)
        'unknown' -> ()
    """
    if not version_str:
        return ()
    # Extract numeric parts only
    match = re.match(r'^(\d+(?:\.\d+)*)', version_str.strip())
    if not match:
        return ()
    parts = match.group(1).split('.')
    return tuple(int(p) for p in parts)


def version_matches(installed: str, condition: str) -> bool:
    """Check if installed version matches a version condition.

    Conditions: '< 2.0.0', '<= 2.0.0', '> 2.0.0', '>= 2.0.0', '= 2.0.0', '2.0.0', '*'
    """
    if not condition:
        return False

    installed_parts = parse_version(installed)
    if not installed_parts:
        return False

    condition = condition.strip()
    if condition == '*':
        return True

    # Parse operator and version from condition
    match = re.match(r'^(<=?|>=?|=)?\s*(.+)$', condition)
    if not match:
        return False

    op = match.group(1) or '='
    cond_version = match.group(2).strip()
    cond_parts = parse_version(cond_version)

    if not cond_parts:
        return False

    # Pad to same length for comparison
    max_len = max(len(installed_parts), len(cond_parts))
    inst = installed_parts + (0,) * (max_len - len(installed_parts))
    cond = cond_parts + (0,) * (max_len - len(cond_parts))

    if op == '<':
        return inst < cond
    elif op == '<=':
        return inst <= cond
    elif op == '>':
        return inst > cond
    elif op == '>=':
        return inst >= cond
    elif op == '=':
        return inst == cond

    return False


def is_version_affected(installed_version: str | None, affected_versions: dict) -> bool:
    """Check if installed version is in any affected range.
    If installed version is unknown/None, returns True (include all CVEs).
    """
    if not installed_version or installed_version == 'unknown':
        return True
    for condition in affected_versions.keys():
        if version_matches(installed_version, condition):
            return True
    return False


def find_cves_for_plugin(slug: str, version: str | None, vuln_db: dict) -> list[dict]:
    """Find all CVEs affecting a plugin at a given version."""
    slug_lower = slug.lower().strip()
    results = []

    for vuln_id, vuln in vuln_db.items():
        software_list = vuln.get('software', [])
        plugin_match = any(
            s.get('type') == 'plugin' and s.get('slug', '').lower() == slug_lower
            for s in software_list
        )
        if not plugin_match:
            continue

        affects = vuln.get('affects', {})
        plugin_affects = affects.get(slug_lower) or affects.get(slug)
        if not plugin_affects:
            for key in affects:
                if key.lower() == slug_lower:
                    plugin_affects = affects[key]
                    break

        if not plugin_affects:
            continue

        affected_versions = plugin_affects.get('affected_versions', {})
        if not is_version_affected(version, affected_versions):
            continue

        cve_refs = vuln.get('references', {}).get('cve', [])
        cve_id = cve_refs[0] if cve_refs else f"WF-{vuln_id}"

        affected_str = ', '.join(affected_versions.keys())

        patched = plugin_affects.get('patched_versions', [])
        fixed = patched[0] if patched else None

        results.append({
            'cve_id': cve_id,
            'cvss': vuln.get('cvss', {}).get('score'),
            'type': vuln.get('cwe', {}).get('name', 'Unknown'),
            'affected': affected_str,
            'fixed': fixed,
            'title': vuln.get('title', ''),
        })

    results.sort(key=lambda x: x.get('cvss') or 0, reverse=True)
    return results


def lookup_plugin_cves(plugins: list[dict]) -> dict:
    """Look up CVEs for all plugins."""
    vuln_db, cache_status = load_or_refresh_cache()
    cache_age = get_cache_age_hours(get_cache_path())

    result = {
        'cache_age_hours': round(cache_age, 1) if cache_age else None,
        'cache_status': cache_status,
        'plugins_checked': 0,
        'plugins_with_cves': 0,
        'total_cves_matched': 0,
        'plugins': {},
    }

    if vuln_db is None:
        return result

    for plugin in plugins:
        slug = plugin.get('slug', '')
        version = plugin.get('version')
        version_known = bool(version and version != 'unknown')

        cves = find_cves_for_plugin(slug, version, vuln_db)

        result['plugins'][slug] = {
            'installed_version': version,
            'version_known': version_known,
            'cves': cves,
        }
        result['plugins_checked'] += 1
        if cves:
            result['plugins_with_cves'] += 1
            result['total_cves_matched'] += len(cves)

    return result


def find_cves_for_core(wp_version: str, vuln_db: dict) -> list[dict]:
    """Find all CVEs affecting WordPress core at a given version."""
    results = []

    for vuln_id, vuln in vuln_db.items():
        software_list = vuln.get('software', [])
        is_core = any(
            s.get('type') == 'core' and s.get('slug', '').lower() == 'wordpress'
            for s in software_list
        )
        if not is_core:
            continue

        affects = vuln.get('affects', {})
        core_affects = affects.get('wordpress')
        if not core_affects:
            continue

        affected_versions = core_affects.get('affected_versions', {})
        if not is_version_affected(wp_version, affected_versions):
            continue

        cve_refs = vuln.get('references', {}).get('cve', [])
        cve_id = cve_refs[0] if cve_refs else f"WF-{vuln_id}"

        affected_str = ', '.join(affected_versions.keys())
        patched = core_affects.get('patched_versions', [])
        fixed = patched[0] if patched else None

        results.append({
            'cve_id': cve_id,
            'cvss': vuln.get('cvss', {}).get('score'),
            'type': vuln.get('cwe', {}).get('name', 'Unknown'),
            'affected': affected_str,
            'fixed': fixed,
            'title': vuln.get('title', ''),
        })

    results.sort(key=lambda x: x.get('cvss') or 0, reverse=True)
    return results
