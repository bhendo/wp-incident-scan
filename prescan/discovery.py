"""
Functions that locate WordPress components (root, plugins, themes, SQL dumps, log files)
but do not analyze content.
"""

import re
import sys
from pathlib import Path

from prescan.constants import (
    ERROR_LOG_GLOB_PATTERNS,
    ERROR_LOG_KNOWN_PATHS,
    MAX_LOG_FILES,
    SECURITY_LOG_DIRS,
)
from prescan.utils import (
    is_within_root,
    sanitize_name,
    sanitize_slug,
    sanitize_version,
)


def find_wp_root(backup_path: Path) -> Path | None:
    """Find the WordPress root by looking for wp-includes/version.php."""
    for candidate in [backup_path] + sorted(backup_path.iterdir()):
        if candidate.is_dir():
            if (candidate / 'wp-includes' / 'version.php').exists():
                return candidate
    # Deeper search (one more level)
    for d in sorted(backup_path.iterdir()):
        if d.is_dir():
            for dd in sorted(d.iterdir()):
                if dd.is_dir() and (dd / 'wp-includes' / 'version.php').exists():
                    return dd
    return None


def get_wp_version(wp_root: Path) -> str:
    """Extract the WordPress version from wp-includes/version.php."""
    version_file = wp_root / 'wp-includes' / 'version.php'
    try:
        content = version_file.read_text(errors='replace')
        m = re.search(r"\$wp_version\s*=\s*'([^']+)'", content)
        return m.group(1) if m else 'unknown'
    except Exception:
        return 'unknown'


def get_plugin_info(plugin_dir: Path) -> dict:
    """Read plugin header from the main PHP file."""
    info = {'slug': sanitize_slug(plugin_dir.name), 'name': sanitize_name(plugin_dir.name), 'version': 'unknown', 'path': str(plugin_dir)}
    candidates = [plugin_dir / f'{plugin_dir.name}.php']
    candidates += sorted(plugin_dir.glob('*.php'))
    for php_file in candidates:
        if not php_file.exists():
            continue
        try:
            head = php_file.read_text(errors='replace')[:4096]
        except Exception:
            continue
        name_m = re.search(r'Plugin Name:\s*(.+)', head)
        ver_m = re.search(r'Version:\s*(\S+)', head)
        if name_m:
            info['name'] = sanitize_name(name_m.group(1).strip())
        if ver_m:
            info['version'] = sanitize_version(ver_m.group(1).strip())
        if name_m or ver_m:
            break
    return info


def get_theme_info(theme_dir: Path) -> dict:
    """Read theme metadata from style.css."""
    info = {'slug': sanitize_slug(theme_dir.name), 'name': sanitize_name(theme_dir.name), 'version': 'unknown', 'path': str(theme_dir)}
    style = theme_dir / 'style.css'
    if style.exists():
        try:
            head = style.read_text(errors='replace')[:4096]
        except Exception:
            return info
        name_m = re.search(r'Theme Name:\s*(.+)', head)
        ver_m = re.search(r'Version:\s*(\S+)', head)
        if name_m:
            info['name'] = sanitize_name(name_m.group(1).strip())
        if ver_m:
            info['version'] = sanitize_version(ver_m.group(1).strip())
    return info


def find_sql_dumps(backup_path: Path) -> list[str]:
    """Find all .sql and .sql.gz files in the backup."""
    dumps = []
    for f in backup_path.rglob('*.sql'):
        dumps.append(str(f))
    for f in backup_path.rglob('*.sql.gz'):
        dumps.append(str(f))
    return sorted(dumps)


def discover_log_files(wp_root: Path) -> list[dict]:
    """Discover PHP error log files using three-tier search.

    1. Check known paths directly (O(1) each)
    2. Glob patterns in root, wp-content, logs/ (bounded, not recursive)
    3. Check for extensionless 'error_log' in key directories
    """
    wp_root_resolved = str(wp_root.resolve())
    found = {}  # rel_path -> dict, for deduplication

    def _add_candidate(path: Path, source: str):
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return
        if not resolved.is_file():
            return
        if not is_within_root(resolved, wp_root_resolved):
            return
        try:
            rel = str(path.relative_to(wp_root))
        except ValueError:
            return
        if rel in found:
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size == 0:
            return
        found[rel] = {
            'path': str(path),
            'rel_path': rel,
            'size': size,
            'source': source,
        }

    # Tier 1: known paths
    for known in ERROR_LOG_KNOWN_PATHS:
        _add_candidate(wp_root / known, 'known_path')

    # Tier 2: glob patterns (bounded, not recursive)
    for pattern in ERROR_LOG_GLOB_PATTERNS:
        for match in wp_root.glob(pattern):
            _add_candidate(match, 'glob')

    # Tier 3: extensionless 'error_log' in key directories
    for subdir in ['', 'wp-content', 'wp-admin']:
        candidate = wp_root / subdir / 'error_log' if subdir else wp_root / 'error_log'
        _add_candidate(candidate, 'extensionless_check')

    # Sort by size descending, cap at MAX_LOG_FILES
    results = sorted(found.values(), key=lambda x: x['size'], reverse=True)
    return results[:MAX_LOG_FILES]


def discover_security_log_dirs(wp_root: Path) -> list[dict]:
    """Discover Wordfence, Sucuri, and other security plugin log directories.

    Returns list of dicts with path, rel_path, plugin_name, file_count, total_size.
    """
    wp_content = wp_root / 'wp-content'
    if not wp_content.is_dir():
        return []

    found = []
    wp_root_resolved = str(wp_root.resolve())

    for rel_dir in SECURITY_LOG_DIRS:
        candidate = wp_content / rel_dir
        if not candidate.is_dir():
            continue
        resolved = candidate.resolve()
        if not is_within_root(resolved, wp_root_resolved):
            continue

        # Identify which plugin this belongs to
        plugin_name = rel_dir.split('/')[0]
        if plugin_name == 'wflogs':
            plugin_name = 'wordfence'
        elif plugin_name == 'uploads':
            plugin_name = rel_dir.split('/')[1] if '/' in rel_dir else 'unknown'

        files = []
        total_size = 0
        try:
            for f in sorted(candidate.rglob('*')):
                if f.is_file() and is_within_root(f.resolve(), wp_root_resolved):
                    try:
                        size = f.stat().st_size
                        files.append({
                            'path': str(f),
                            'rel_path': str(f.relative_to(wp_root)),
                            'size': size,
                            'name': f.name,
                        })
                        total_size += size
                    except OSError:
                        continue
        except (PermissionError, OSError):
            continue

        if files:
            found.append({
                'dir_path': str(candidate),
                'rel_path': str(candidate.relative_to(wp_root)),
                'plugin_name': plugin_name,
                'file_count': len(files),
                'total_size': total_size,
                'files': files,
            })

    return found
