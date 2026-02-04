"""Read and inspect WordPress core files and .htaccess files."""

from pathlib import Path

from prescan.constants import CORE_FILES_TO_INSPECT, MAX_FILE_READ_SIZE
from prescan.utils import is_within_root, redact_wp_config, truncate_content


def read_core_files(wp_root: Path) -> dict:
    """Read core files and all .htaccess files for model inspection."""
    core = {}
    wp_root_resolved = str(wp_root.resolve())

    for relpath in CORE_FILES_TO_INSPECT:
        fpath = wp_root / relpath
        if fpath.exists():
            try:
                resolved = fpath.resolve(strict=True)
                if not is_within_root(resolved, wp_root_resolved):
                    core[relpath] = 'SKIPPED: symlink points outside backup'
                    continue
                if fpath.stat().st_size > MAX_FILE_READ_SIZE:
                    core[relpath] = f'SKIPPED: exceeds {MAX_FILE_READ_SIZE // (1024*1024)}MB limit'
                    continue
                content = fpath.read_text(errors='replace')
                if relpath == 'wp-config.php':
                    content = redact_wp_config(content)
                core[relpath] = truncate_content(content)
            except Exception as e:
                core[relpath] = f'ERROR: {type(e).__name__}'
        else:
            core[relpath] = 'FILE NOT FOUND'

    # All .htaccess files (capped at 1000 to prevent enumeration exhaustion)
    htaccess_count = 0
    for htaccess in wp_root.rglob('.htaccess'):
        htaccess_count += 1
        if htaccess_count > 1000:
            break
        rel = str(htaccess.relative_to(wp_root))
        if rel not in core:
            try:
                resolved = htaccess.resolve(strict=True)
                if not is_within_root(resolved, wp_root_resolved):
                    core[rel] = 'SKIPPED: symlink points outside backup'
                    continue
                if htaccess.stat().st_size > MAX_FILE_READ_SIZE:
                    core[rel] = f'SKIPPED: exceeds {MAX_FILE_READ_SIZE // (1024*1024)}MB limit'
                    continue
                content = htaccess.read_text(errors='replace')
                core[rel] = truncate_content(content)
            except Exception as e:
                core[rel] = f'ERROR: {type(e).__name__}'

    return core
