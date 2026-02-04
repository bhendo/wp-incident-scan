"""Read and inspect WordPress core files and .htaccess files."""

from pathlib import Path

from prescan.constants import CORE_FILES_TO_INSPECT
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
                content = fpath.read_text(errors='replace')
                if relpath == 'wp-config.php':
                    content = redact_wp_config(content)
                core[relpath] = truncate_content(content)
            except Exception as e:
                core[relpath] = f'ERROR reading: {e}'
        else:
            core[relpath] = 'FILE NOT FOUND'

    # All .htaccess files
    for htaccess in wp_root.rglob('.htaccess'):
        rel = str(htaccess.relative_to(wp_root))
        if rel not in core:
            try:
                resolved = htaccess.resolve(strict=True)
                if not is_within_root(resolved, wp_root_resolved):
                    core[rel] = 'SKIPPED: symlink points outside backup'
                    continue
                content = htaccess.read_text(errors='replace')
                core[rel] = truncate_content(content)
            except Exception as e:
                core[rel] = f'ERROR reading: {e}'

    return core
