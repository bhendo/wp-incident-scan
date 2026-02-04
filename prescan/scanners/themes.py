"""Read theme functions.php files for inspection."""

from pathlib import Path

from prescan.constants import MAX_FILE_READ_SIZE
from prescan.utils import is_within_root, truncate_content


def read_theme_functions(wp_root: Path, themes: list[dict]) -> dict:
    """Read functions.php from all themes."""
    results = {}
    wp_root_resolved = str(wp_root.resolve())
    for theme in themes:
        func_file = Path(theme['path']) / 'functions.php'
        if func_file.exists():
            try:
                resolved = func_file.resolve(strict=True)
                if not is_within_root(resolved, wp_root_resolved):
                    results[theme['slug']] = 'SKIPPED: symlink points outside backup'
                    continue
                if func_file.stat().st_size > MAX_FILE_READ_SIZE:
                    results[theme['slug']] = f'SKIPPED: exceeds {MAX_FILE_READ_SIZE // (1024*1024)}MB limit'
                    continue
                content = func_file.read_text(errors='replace')
                results[theme['slug']] = truncate_content(content)
            except Exception as e:
                results[theme['slug']] = f'ERROR reading: {e}'
        else:
            results[theme['slug']] = 'NO functions.php'
    return results
