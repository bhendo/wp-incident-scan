"""
Shared helper functions used by multiple scanner modules.
"""

import json
import os
import re
from pathlib import Path

from prescan.constants import (
    LEGITIMATE_PATHS,
    MAX_FILE_CONTENT_SIZE,
    MAX_NAME_LENGTH,
    MAX_SLUG_LENGTH,
    MAX_VERSION_LENGTH,
    SENSITIVE_WP_DEFINES,
    VALID_SLUG_RE,
    VALID_VERSION_RE,
)


def is_legitimate_path(filepath: str) -> bool:
    """Check if a file path is in a known vendor/library directory."""
    return any(seg in filepath for seg in LEGITIMATE_PATHS)


def is_within_root(resolved_path: Path, root_resolved: str) -> bool:
    """Check that a resolved path stays within the WordPress root (symlink boundary guard)."""
    s = str(resolved_path)
    return s == root_resolved or s.startswith(root_resolved + os.sep)


def truncate_content(content: str, max_size: int = MAX_FILE_CONTENT_SIZE) -> str:
    """Truncate file content with a notice if it exceeds max_size."""
    if len(content) <= max_size:
        return content
    return content[:max_size] + f'\n\n[TRUNCATED at {max_size // 1024}KB — read full file directly for complete contents]'


def redact_wp_config(content: str) -> str:
    """Redact sensitive define() values in wp-config.php while preserving structure (SEC-04).

    Replaces the value argument of define() calls for known sensitive constants
    (DB_PASSWORD, auth keys, salts) with '[REDACTED]'. Preserves all other content
    including comments, require statements, and any injected code so agents can
    still detect malware.
    """
    for const_name in SENSITIVE_WP_DEFINES:
        pattern = (
            r"(define\s*\(\s*['\"]" + re.escape(const_name) + r"['\"]\s*,\s*)"
            r"['\"].*?['\"]\s*\)"
        )
        content = re.sub(pattern, r"\g<1>'[REDACTED]')", content)

    return content


def redact_email(email: str) -> str:
    """Partially redact an email address, keeping first char of local part + full domain (SEC-04).

    Example: admin@example.com -> a***@example.com
    """
    if '@' not in email:
        return email
    local, domain = email.split('@', 1)
    if local:
        return f"{local[0]}***@{domain}"
    return f"***@{domain}"


def sanitize_slug(raw: str) -> str:
    """Sanitize a plugin/theme slug for safe use in search queries (SEC-07)."""
    slug = raw[:MAX_SLUG_LENGTH]
    if not VALID_SLUG_RE.match(slug):
        slug = re.sub(r'[^a-zA-Z0-9_-]', '', slug)
    return slug or 'unknown'


def sanitize_version(raw: str) -> str:
    """Sanitize a version string for safe use in search queries (SEC-07)."""
    ver = raw.strip()[:MAX_VERSION_LENGTH]
    if not VALID_VERSION_RE.match(ver):
        m = re.search(r'[\d]+(?:\.[\d]+)*', ver)
        return m.group(0) if m else 'unknown'
    return ver


def sanitize_name(raw: str) -> str:
    """Sanitize a plugin/theme display name (SEC-07)."""
    name = re.sub(r'[\x00-\x1f\x7f]', '', raw)
    return name[:MAX_NAME_LENGTH] or 'unknown'


def write_section(data_dir: Path, name: str, data: dict | list) -> str:
    """Write a single section to its own JSON file and return the filename."""
    filename = f'{name}.json'
    filepath = data_dir / filename
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return filename
