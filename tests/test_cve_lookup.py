"""Tests for prescan/scanners/cve_lookup.py CVE lookup functionality."""

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

from prescan.scanners.cve_lookup import parse_version, version_matches
from prescan.scanners.cve_lookup import get_cache_path, get_cache_age_hours, load_or_refresh_cache
from prescan.scanners.cve_lookup import find_cves_for_plugin, is_version_affected
from prescan.scanners.cve_lookup import lookup_plugin_cves, find_cves_for_core


# --- Sample Wordfence-style vulnerability data for tests ---

SAMPLE_VULN = {
    'id': 'abc-123',
    'title': 'Test Plugin <= 2.0.0 - SQL Injection',
    'software': [
        {'type': 'plugin', 'slug': 'test-plugin'}
    ],
    'affects': {
        'test-plugin': {
            'affected_versions': {
                '<= 2.0.0': True
            }
        }
    },
    'cve': 'CVE-2024-1234',
    'cvss': {'score': 8.5},
    'references': {
        'cve': ['CVE-2024-1234']
    }
}

SAMPLE_VULN_NO_CVE = {
    'id': 'def-456',
    'title': 'Another Plugin < 1.5 - XSS',
    'software': [
        {'type': 'plugin', 'slug': 'another-plugin'}
    ],
    'affects': {
        'another-plugin': {
            'affected_versions': {
                '< 1.5.0': True
            }
        }
    },
    'cvss': {'score': 5.0},
}

SAMPLE_DB = {
    'abc-123': SAMPLE_VULN,
    'def-456': SAMPLE_VULN_NO_CVE,
}

SAMPLE_CORE_VULN = {
    'id': 'core-123',
    'title': 'WordPress <= 6.4 - XSS',
    'software': [
        {'type': 'core', 'slug': 'wordpress'}
    ],
    'affects': {
        'wordpress': {
            'affected_versions': {
                '<= 6.4.0': True
            }
        }
    },
    'cve': 'CVE-2024-5678',
    'cvss': {'score': 6.1},
    'references': {
        'cve': ['CVE-2024-5678']
    }
}


def test_parse_version_simple():
    """Parse simple version strings."""
    assert parse_version('1.2.3') == (1, 2, 3)
    assert parse_version('5.0') == (5, 0)
    assert parse_version('10') == (10,)


def test_parse_version_with_suffix():
    """Parse versions with suffixes (strips non-numeric suffix)."""
    assert parse_version('1.2.3-beta') == (1, 2, 3)
    assert parse_version('2.0.0rc1') == (2, 0, 0)


def test_parse_version_invalid():
    """Invalid versions return empty tuple."""
    assert parse_version('unknown') == ()
    assert parse_version('') == ()
    assert parse_version(None) == ()


def test_version_matches_less_than():
    """Test < operator."""
    assert version_matches('1.0.0', '< 2.0.0') is True
    assert version_matches('2.0.0', '< 2.0.0') is False
    assert version_matches('3.0.0', '< 2.0.0') is False


def test_version_matches_less_equal():
    """Test <= operator."""
    assert version_matches('1.0.0', '<= 2.0.0') is True
    assert version_matches('2.0.0', '<= 2.0.0') is True
    assert version_matches('2.0.1', '<= 2.0.0') is False


def test_version_matches_greater_than():
    """Test > operator."""
    assert version_matches('3.0.0', '> 2.0.0') is True
    assert version_matches('2.0.0', '> 2.0.0') is False
    assert version_matches('1.0.0', '> 2.0.0') is False


def test_version_matches_greater_equal():
    """Test >= operator."""
    assert version_matches('3.0.0', '>= 2.0.0') is True
    assert version_matches('2.0.0', '>= 2.0.0') is True
    assert version_matches('1.0.0', '>= 2.0.0') is False


def test_version_matches_equal():
    """Test = operator."""
    assert version_matches('2.0.0', '= 2.0.0') is True
    assert version_matches('2.0.0', '2.0.0') is True  # implicit =
    assert version_matches('2.0.1', '= 2.0.0') is False


def test_version_matches_star():
    """Test * (all versions) operator."""
    assert version_matches('1.0.0', '*') is True
    assert version_matches('999.0.0', '*') is True


def test_version_matches_invalid_version():
    """Unknown installed version never matches."""
    assert version_matches('unknown', '<= 2.0.0') is False
    assert version_matches('', '<= 2.0.0') is False


def test_version_matches_different_lengths():
    """Versions of different lengths compare correctly after padding."""
    assert version_matches('1.0', '= 1.0.0') is True
    assert version_matches('5.0', '<= 5.0.0') is True
    assert version_matches('5.0', '< 5.0.0') is False


def test_version_matches_none_condition():
    """None condition returns False."""
    assert version_matches('1.0.0', None) is False


# --- Cache management tests ---


def test_get_cache_path():
    """Cache path is in project cache directory."""
    path = get_cache_path()
    assert path.name == 'wordfence-vulns.json'
    assert 'cache' in str(path)


def test_get_cache_age_hours_missing():
    """Missing cache returns None."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_path = Path(tmpdir) / 'missing.json'
        assert get_cache_age_hours(fake_path) is None


def test_get_cache_age_hours_exists():
    """Existing cache returns age in hours."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_path = Path(tmpdir) / 'cache.json'
        cache_path.write_text('{}')
        age = get_cache_age_hours(cache_path)
        assert age is not None
        assert age < 0.01  # Just created, should be ~0


def test_load_or_refresh_cache_fresh(tmp_path):
    """Fresh cache is used without network call."""
    cache_path = tmp_path / 'cache' / 'wordfence-vulns.json'
    cache_path.parent.mkdir(parents=True)
    cache_data = {'test-uuid': {'id': 'test'}}
    cache_path.write_text(json.dumps(cache_data))

    with patch('prescan.scanners.cve_lookup.get_cache_path', return_value=cache_path):
        with patch('prescan.scanners.cve_lookup._fetch_from_api') as mock_fetch:
            result, status = load_or_refresh_cache()
            mock_fetch.assert_not_called()
            assert result == cache_data
            assert status == 'fresh'


def test_load_or_refresh_cache_stale_success(tmp_path):
    """Stale cache triggers refresh, returns fresh on success."""
    cache_path = tmp_path / 'cache' / 'wordfence-vulns.json'
    cache_path.parent.mkdir(parents=True)
    old_data = {'old': True}
    cache_path.write_text(json.dumps(old_data))
    # Make it old
    old_time = time.time() - (25 * 3600)  # 25 hours ago
    os.utime(cache_path, (old_time, old_time))

    new_data = {'new': True}
    with patch('prescan.scanners.cve_lookup.get_cache_path', return_value=cache_path):
        with patch('prescan.scanners.cve_lookup._fetch_from_api', return_value=new_data):
            result, status = load_or_refresh_cache()
            assert result == new_data
            assert status == 'fresh'


def test_load_or_refresh_cache_stale_fallback(tmp_path):
    """Stale cache used if refresh fails."""
    cache_path = tmp_path / 'cache' / 'wordfence-vulns.json'
    cache_path.parent.mkdir(parents=True)
    old_data = {'old': True}
    cache_path.write_text(json.dumps(old_data))
    old_time = time.time() - (25 * 3600)
    os.utime(cache_path, (old_time, old_time))

    with patch('prescan.scanners.cve_lookup.get_cache_path', return_value=cache_path):
        with patch('prescan.scanners.cve_lookup._fetch_from_api', return_value=None):
            result, status = load_or_refresh_cache()
            assert result == old_data
            assert status == 'stale'


def test_load_or_refresh_cache_missing_no_network(tmp_path):
    """Missing cache + network failure returns None."""
    cache_path = tmp_path / 'cache' / 'wordfence-vulns.json'

    with patch('prescan.scanners.cve_lookup.get_cache_path', return_value=cache_path):
        with patch('prescan.scanners.cve_lookup._fetch_from_api', return_value=None):
            result, status = load_or_refresh_cache()
            assert result is None
            assert status == 'unavailable'


# --- is_version_affected tests ---


def test_is_version_affected_match():
    affected = {'<= 2.0.0': True}
    assert is_version_affected('1.5.0', affected) is True
    assert is_version_affected('2.0.0', affected) is True


def test_is_version_affected_no_match():
    affected = {'<= 2.0.0': True}
    assert is_version_affected('2.0.1', affected) is False
    assert is_version_affected('3.0.0', affected) is False


def test_is_version_affected_unknown():
    affected = {'<= 2.0.0': True}
    assert is_version_affected('unknown', affected) is True
    assert is_version_affected(None, affected) is True


# --- find_cves_for_plugin tests ---


def test_find_cves_for_plugin_match():
    cves = find_cves_for_plugin('test-plugin', '1.5.0', SAMPLE_DB)
    assert len(cves) == 1
    assert cves[0]['cve_id'] == 'CVE-2024-1234'
    assert cves[0]['cvss'] == 8.5


def test_find_cves_for_plugin_no_match_version():
    cves = find_cves_for_plugin('test-plugin', '3.0.0', SAMPLE_DB)
    assert len(cves) == 0


def test_find_cves_for_plugin_not_found():
    cves = find_cves_for_plugin('unknown-plugin', '1.0.0', SAMPLE_DB)
    assert len(cves) == 0


def test_find_cves_for_plugin_unknown_version():
    cves = find_cves_for_plugin('test-plugin', 'unknown', SAMPLE_DB)
    assert len(cves) == 1


def test_find_cves_for_plugin_case_insensitive():
    cves = find_cves_for_plugin('Test-Plugin', '1.5.0', SAMPLE_DB)
    assert len(cves) == 1


def test_find_cves_no_cve_id():
    cves = find_cves_for_plugin('another-plugin', '1.0.0', SAMPLE_DB)
    assert len(cves) == 1
    assert cves[0]['cve_id'] == 'WF-def-456'


# --- lookup_plugin_cves tests ---


def test_lookup_plugin_cves():
    plugins = [
        {'slug': 'test-plugin', 'version': '1.5.0'},
        {'slug': 'another-plugin', 'version': '1.0.0'},
        {'slug': 'clean-plugin', 'version': '1.0.0'},
    ]

    with patch('prescan.scanners.cve_lookup.load_or_refresh_cache', return_value=(SAMPLE_DB, 'fresh')):
        result = lookup_plugin_cves(plugins)

    assert result['cache_status'] == 'fresh'
    assert result['plugins_checked'] == 3
    assert result['plugins_with_cves'] == 2
    assert result['total_cves_matched'] == 2
    assert 'test-plugin' in result['plugins']
    assert len(result['plugins']['test-plugin']['cves']) == 1
    assert result['plugins']['clean-plugin']['cves'] == []


def test_lookup_plugin_cves_no_cache():
    plugins = [{'slug': 'test-plugin', 'version': '1.0.0'}]

    with patch('prescan.scanners.cve_lookup.load_or_refresh_cache', return_value=(None, 'unavailable')):
        result = lookup_plugin_cves(plugins)

    assert result['cache_status'] == 'unavailable'
    assert result['plugins_checked'] == 0
    assert result['plugins'] == {}


# --- find_cves_for_core tests ---


def test_find_cves_for_core():
    db = {'core-123': SAMPLE_CORE_VULN}
    cves = find_cves_for_core('6.4', db)
    assert len(cves) == 1
    assert cves[0]['cve_id'] == 'CVE-2024-5678'


def test_find_cves_for_core_not_affected():
    db = {'core-123': SAMPLE_CORE_VULN}
    cves = find_cves_for_core('6.5', db)
    assert len(cves) == 0
