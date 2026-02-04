"""Tests for prescan/scanners/timestamps.py timestamp analysis."""

import os
import tempfile
import time
from pathlib import Path

from prescan.scanners.timestamps import analyze_timestamps


def _create_test_structure(root: Path, files: list[str], mtime: float | None = None):
    """Create test files with optional modification time."""
    for f in files:
        fpath = root / f
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text('<?php // test')
        if mtime is not None:
            os.utime(fpath, (mtime, mtime))


def test_cluster_includes_dir_distribution():
    """Clusters should include directory distribution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create minimal WP structure for detection
        (root / 'wp-includes').mkdir()
        (root / 'wp-includes' / 'version.php').write_text('<?php $wp_version = "6.4";')

        # Create 60 files across different dirs (>50 to trigger clustering)
        mtime = time.time()
        files = (
            [f'wp-admin/file{i}.php' for i in range(20)] +
            [f'wp-includes/file{i}.php' for i in range(15)] +
            [f'wp-content/plugins/akismet/file{i}.php' for i in range(15)] +
            [f'wp-content/uploads/2024/01/file{i}.jpg' for i in range(10)]
        )
        _create_test_structure(root, files, mtime)

        result = analyze_timestamps(root, '6.4')
        clusters = result['modification_clusters']

        assert len(clusters) >= 1, 'Expected at least one cluster'
        cluster = list(clusters.values())[0]

        assert 'dir_distribution' in cluster
        dir_dist = cluster['dir_distribution']
        assert 'wp-admin' in dir_dist
        assert dir_dist['wp-admin'] == 20
        assert 'wp-content/plugins' in dir_dist


def test_cluster_includes_ext_distribution():
    """Clusters should include file extension distribution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / 'wp-includes').mkdir()
        (root / 'wp-includes' / 'version.php').write_text('<?php $wp_version = "6.4";')

        mtime = time.time()
        files = (
            [f'wp-admin/file{i}.php' for i in range(30)] +
            [f'wp-includes/file{i}.js' for i in range(15)] +
            [f'wp-content/themes/theme/style{i}.css' for i in range(10)]
        )
        _create_test_structure(root, files, mtime)

        result = analyze_timestamps(root, '6.4')
        clusters = result['modification_clusters']
        cluster = list(clusters.values())[0]

        assert 'ext_distribution' in cluster
        ext_dist = cluster['ext_distribution']
        assert '.php' in ext_dist
        assert ext_dist['.php'] == 31  # 30 + version.php
        assert '.js' in ext_dist
        assert ext_dist['.js'] == 15


def test_cluster_includes_pct_of_total():
    """Clusters should include percentage of total files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / 'wp-includes').mkdir()
        (root / 'wp-includes' / 'version.php').write_text('<?php $wp_version = "6.4";')

        mtime = time.time()
        files = [f'wp-admin/file{i}.php' for i in range(100)]
        _create_test_structure(root, files, mtime)

        result = analyze_timestamps(root, '6.4')
        clusters = result['modification_clusters']
        cluster = list(clusters.values())[0]

        assert 'pct_of_total' in cluster
        # 101 files total (100 + version.php), cluster has 101 files
        assert cluster['pct_of_total'] == 100.0


def test_distributions_capped_at_10_entries():
    """Dir and ext distributions should be capped at 10 entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / 'wp-includes').mkdir()
        (root / 'wp-includes' / 'version.php').write_text('<?php $wp_version = "6.4";')

        mtime = time.time()
        # Create files in 15 different directories
        files = []
        for i in range(15):
            files.append(f'dir{i}/file.php')
        # And with 15 different extensions
        for i in range(15):
            files.append(f'root/file{i}.ext{i}')
        # Need at least 51 files total
        files.extend([f'root/extra{i}.php' for i in range(30)])
        _create_test_structure(root, files, mtime)

        result = analyze_timestamps(root, '6.4')
        clusters = result['modification_clusters']
        cluster = list(clusters.values())[0]

        assert len(cluster['dir_distribution']) <= 10
        assert len(cluster['ext_distribution']) <= 10


def test_files_without_extension():
    """Files without extension should be counted as '(no ext)'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / 'wp-includes').mkdir()
        (root / 'wp-includes' / 'version.php').write_text('<?php $wp_version = "6.4";')

        mtime = time.time()
        files = [f'root/file{i}' for i in range(55)]  # no extension
        _create_test_structure(root, files, mtime)

        result = analyze_timestamps(root, '6.4')
        clusters = result['modification_clusters']
        cluster = list(clusters.values())[0]

        assert '(no ext)' in cluster['ext_distribution']
        assert cluster['ext_distribution']['(no ext)'] == 55
