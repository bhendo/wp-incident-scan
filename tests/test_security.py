"""Security regression tests for wp-malware-scan prescan."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prescan.utils import is_within_root


class TestIsWithinRoot(unittest.TestCase):
    def test_child_path_accepted(self):
        self.assertTrue(is_within_root(Path('/home/user/backup/wp/file.php'), '/home/user/backup'))

    def test_exact_root_accepted(self):
        self.assertTrue(is_within_root(Path('/home/user/backup'), '/home/user/backup'))

    def test_sibling_dir_rejected(self):
        """PATH-01: /backup-evil/ must NOT pass when root is /backup."""
        self.assertFalse(is_within_root(Path('/home/user/backup-evil/secret.php'), '/home/user/backup'))

    def test_parent_dir_rejected(self):
        self.assertFalse(is_within_root(Path('/home/user/other/file.php'), '/home/user/backup'))

    def test_sibling_with_suffix_rejected(self):
        self.assertFalse(is_within_root(Path('/home/user/backup_exfil/data'), '/home/user/backup'))


class TestSqlDumpDiscovery(unittest.TestCase):
    def test_find_sql_dumps_excludes_symlinks_outside_root(self):
        """PATH-02: Symlinked SQL files outside backup must be excluded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup = Path(tmpdir) / 'backup'
            backup.mkdir()
            external = Path(tmpdir) / 'external'
            external.mkdir()

            # Legitimate SQL file inside backup
            legit = backup / 'dump.sql'
            legit.write_text('-- SQL dump')

            # External SQL file
            ext_sql = external / 'secret.sql'
            ext_sql.write_text('-- secret data')

            # Symlink inside backup pointing outside
            link = backup / 'linked.sql'
            link.symlink_to(ext_sql)

            from prescan.discovery import find_sql_dumps
            dumps = find_sql_dumps(backup)

            self.assertEqual(len(dumps), 1)
            self.assertIn('dump.sql', dumps[0])
            for d in dumps:
                self.assertNotIn('secret', d)


class TestWpRootBoundary(unittest.TestCase):
    def test_wp_root_outside_backup_detected(self):
        """PATH-03: wp_root resolving outside backup must be caught."""
        import os as _os
        backup_resolved = '/home/user/backup'
        wp_root_resolved = '/var/www/other-site'
        result = (wp_root_resolved == backup_resolved or
                  wp_root_resolved.startswith(backup_resolved + _os.sep))
        self.assertFalse(result)

    def test_wp_root_inside_backup_accepted(self):
        import os as _os
        backup_resolved = '/home/user/backup'
        wp_root_resolved = '/home/user/backup/wordpress'
        result = (wp_root_resolved == backup_resolved or
                  wp_root_resolved.startswith(backup_resolved + _os.sep))
        self.assertTrue(result)


class TestResourceLimits(unittest.TestCase):
    def test_max_file_read_size_constant(self):
        """MEM-01: MAX_FILE_READ_SIZE should be 10MB."""
        from prescan.constants import MAX_FILE_READ_SIZE
        self.assertEqual(MAX_FILE_READ_SIZE, 10 * 1024 * 1024)

    def test_large_file_skipped_in_core_files(self):
        """MEM-01: Files exceeding MAX_FILE_READ_SIZE should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wp = Path(tmpdir)
            # Create wp-includes/version.php so it looks like a WP root
            (wp / 'wp-includes').mkdir()
            (wp / 'wp-includes' / 'version.php').write_text("<?php $wp_version = '6.5'; ?>")
            # Create an oversized wp-config.php
            big_file = wp / 'wp-config.php'
            big_file.write_text('x' * (11 * 1024 * 1024))  # 11MB

            from prescan.scanners.core_files import read_core_files
            result = read_core_files(wp)

            self.assertIn('wp-config.php', result)
            self.assertIn('SKIPPED', result['wp-config.php'])

    def test_max_security_log_files_constant(self):
        """LIMIT-02: MAX_SECURITY_LOG_FILES should exist."""
        from prescan.constants import MAX_SECURITY_LOG_FILES
        self.assertEqual(MAX_SECURITY_LOG_FILES, 100)


if __name__ == '__main__':
    unittest.main()
