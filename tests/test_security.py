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


if __name__ == '__main__':
    unittest.main()
