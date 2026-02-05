"""Tests for prescan/scanner.py output directory resolution."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prescan.scanner import resolve_output_dir, parse_args


class TestResolveOutputDir(unittest.TestCase):
    def test_default_sibling_directory(self):
        """Default output dir is {backup_name}-scan-output/ next to backup."""
        backup = Path('/backups/clientsite')
        result = resolve_output_dir(backup, output_dir=None)
        self.assertEqual(result, Path('/backups/clientsite-scan-output'))

    def test_explicit_output_dir(self):
        """--output-dir overrides the default."""
        backup = Path('/backups/clientsite')
        result = resolve_output_dir(backup, output_dir='/tmp/my-output')
        self.assertEqual(result, Path('/tmp/my-output').resolve())

    def test_backup_with_trailing_slash(self):
        """Trailing slash on backup path doesn't affect output name."""
        backup = Path('/backups/clientsite/')
        result = resolve_output_dir(backup.resolve(), output_dir=None)
        self.assertIn('clientsite-scan-output', str(result))

    def test_symlinked_backup_resolved(self):
        """Symlinked backup path uses resolved name for sibling dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_resolved = Path(tmpdir).resolve()
            real = tmpdir_resolved / 'real-backup'
            real.mkdir()
            link = tmpdir_resolved / 'link-backup'
            link.symlink_to(real)

            result = resolve_output_dir(link.resolve(), output_dir=None)
            self.assertEqual(result, tmpdir_resolved / 'real-backup-scan-output')


class TestParseArgs(unittest.TestCase):
    def test_backup_path_required(self):
        """backup_path is a required positional argument."""
        args = parse_args(['/backups/clientsite'])
        self.assertEqual(args.backup_path, '/backups/clientsite')
        self.assertIsNone(args.output_dir)

    def test_output_dir_flag(self):
        """--output-dir is optional."""
        args = parse_args(['/backups/clientsite', '--output-dir', '/tmp/output'])
        self.assertEqual(args.backup_path, '/backups/clientsite')
        self.assertEqual(args.output_dir, '/tmp/output')


class TestOutputIsolation(unittest.TestCase):
    def test_prescan_does_not_write_to_backup(self):
        """SEC-03: Prescan must not create files inside the backup directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_resolved = Path(tmpdir).resolve()
            backup = tmpdir_resolved / 'backup'
            backup.mkdir()
            wp_inc = backup / 'wp-includes'
            wp_inc.mkdir()
            (wp_inc / 'version.php').write_text(
                "<?php\n$wp_version = '6.5';\n"
            )
            (backup / 'wp-config.php').write_text("<?php // config ?>")
            (backup / 'index.php').write_text("<?php // index ?>")
            content_dir = backup / 'wp-content'
            content_dir.mkdir()
            (content_dir / 'plugins').mkdir()
            (content_dir / 'themes').mkdir()

            # Snapshot backup contents before scan
            before = set()
            for f in backup.rglob('*'):
                before.add(f.relative_to(backup))

            # Run prescan
            from prescan.scanner import main
            with patch('sys.argv', ['prescan', str(backup)]):
                main()

            # Snapshot backup contents after scan
            after = set()
            for f in backup.rglob('*'):
                after.add(f.relative_to(backup))

            # No new files should exist in backup
            new_files = after - before
            self.assertEqual(new_files, set(),
                             f'Prescan wrote files into backup: {new_files}')

            # Output should exist in sibling directory
            output_dir = tmpdir_resolved / 'backup-scan-output'
            self.assertTrue(output_dir.exists())
            self.assertTrue((output_dir / 'wp-prescan-results.json').exists())
            self.assertTrue((output_dir / 'prescan-data').is_dir())

    def test_prescan_index_includes_output_dir(self):
        """Prescan JSON index must include output_dir for orchestrator."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_resolved = Path(tmpdir).resolve()
            backup = tmpdir_resolved / 'backup'
            backup.mkdir()
            wp_inc = backup / 'wp-includes'
            wp_inc.mkdir()
            (wp_inc / 'version.php').write_text(
                "<?php\n$wp_version = '6.5';\n"
            )
            (backup / 'wp-config.php').write_text("<?php // config ?>")
            (backup / 'index.php').write_text("<?php // index ?>")
            content_dir = backup / 'wp-content'
            content_dir.mkdir()
            (content_dir / 'plugins').mkdir()
            (content_dir / 'themes').mkdir()

            from prescan.scanner import main
            with patch('sys.argv', ['prescan', str(backup)]):
                main()

            output_dir = tmpdir_resolved / 'backup-scan-output'
            with open(output_dir / 'wp-prescan-results.json') as f:
                index = json.load(f)

            self.assertIn('output_dir', index['_meta'])
            self.assertEqual(index['_meta']['output_dir'], str(output_dir))


if __name__ == '__main__':
    unittest.main()
