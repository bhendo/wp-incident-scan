"""Tests for prescan/scanners/database.py SQL dump scanning."""

import os
import tempfile

from prescan.scanners.database import scan_sql_dump


def _write_sql(content: str) -> str:
    """Write SQL content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix='.sql')
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Standard WordPress wp_users INSERT (mysqldump column order)
# Columns: ID, user_login, user_pass, user_nicename, user_email,
#           user_url, user_registered, user_activation_key, user_status, display_name
# ---------------------------------------------------------------------------

SINGLE_USER_SQL = """\
CREATE TABLE `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`ID`)
);
INSERT INTO `wp_users` VALUES (1,'admin','$P$BxUhbSGOcf7NJHKA4i3sba/Ge3tPA9.','admin','admin@example.com','https://example.com','2024-01-15 10:30:00','',0,'Admin User');
"""

MULTI_USER_SQL = """\
CREATE TABLE `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`ID`)
);
INSERT INTO `wp_users` VALUES (1,'admin','$P$BxUhbSGOcf7NJHKA4i3sba/Ge3tPA9.','admin','admin@example.com','https://example.com','2024-01-15 10:30:00','',0,'Admin User'),(2,'editor','$P$BAnotherHashValue1234567890abcdef.','editor-nick','editor@example.com','','2024-03-20 14:00:00','',0,'Editor User'),(3,'subscriber','$P$BYetAnotherHashHere9876543210xyz.','sub-user','subscriber@test.org','','2024-06-01 09:15:00','',0,'Sub User');
"""


class TestUserExtraction:
    """Regression tests for BUG-03: capture group indexing in user extraction."""

    def test_single_user_email_extracted(self):
        path = _write_sql(SINGLE_USER_SQL)
        try:
            results = scan_sql_dump(path)
            assert len(results['users']) == 1
            user = results['users'][0]
            # Email should be admin@example.com, NOT 'admin' (nicename)
            assert '@' in user['email'], (
                f"Email field has no @: got '{user['email']}'. "
                f"Likely extracting nicename instead of email (BUG-03)."
            )
            assert user['email'] == 'admin@example.com'
        finally:
            os.unlink(path)

    def test_single_user_nicename_extracted(self):
        path = _write_sql(SINGLE_USER_SQL)
        try:
            results = scan_sql_dump(path)
            user = results['users'][0]
            # Nicename should be 'admin', NOT the password hash
            assert user['nicename'] == 'admin'
            assert not user['nicename'].startswith('$P$'), (
                f"Nicename contains a password hash: '{user['nicename']}'. "
                f"Likely extracting user_pass instead of nicename (BUG-03)."
            )
        finally:
            os.unlink(path)

    def test_single_user_id_and_login(self):
        path = _write_sql(SINGLE_USER_SQL)
        try:
            results = scan_sql_dump(path)
            user = results['users'][0]
            assert user['id'] == '1'
            assert user['login'] == 'admin'
        finally:
            os.unlink(path)

    def test_multi_user_insert(self):
        """Multiple users in a single INSERT VALUES() statement."""
        path = _write_sql(MULTI_USER_SQL)
        try:
            results = scan_sql_dump(path)
            assert len(results['users']) == 3

            assert results['users'][0]['login'] == 'admin'
            assert results['users'][0]['email'] == 'admin@example.com'
            assert results['users'][0]['nicename'] == 'admin'

            assert results['users'][1]['login'] == 'editor'
            assert results['users'][1]['email'] == 'editor@example.com'
            assert results['users'][1]['nicename'] == 'editor-nick'

            assert results['users'][2]['login'] == 'subscriber'
            assert results['users'][2]['email'] == 'subscriber@test.org'
            assert results['users'][2]['nicename'] == 'sub-user'
        finally:
            os.unlink(path)

    def test_password_hash_not_leaked(self):
        """Ensure password hashes don't appear in any extracted user field."""
        path = _write_sql(SINGLE_USER_SQL)
        try:
            results = scan_sql_dump(path)
            user = results['users'][0]
            for field_name, value in user.items():
                assert '$P$' not in value, (
                    f"Password hash leaked in field '{field_name}': '{value}'"
                )
        finally:
            os.unlink(path)

    def test_email_with_plus_addressing(self):
        """Emails with + addressing should be handled correctly."""
        sql = """\
CREATE TABLE `wp_users` (`ID` bigint(20));
INSERT INTO `wp_users` VALUES (1,'testuser','$P$Bhash','test-nice','test+tag@example.com','','2024-01-01 00:00:00','',0,'Test');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert len(results['users']) == 1
            assert results['users'][0]['email'] == 'test+tag@example.com'
        finally:
            os.unlink(path)

    def test_email_with_subdomain(self):
        sql = """\
CREATE TABLE `wp_users` (`ID` bigint(20));
INSERT INTO `wp_users` VALUES (1,'user1','$P$Bhash','nick','user@mail.sub.example.co.uk','','2024-01-01 00:00:00','',0,'User');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert results['users'][0]['email'] == 'user@mail.sub.example.co.uk'
        finally:
            os.unlink(path)


class TestAdminDetection:
    def test_admin_role_detected(self):
        sql = """\
CREATE TABLE `wp_usermeta` (`meta_id` bigint(20));
INSERT INTO `wp_usermeta` VALUES (1,1,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert len(results['admin_users']) == 1
            assert results['admin_users'][0]['user_id'] == '1'
        finally:
            os.unlink(path)


class TestOptionsExtraction:
    def test_siteurl_extracted(self):
        sql = """\
CREATE TABLE `wp_options` (`option_id` bigint(20));
INSERT INTO `wp_options` VALUES (1,'siteurl','https://example.com','yes');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert results['options'].get('siteurl') == 'https://example.com'
        finally:
            os.unlink(path)

    def test_active_plugins_extracted(self):
        sql = """\
CREATE TABLE `wp_options` (`option_id` bigint(20));
INSERT INTO `wp_options` VALUES (1,'active_plugins','a:2:{i:0;s:19:\"akismet/akismet.php\";i:1;s:27:\"wordfence/wordfence.php\";}','yes');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert 'active_plugins' in results['options']
            assert 'akismet' in results['options']['active_plugins']
        finally:
            os.unlink(path)


class TestSuspiciousPatterns:
    def test_script_tag_flagged(self):
        sql = """\
CREATE TABLE `wp_options` (`option_id` bigint(20));
INSERT INTO `wp_options` VALUES (1,'ihaf_insert_header','<script src=\"https://evil.com/mal.js\"></script>','yes');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            labels = [m['pattern'] for m in results['content_matches']]
            assert 'script tag' in labels
        finally:
            os.unlink(path)

    def test_eval_in_db_flagged(self):
        sql = """\
CREATE TABLE `wp_posts` (`ID` bigint(20));
INSERT INTO `wp_posts` VALUES (1,'eval(base64_decode(\"dGVzdA==\"))');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            labels = [m['pattern'] for m in results['content_matches']]
            assert 'eval()' in labels
            assert 'base64_decode' in labels
        finally:
            os.unlink(path)


class TestMultisiteSubsites:
    def test_subsite_options_extracted(self):
        sql = """\
CREATE TABLE `wp_2_options` (`option_id` bigint(20));
INSERT INTO `wp_2_options` VALUES (1,'siteurl','https://sub.example.com','yes');
INSERT INTO `wp_2_options` VALUES (2,'admin_email','subadmin@example.com','yes');
"""
        path = _write_sql(sql)
        try:
            results = scan_sql_dump(path)
            assert '2' in results['subsites']
            assert results['subsites']['2'].get('siteurl') == 'https://sub.example.com'
            assert results['subsites']['2'].get('admin_email') == 'subadmin@example.com'
        finally:
            os.unlink(path)
