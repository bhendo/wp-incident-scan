"""Tests for prescan/utils.py helper functions."""

from prescan.utils import redact_email


class TestRedactEmail:
    def test_standard_email(self):
        assert redact_email('admin@example.com') == 'a***@example.com'

    def test_preserves_full_domain(self):
        assert redact_email('user@sub.domain.co.uk') == 'u***@sub.domain.co.uk'

    def test_single_char_local(self):
        assert redact_email('a@example.com') == 'a***@example.com'

    def test_empty_local_part(self):
        assert redact_email('@example.com') == '***@example.com'

    def test_no_at_sign_returns_unchanged(self):
        assert redact_email('noemail') == 'noemail'

    def test_empty_string(self):
        assert redact_email('') == ''

    def test_multiple_at_signs(self):
        # split('@', 1) handles this — only splits on first @
        result = redact_email('user@host@domain.com')
        assert result == 'u***@host@domain.com'

    def test_long_local_part(self):
        result = redact_email('verylonglocalpart@example.com')
        assert result == 'v***@example.com'
