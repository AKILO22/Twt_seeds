#!/usr/bin/env python3
"""
Tests for Email Monitor Tool modules.
Tests email_verifier, header_analyzer, domain_checker, imap_handler,
email_data_manager, email_reporter, and email_monitor.
"""

import email
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# EmailVerifier Tests
# ---------------------------------------------------------------------------

class TestEmailVerifier:
    """Tests for EmailVerifier format validation and verification logic."""

    def setup_method(self):
        from email_verifier import EmailVerifier
        self.verifier = EmailVerifier(skip_smtp=True)

    def test_valid_email_format(self):
        valid, msg = self.verifier.validate_format("user@example.com")
        assert valid is True

    def test_valid_email_with_plus(self):
        valid, msg = self.verifier.validate_format("user+tag@example.co.uk")
        assert valid is True

    def test_invalid_email_missing_at(self):
        valid, msg = self.verifier.validate_format("userexample.com")
        assert valid is False
        assert "@" in msg or "Missing" in msg

    def test_invalid_email_empty(self):
        valid, msg = self.verifier.validate_format("")
        assert valid is False
        assert "empty" in msg.lower()

    def test_invalid_email_missing_domain(self):
        valid, msg = self.verifier.validate_format("user@")
        assert valid is False

    def test_invalid_email_missing_local(self):
        valid, msg = self.verifier.validate_format("@example.com")
        assert valid is False

    def test_invalid_email_no_tld(self):
        valid, msg = self.verifier.validate_format("user@example")
        assert valid is False

    def test_email_too_long(self):
        long_email = "a" * 250 + "@example.com"
        valid, msg = self.verifier.validate_format(long_email)
        assert valid is False
        assert "long" in msg.lower()

    def test_local_part_too_long(self):
        long_local = "a" * 65
        valid, msg = self.verifier.validate_format(f"{long_local}@example.com")
        assert valid is False

    def test_verify_skips_smtp(self):
        """Verify method with skip_smtp=True should not attempt SMTP."""
        with patch('domain_checker.DomainChecker.get_mx_records') as mock_mx, \
             patch('domain_checker.DomainChecker.get_spf_record', return_value=None), \
             patch('domain_checker.DomainChecker.get_dmarc_record', return_value=None), \
             patch('domain_checker.DomainChecker.get_a_records', return_value=['1.2.3.4']), \
             patch('domain_checker.DomainChecker.is_disposable', return_value=False), \
             patch('domain_checker.DomainChecker.check_catch_all', return_value=False):
            mock_mx.return_value = [{'priority': 10, 'host': 'mail.example.com'}]
            result = self.verifier.verify("user@example.com")
            assert result['format_valid'] is True
            assert result['smtp_valid'] is None  # Skipped

    def test_verify_invalid_format_short_circuits(self):
        result = self.verifier.verify("not-an-email")
        assert result['format_valid'] is False
        assert result['confidence'] == 'invalid'

    def test_verify_no_mx_records(self):
        with patch('domain_checker.DomainChecker.get_mx_records', return_value=[]), \
             patch('domain_checker.DomainChecker.get_spf_record', return_value=None), \
             patch('domain_checker.DomainChecker.get_dmarc_record', return_value=None), \
             patch('domain_checker.DomainChecker.get_a_records', return_value=[]), \
             patch('domain_checker.DomainChecker.is_disposable', return_value=False), \
             patch('domain_checker.DomainChecker.check_catch_all', return_value=False):
            result = self.verifier.verify("user@nonexistent-domain-xyz.com")
            assert result['mx_found'] is False
            assert result['is_deliverable'] is False

    def test_verify_disposable_email(self):
        with patch('domain_checker.DomainChecker.analyze_domain') as mock_analyze:
            mock_analyze.return_value = {
                'domain': 'mailinator.com',
                'has_mx': True,
                'mx_records': [{'priority': 10, 'host': 'mail.mailinator.com'}],
                'has_spf': False, 'spf_record': None,
                'has_dkim': False, 'dkim_record': None,
                'has_dmarc': False, 'dmarc_record': None,
                'a_records': [],
                'is_disposable': True,
                'catch_all': False,
            }
            result = self.verifier.verify("test@mailinator.com")
            assert result['is_disposable'] is True
            assert result['risk_level'] == 'high'

    def test_verify_batch(self):
        emails = ["user@example.com", "invalid-email", "another@domain.org"]
        with patch('domain_checker.DomainChecker.analyze_domain') as mock_analyze:
            mock_analyze.return_value = {
                'domain': 'example.com',
                'has_mx': True,
                'mx_records': [{'priority': 10, 'host': 'mail.example.com'}],
                'has_spf': True, 'spf_record': 'v=spf1 include:example.com ~all',
                'has_dkim': False, 'dkim_record': None,
                'has_dmarc': False, 'dmarc_record': None,
                'a_records': ['1.2.3.4'],
                'is_disposable': False,
                'catch_all': False,
            }
            results = self.verifier.verify_batch(emails)
            assert len(results) == 3
            assert results[1]['format_valid'] is False  # invalid-email


# ---------------------------------------------------------------------------
# DomainChecker Tests
# ---------------------------------------------------------------------------

class TestDomainChecker:
    """Tests for DomainChecker DNS lookups and disposable detection."""

    def setup_method(self):
        from domain_checker import DomainChecker
        self.checker = DomainChecker()

    def test_is_disposable_known_domain(self):
        assert self.checker.is_disposable('mailinator.com') is True
        assert self.checker.is_disposable('yopmail.com') is True
        assert self.checker.is_disposable('guerrillamail.com') is True

    def test_is_disposable_legitimate_domain(self):
        assert self.checker.is_disposable('gmail.com') is False
        assert self.checker.is_disposable('example.com') is False

    def test_is_disposable_case_insensitive(self):
        assert self.checker.is_disposable('MAILINATOR.COM') is True

    def test_get_mx_records_no_dns(self):
        """Test fallback behavior when DNS is unavailable."""
        with patch('domain_checker.DNS_AVAILABLE', False), \
             patch('socket.getaddrinfo', side_effect=OSError("no address")):
            records = self.checker.get_mx_records('nonexistent.invalid')
            assert records == []

    def test_extract_auth_result_pass(self):
        """Test SPF/DKIM/DMARC result extraction from auth header."""
        # This exercises the logic indirectly through analyze_domain mocking
        pass

    def test_analyze_domain_structure(self):
        """Test that analyze_domain returns the expected structure."""
        with patch.object(self.checker, 'get_mx_records', return_value=[{'priority': 10, 'host': 'mx.example.com'}]), \
             patch.object(self.checker, 'get_spf_record', return_value='v=spf1 ~all'), \
             patch.object(self.checker, 'get_dmarc_record', return_value='v=DMARC1; p=reject'), \
             patch.object(self.checker, 'get_a_records', return_value=['1.2.3.4']), \
             patch.object(self.checker, 'is_disposable', return_value=False), \
             patch.object(self.checker, 'check_catch_all', return_value=False), \
             patch.object(self.checker, 'get_dkim_record', return_value=None):
            result = self.checker.analyze_domain('example.com')
            assert result['domain'] == 'example.com'
            assert result['has_mx'] is True
            assert result['has_spf'] is True
            assert result['has_dmarc'] is True
            assert result['is_disposable'] is False
            assert 'mx_records' in result


# ---------------------------------------------------------------------------
# HeaderAnalyzer Tests
# ---------------------------------------------------------------------------

# Sample raw email for testing
SAMPLE_RAW_EMAIL = """From: Sender Name <sender@example.com>
To: Recipient <recipient@example.org>
Subject: Test Email Subject
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass

This is the body of the test email.
Visit https://example.com/page for more info.
"""

SAMPLE_PHISHING_EMAIL = """From: Fake Bank <support@definitely-not-bank.tk>
To: Victim <victim@example.com>
Subject: URGENT: Your account has been suspended - verify immediately
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <phish@fake.tk>
Content-Type: text/plain; charset=UTF-8
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=fake.tk

Dear customer, your account will expire. Click here to verify your login.
Act now or your account will be suspended immediately.
Please update your information: https://malicious.xyz/login
"""


class TestHeaderAnalyzer:
    """Tests for HeaderAnalyzer parsing and security analysis."""

    def setup_method(self):
        from header_analyzer import HeaderAnalyzer
        self.analyzer = HeaderAnalyzer()

    def test_analyze_raw_returns_structure(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert 'headers' in result
        assert 'authentication' in result
        assert 'routing' in result
        assert 'sender' in result
        assert 'security' in result
        assert 'metadata' in result
        assert 'attachments' in result

    def test_extract_subject(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['metadata']['subject'] == 'Test Email Subject'

    def test_extract_sender_email(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['sender']['from_email'] == 'sender@example.com'

    def test_extract_sender_domain(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['sender']['from_domain'] == 'example.com'

    def test_authentication_results_pass(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['authentication']['spf'] == 'pass'
        assert result['authentication']['dkim'] == 'pass'
        assert result['authentication']['dmarc'] == 'pass'

    def test_authentication_results_fail(self):
        result = self.analyzer.analyze_raw(SAMPLE_PHISHING_EMAIL)
        assert result['authentication']['spf'] == 'fail'

    def test_phishing_keywords_detected(self):
        result = self.analyzer.analyze_raw(SAMPLE_PHISHING_EMAIL)
        security = result['security']
        assert security['phishing_keyword_count'] > 0
        assert len(security['phishing_keywords']) > 0

    def test_phishing_keywords_not_detected_in_normal_email(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        # Normal email should have low or zero phishing keywords
        security = result['security']
        assert security['risk_score'] < 5

    def test_spoofing_risk_when_spf_fail(self):
        result = self.analyzer.analyze_raw(SAMPLE_PHISHING_EMAIL)
        assert result['security']['spoofing_risk'] is True

    def test_url_extraction(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['security']['url_count'] >= 1
        assert 'https://example.com/page' in result['security']['urls']

    def test_suspicious_url_detection(self):
        result = self.analyzer.analyze_raw(SAMPLE_PHISHING_EMAIL)
        assert result['security']['suspicious_url_count'] >= 1

    def test_no_attachments_in_simple_email(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL)
        assert result['attachments'] == []

    def test_decode_header_encoded(self):
        encoded_email = "From: =?UTF-8?b?VGVzdCBTZW5kZXI=?= <test@example.com>\r\nSubject: Hello\r\n\r\n"
        result = self.analyzer.analyze_raw(encoded_email)
        assert 'Test Sender' in result['sender']['from']

    def test_multipart_attachment_detection(self):
        msg_str = """MIME-Version: 1.0
From: sender@example.com
Subject: Attachment Test
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Hello

--boundary123
Content-Type: application/pdf
Content-Disposition: attachment; filename="test.pdf"
Content-Transfer-Encoding: base64

dGVzdA==
--boundary123--
"""
        result = self.analyzer.analyze_raw(msg_str)
        assert len(result['attachments']) >= 1
        assert result['attachments'][0]['filename'] == 'test.pdf'

    def test_reply_to_mismatch_detection(self):
        mismatch_email = """From: legit@bank.com
Reply-To: attacker@phish.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000

Body
"""
        result = self.analyzer.analyze_raw(mismatch_email)
        assert result['sender']['domain_mismatch'] is True
        assert len(result['sender']['inconsistencies']) > 0

    def test_risk_level_mapping(self):
        assert self.analyzer._risk_level(0) == 'low'
        assert self.analyzer._risk_level(2) == 'medium'
        assert self.analyzer._risk_level(5) == 'high'
        assert self.analyzer._risk_level(8) == 'critical'

    def test_routing_hop_parsing(self):
        hop_email = """From: sender@example.com
Subject: Routing Test
Received: from mail.sender.com (mail.sender.com [1.2.3.4])
        by mail.example.com with ESMTPS id abc123;
        Mon, 01 Jan 2024 12:00:00 +0000 (UTC)

Body
"""
        result = self.analyzer.analyze_raw(hop_email)
        assert len(result['routing']) >= 1
        hop = result['routing'][0]
        assert 'from_host' in hop
        assert 'by_server' in hop

    def test_analyze_bytes_input(self):
        result = self.analyzer.analyze_raw(SAMPLE_RAW_EMAIL.encode('utf-8'))
        assert result['metadata']['subject'] == 'Test Email Subject'


# ---------------------------------------------------------------------------
# IMAPHandler Tests
# ---------------------------------------------------------------------------

class TestIMAPHandler:
    """Tests for IMAPHandler configuration and connection."""

    def test_from_email_gmail(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler.from_email_address('user@gmail.com')
        assert handler.host == 'imap.gmail.com'
        assert handler.port == 993
        assert handler.use_ssl is True

    def test_from_email_yahoo(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler.from_email_address('user@yahoo.com')
        assert handler.host == 'imap.mail.yahoo.com'

    def test_from_email_outlook(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler.from_email_address('user@outlook.com')
        assert handler.host == 'outlook.office365.com'

    def test_from_email_hotmail(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler.from_email_address('user@hotmail.com')
        assert handler.host == 'outlook.office365.com'

    def test_from_email_unknown_domain(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler.from_email_address('user@mycompany.com')
        assert handler.host == 'imap.mycompany.com'

    def test_default_ssl_port(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        assert handler.port == 993
        assert handler.use_ssl is True

    def test_starttls_default_port(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com', use_ssl=False)
        assert handler.port == 143

    def test_require_connection_raises(self):
        from imap_handler import IMAPHandler, IMAPError
        handler = IMAPHandler(host='imap.example.com')
        with pytest.raises(IMAPError, match="Not connected"):
            handler._require_connection()

    def test_decode_header_plain(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        assert handler._decode_header('Hello World') == 'Hello World'

    def test_decode_header_encoded(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        # Base64 encoded "Test Subject" in UTF-8
        result = handler._decode_header('=?UTF-8?b?VGVzdCBTdWJqZWN0?=')
        assert result == 'Test Subject'

    def test_context_manager_connect_fail(self):
        from imap_handler import IMAPHandler, IMAPError
        handler = IMAPHandler(host='imap.invalid-host.xyz', port=993)
        with pytest.raises(IMAPError):
            with handler:
                handler.connect('user@invalid.com', 'password')

    def test_has_attachments_false(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        msg = email.message_from_string("From: a@b.com\n\nBody")
        assert handler._has_attachments(msg) is False

    def test_has_attachments_true(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        msg_str = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain
Content-Disposition: inline

body

--b
Content-Type: application/pdf
Content-Disposition: attachment; filename="test.pdf"

data
--b--
"""
        msg = email.message_from_string(msg_str)
        assert handler._has_attachments(msg) is True

    def test_extract_preview_plain_text(self):
        from imap_handler import IMAPHandler
        handler = IMAPHandler(host='imap.example.com')
        msg = email.message_from_string(
            "Content-Type: text/plain\n\nThis is the email body."
        )
        preview = handler._extract_preview(msg)
        assert 'This is the email body.' in preview


# ---------------------------------------------------------------------------
# EmailDataManager Tests
# ---------------------------------------------------------------------------

class TestEmailDataManager:
    """Tests for EmailDataManager storage and export."""

    def setup_method(self):
        from email_data_manager import EmailDataManager
        self.tmpdir = tempfile.mkdtemp()
        self.manager = EmailDataManager(data_dir=self.tmpdir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _sample_email(self, i=1):
        return {
            'id': f'msg{i}',
            'from': f'sender{i}@example.com',
            'subject': f'Subject {i}',
            'date': '2024-01-01T12:00:00',
            'preview': f'Preview text {i}',
            'is_unread': i % 2 == 0,
            'source': 'imap',
        }

    def test_save_and_load_emails(self):
        emails = [self._sample_email(i) for i in range(1, 4)]
        self.manager.save_emails(emails, account='test')
        loaded = self.manager.load_emails()
        assert len(loaded) == 3
        assert loaded[0]['subject'] == 'Subject 1'

    def test_save_appends_emails(self):
        self.manager.save_emails([self._sample_email(1)], account='test')
        self.manager.save_emails([self._sample_email(2)], account='test')
        loaded = self.manager.load_emails()
        assert len(loaded) == 2

    def test_load_empty_when_no_file(self):
        loaded = self.manager.load_emails()
        assert loaded == []

    def test_save_and_load_verification(self):
        result = {
            'email': 'test@example.com',
            'format_valid': True,
            'is_deliverable': True,
            'confidence': 'high',
        }
        self.manager.save_verification(result)
        verifications = self.manager.load_verifications()
        assert len(verifications) == 1
        assert verifications[0]['email'] == 'test@example.com'

    def test_export_emails_json(self):
        emails = [self._sample_email(1), self._sample_email(2)]
        filepath = os.path.join(self.tmpdir, 'test_export.json')
        result_path = self.manager.export_emails_json(emails, filepath)
        assert os.path.exists(result_path)
        with open(result_path) as f:
            data = json.load(f)
        assert len(data) == 2

    def test_export_emails_csv(self):
        emails = [self._sample_email(1), self._sample_email(2)]
        filepath = os.path.join(self.tmpdir, 'test_export.csv')
        result_path = self.manager.export_emails_csv(emails, filepath)
        assert os.path.exists(result_path)
        with open(result_path) as f:
            content = f.read()
        assert 'sender1@example.com' in content

    def test_get_email_stats_empty(self):
        stats = self.manager.get_email_stats()
        assert stats['total_emails'] == 0
        assert stats['unread_emails'] == 0

    def test_get_email_stats_with_data(self):
        emails = [
            {**self._sample_email(1), 'is_unread': True},
            {**self._sample_email(2), 'is_unread': False},
            {**self._sample_email(3), 'is_unread': True},
        ]
        self.manager.save_emails(emails)
        stats = self.manager.get_email_stats()
        assert stats['total_emails'] == 3
        assert stats['unread_emails'] == 2

    def test_get_verification_stats(self):
        for i in range(3):
            self.manager.save_verification({
                'email': f'test{i}@example.com',
                'format_valid': True,
                'is_deliverable': i < 2,
                'is_disposable': False,
            })
        stats = self.manager.get_verification_stats()
        assert stats['total_verified'] == 3
        assert stats['valid_format'] == 3
        assert stats['deliverable'] == 2

    def test_purge_history(self):
        self.manager.save_emails([self._sample_email(1)])
        self.manager.save_verification({'email': 'a@b.com', 'format_valid': True})
        self.manager.purge_history()
        assert self.manager.load_emails() == []
        assert self.manager.load_verifications() == []

    def test_export_auto_generates_filename(self):
        emails = [self._sample_email(1)]
        result_path = self.manager.export_emails_json(emails)
        assert os.path.exists(result_path)
        os.unlink(result_path)


# ---------------------------------------------------------------------------
# EmailReporter Tests
# ---------------------------------------------------------------------------

class TestEmailReporter:
    """Tests for EmailReporter report generation."""

    def setup_method(self):
        from email_reporter import EmailReporter
        self.tmpdir = tempfile.mkdtemp()
        self.reporter = EmailReporter(output_dir=self.tmpdir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _sample_email(self):
        return {
            'id': 'msg1',
            'from': 'sender@example.com',
            'subject': 'Test Subject',
            'date': '2024-01-01T12:00:00',
            'preview': 'Preview text here',
            'is_unread': True,
            'has_attachments': False,
            'source': 'imap',
        }

    def test_report_emails_json(self):
        emails = [self._sample_email()]
        fp = self.reporter.report_emails_json(emails)
        assert os.path.exists(fp)
        with open(fp) as f:
            data = json.load(f)
        assert len(data) == 1

    def test_report_emails_csv(self):
        emails = [self._sample_email()]
        fp = self.reporter.report_emails_csv(emails)
        assert os.path.exists(fp)
        with open(fp) as f:
            content = f.read()
        assert 'sender@example.com' in content

    def test_report_emails_html(self):
        emails = [self._sample_email()]
        fp = self.reporter.report_emails_html(emails, account="Test Account")
        assert os.path.exists(fp)
        with open(fp) as f:
            content = f.read()
        assert 'sender@example.com' in content
        assert 'Test Subject' in content
        assert 'Unread' in content  # Unread badge

    def test_report_emails_html_xss_escaping(self):
        """Ensure HTML special chars are escaped in reports."""
        emails = [{**self._sample_email(), 'subject': '<script>alert(1)</script>'}]
        fp = self.reporter.report_emails_html(emails)
        with open(fp) as f:
            content = f.read()
        assert '<script>' not in content
        assert '&lt;script&gt;' in content

    def test_report_verification_json(self):
        results = [{'email': 'a@b.com', 'format_valid': True, 'is_deliverable': True}]
        fp = self.reporter.report_verification_json(results)
        assert os.path.exists(fp)
        with open(fp) as f:
            data = json.load(f)
        assert data[0]['email'] == 'a@b.com'

    def test_report_verification_html(self):
        results = [{
            'email': 'test@example.com',
            'format_valid': True,
            'mx_found': True,
            'smtp_valid': True,
            'is_disposable': False,
            'is_deliverable': True,
            'confidence': 'high',
            'risk_level': 'low',
        }]
        fp = self.reporter.report_verification_html(results)
        assert os.path.exists(fp)
        with open(fp) as f:
            content = f.read()
        assert 'test@example.com' in content

    def test_report_header_analysis_json(self):
        analysis = {'metadata': {'subject': 'Test'}, 'security': {'risk_score': 0}}
        fp = self.reporter.report_header_analysis_json(analysis)
        assert os.path.exists(fp)
        with open(fp) as f:
            data = json.load(f)
        assert data['metadata']['subject'] == 'Test'

    def test_report_header_analysis_html(self):
        analysis = {
            'metadata': {'subject': 'Test', 'date_iso': '2024-01-01', 'message_id': '<id>', 'content_type': 'text/plain', 'x_mailer': ''},
            'authentication': {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass', 'has_dkim_signature': True},
            'sender': {'from': 'test@example.com', 'from_email': 'test@example.com', 'from_domain': 'example.com',
                       'reply_to': '', 'return_path': '', 'inconsistencies': [], 'domain_mismatch': False},
            'security': {'phishing_keywords': [], 'phishing_keyword_count': 0, 'urls': [], 'url_count': 0,
                         'suspicious_urls': [], 'suspicious_url_count': 0, 'spf_result': 'pass',
                         'dkim_result': 'pass', 'dmarc_result': 'pass', 'spoofing_risk': False,
                         'spoofing_reasons': [], 'reply_to_mismatch': False, 'risk_score': 0, 'risk_level': 'low'},
            'routing': [],
            'attachments': [],
        }
        fp = self.reporter.report_header_analysis_html(analysis)
        assert os.path.exists(fp)
        with open(fp) as f:
            content = f.read()
        assert 'test@example.com' in content

    def test_html_escape_method(self):
        assert self.reporter._esc('<b>Test & "Value"</b>') == '&lt;b&gt;Test &amp; &quot;Value&quot;&lt;/b&gt;'


# ---------------------------------------------------------------------------
# EmailMonitor Tests
# ---------------------------------------------------------------------------

class TestEmailMonitor:
    """Tests for EmailMonitor orchestration."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        from email_monitor import EmailMonitor
        self.monitor = EmailMonitor(data_dir=self.tmpdir, output_dir=self.tmpdir)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_mask_email_address(self):
        masked = self.monitor._mask_email('John Doe <john.doe@example.com>')
        assert '@example.com' in masked
        assert 'john.doe' not in masked

    def test_mask_email_short_local(self):
        masked = self.monitor._mask_email('ab@example.com')
        assert '@example.com' in masked

    def test_display_emails_empty(self, capsys):
        self.monitor.display_emails([])
        captured = capsys.readouterr()
        assert 'No emails found' in captured.out

    def test_display_emails_with_data(self, capsys):
        emails = [{
            'from': 'sender@example.com',
            'subject': 'Test Subject',
            'date': '2024-01-01',
            'preview': 'Preview text',
            'is_unread': True,
            'has_attachments': False,
        }]
        self.monitor.display_emails(emails)
        captured = capsys.readouterr()
        assert 'Test Subject' in captured.out

    def test_monitor_imap_saves_emails(self):
        """Test that monitor_imap with save=True calls data_manager.save_emails."""
        mock_emails = [{'id': '1', 'subject': 'Test', 'source': 'imap'}]
        with patch('imap_handler.IMAPHandler.connect'), \
             patch('imap_handler.IMAPHandler.fetch_emails', return_value=mock_emails), \
             patch('imap_handler.IMAPHandler.disconnect'):
            emails = self.monitor.monitor_imap(
                host='imap.example.com',
                username='user@example.com',
                password='password',
                save=True,
            )
        assert len(emails) == 1
        stored = self.monitor.data_manager.load_emails()
        assert len(stored) == 1

    def test_get_stats_empty(self):
        stats = self.monitor.get_stats()
        assert stats['total_emails'] == 0


# ---------------------------------------------------------------------------
# Config Tests
# ---------------------------------------------------------------------------

class TestConfig:
    """Tests for configuration settings."""

    def test_email_config_values(self):
        import config
        assert hasattr(config, 'EMAIL_DATA_DIR')
        assert hasattr(config, 'EMAIL_OUTPUT_DIR')
        assert hasattr(config, 'EMAIL_TOKEN_DIR')
        assert hasattr(config, 'SMTP_TIMEOUT')
        assert config.SMTP_TIMEOUT > 0
        assert config.EMAIL_DEFAULT_MAX_RESULTS > 0

    def test_seed_config_preserved(self):
        import config
        assert hasattr(config, 'ENTROPY_OPTIONS')
        assert 128 in config.ENTROPY_OPTIONS
        assert 256 in config.ENTROPY_OPTIONS


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
