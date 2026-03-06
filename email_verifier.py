#!/usr/bin/env python3
"""
Email Verifier Module
Comprehensive email address verification: format, DNS/MX, and SMTP.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from domain_checker import DomainChecker

# RFC 5322-compliant email regex (simplified but robust)
_EMAIL_REGEX = re.compile(
    r"^(?!\.)(?!.*\.\.)"           # no leading dot, no consecutive dots
    r"[a-zA-Z0-9._%+\-]+"          # local part
    r"@"
    r"(?:[a-zA-Z0-9]"               # domain labels
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,63}$"             # TLD
)

# Maximum lengths per RFC 5321
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64
MAX_DOMAIN_LENGTH = 253


class EmailVerifier:
    """
    Comprehensive email address verifier.

    Performs:
    1. RFC 5322 format validation
    2. DNS/MX record lookup
    3. SMTP RCPT TO verification
    4. Disposable email detection
    5. Catch-all detection
    """

    def __init__(self, smtp_timeout: int = 10, skip_smtp: bool = False):
        """
        Initialize the email verifier.

        Args:
            smtp_timeout: Timeout in seconds for SMTP verification
            skip_smtp: Skip SMTP verification (faster but less accurate)
        """
        self.skip_smtp = skip_smtp
        self.domain_checker = DomainChecker(smtp_timeout=smtp_timeout)

    # ------------------------------------------------------------------
    # Format Validation
    # ------------------------------------------------------------------

    def validate_format(self, email_address: str) -> Tuple[bool, str]:
        """
        Validate email address format per RFC 5322/5321.

        Args:
            email_address: Email address to validate

        Returns:
            Tuple of (is_valid: bool, message: str)
        """
        if not email_address:
            return False, "Email address is empty"

        if len(email_address) > MAX_EMAIL_LENGTH:
            return False, f"Email too long (max {MAX_EMAIL_LENGTH} characters)"

        if '@' not in email_address:
            return False, "Missing '@' symbol"

        local, _, domain = email_address.rpartition('@')

        if len(local) == 0:
            return False, "Local part (before @) is empty"

        if len(local) > MAX_LOCAL_LENGTH:
            return False, f"Local part too long (max {MAX_LOCAL_LENGTH} characters)"

        if len(domain) == 0:
            return False, "Domain (after @) is empty"

        if len(domain) > MAX_DOMAIN_LENGTH:
            return False, f"Domain too long (max {MAX_DOMAIN_LENGTH} characters)"

        if not _EMAIL_REGEX.match(email_address):
            return False, "Invalid email format (RFC 5322 violation)"

        if '.' not in domain:
            return False, "Domain missing TLD"

        return True, "Valid email format"

    # ------------------------------------------------------------------
    # Full Verification
    # ------------------------------------------------------------------

    def verify(self, email_address: str) -> Dict:
        """
        Perform full verification of an email address.

        Args:
            email_address: Email address to verify

        Returns:
            Dict with comprehensive verification results
        """
        email_address = email_address.strip().lower()
        result = {
            'email': email_address,
            'format_valid': False,
            'domain_valid': False,
            'mx_found': False,
            'smtp_valid': None,
            'is_disposable': False,
            'catch_all': False,
            'is_deliverable': False,
            'confidence': 'unknown',
            'risk_level': 'unknown',
            'details': [],
        }

        # Step 1: Format validation
        fmt_valid, fmt_msg = self.validate_format(email_address)
        result['format_valid'] = fmt_valid
        result['details'].append(f"Format: {fmt_msg}")

        if not fmt_valid:
            result['confidence'] = 'invalid'
            result['risk_level'] = 'high'
            return result

        _, _, domain = email_address.rpartition('@')
        result['domain'] = domain

        # Step 2: Domain analysis (MX, SPF, DMARC, disposable)
        domain_analysis = self.domain_checker.analyze_domain(domain)
        result['domain_analysis'] = domain_analysis
        result['mx_records'] = domain_analysis['mx_records']
        result['mx_found'] = domain_analysis['has_mx']
        result['is_disposable'] = domain_analysis['is_disposable']
        result['catch_all'] = domain_analysis['catch_all']

        if not result['mx_found']:
            result['domain_valid'] = False
            result['details'].append("Domain: No MX records found — domain cannot receive email")
            result['confidence'] = 'invalid'
            result['risk_level'] = 'high'
            return result

        result['domain_valid'] = True
        result['details'].append(
            f"Domain: Valid — {len(domain_analysis['mx_records'])} MX record(s) found"
        )

        if result['is_disposable']:
            result['details'].append("Warning: Disposable/temporary email domain detected")
            result['risk_level'] = 'high'

        # Step 3: SMTP verification
        if not self.skip_smtp and domain_analysis['mx_records']:
            mx_host = domain_analysis['mx_records'][0]['host']
            smtp_exists, smtp_msg = self.domain_checker.smtp_verify(email_address, mx_host)
            result['smtp_valid'] = smtp_exists
            result['details'].append(f"SMTP: {smtp_msg}")

            if result['catch_all']:
                result['details'].append("Note: Domain has catch-all — SMTP result may not be reliable")
        else:
            result['smtp_valid'] = None
            if self.skip_smtp:
                result['details'].append("SMTP: Skipped (disabled)")

        # Step 4: Determine overall deliverability and confidence
        result['is_deliverable'], result['confidence'], result['risk_level'] = \
            self._assess_deliverability(result)

        return result

    def verify_batch(self, email_addresses: List[str]) -> List[Dict]:
        """
        Verify a list of email addresses.

        Args:
            email_addresses: List of email addresses to verify

        Returns:
            List of verification result dicts
        """
        return [self.verify(addr) for addr in email_addresses]

    def _assess_deliverability(self, result: Dict) -> Tuple[bool, str, str]:
        """
        Determine deliverability, confidence, and risk level from partial results.

        Returns:
            Tuple of (is_deliverable, confidence, risk_level)
        """
        if not result['format_valid']:
            return False, 'invalid', 'high'

        if not result['mx_found']:
            return False, 'invalid', 'high'

        if result['is_disposable']:
            # Could still be deliverable but risky
            risk = 'high'
        else:
            risk = 'low'

        smtp = result.get('smtp_valid')
        catch_all = result.get('catch_all', False)

        if smtp is True and not catch_all:
            return True, 'high', risk
        elif smtp is True and catch_all:
            return True, 'medium', risk
        elif smtp is False:
            return False, 'high', 'high'
        else:
            # No SMTP check done
            return True, 'medium', risk
