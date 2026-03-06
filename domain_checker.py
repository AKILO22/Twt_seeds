#!/usr/bin/env python3
"""
Domain Checker Module
DNS/MX record lookup and SMTP connection verification for email addresses.
"""

import logging
import re
import smtplib
import socket
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not available. DNS lookups will be limited.")

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Well-known disposable email domains (partial list; extended via API if available)
DISPOSABLE_DOMAINS = frozenset({
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.de',
    'throwaway.email', 'trashmail.com', 'sharklasers.com', 'guerrillamailblock.com',
    'grr.la', 'guerrillamail.info', 'spam4.me', 'yopmail.com', 'yopmail.fr',
    'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj',
    'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf', 'monemail.fr.nf',
    'monmail.fr.nf', 'tempmail.com', 'temp-mail.org', 'fakeinbox.com',
    'mailnull.com', 'spamgourmet.com', 'trashmail.at', 'trashmail.io',
    'maildrop.cc', 'discard.email', 'spamspot.com', 'getairmail.com',
    'dispostable.com', 'spamherelots.com', 'hulapla.de', 'mt2015.com',
    'trbvm.com', 'rcpt.at', '10minutemail.com', '20minutemail.com',
    'mailnesia.com', 'mytemp.email', 'tempinbox.com', 'filzmail.com',
})

# SMTP verification test sender
SMTP_FROM_ADDRESS = "verify@example.com"
SMTP_TIMEOUT = 10


class DomainChecker:
    """
    DNS and SMTP-based email domain verification.
    Checks MX records, SPF/DKIM/DMARC records, and SMTP reachability.
    """

    def __init__(self, smtp_timeout: int = SMTP_TIMEOUT):
        """
        Initialize domain checker.

        Args:
            smtp_timeout: Timeout in seconds for SMTP connections
        """
        self.smtp_timeout = smtp_timeout

    # ------------------------------------------------------------------
    # MX Records
    # ------------------------------------------------------------------

    def get_mx_records(self, domain: str) -> List[Dict]:
        """
        Retrieve MX records for a domain.

        Args:
            domain: Domain name (e.g., 'example.com')

        Returns:
            List of dicts with 'priority' and 'host' keys, sorted by priority
        """
        if not DNS_AVAILABLE:
            return self._get_mx_fallback(domain)

        try:
            answers = dns.resolver.resolve(domain, 'MX')
            records = sorted(
                [
                    {'priority': r.preference, 'host': str(r.exchange).rstrip('.')}
                    for r in answers
                ],
                key=lambda x: x['priority'],
            )
            logger.debug("MX records for %s: %s", domain, records)
            return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug("No MX records found for %s", domain)
            return []
        except dns.exception.DNSException as e:
            logger.warning("DNS error looking up MX for %s: %s", domain, e)
            return []

    def _get_mx_fallback(self, domain: str) -> List[Dict]:
        """Fallback MX lookup using socket (no dnspython)."""
        try:
            # Use getaddrinfo as a basic reachability check
            socket.getaddrinfo(domain, 25)
            return [{'priority': 10, 'host': domain}]
        except OSError:
            return []

    # ------------------------------------------------------------------
    # DNS Records: SPF, DKIM, DMARC
    # ------------------------------------------------------------------

    def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Get SPF TXT record for a domain.

        Args:
            domain: Domain name

        Returns:
            SPF record string or None
        """
        if not DNS_AVAILABLE:
            return None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt in rdata.strings:
                    decoded = txt.decode('utf-8', errors='replace')
                    if decoded.startswith('v=spf1'):
                        return decoded
        except dns.exception.DNSException:
            pass
        return None

    def get_dkim_record(self, domain: str, selector: str = 'default') -> Optional[str]:
        """
        Get DKIM TXT record for a domain/selector combination.

        Args:
            domain: Domain name
            selector: DKIM selector (default: 'default')

        Returns:
            DKIM record string or None
        """
        if not DNS_AVAILABLE:
            return None
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                parts = []
                for txt in rdata.strings:
                    parts.append(txt.decode('utf-8', errors='replace'))
                record = ''.join(parts)
                if 'v=DKIM1' in record or 'p=' in record:
                    return record
        except dns.exception.DNSException:
            pass
        return None

    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Get DMARC TXT record for a domain.

        Args:
            domain: Domain name

        Returns:
            DMARC record string or None
        """
        if not DNS_AVAILABLE:
            return None
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                for txt in rdata.strings:
                    decoded = txt.decode('utf-8', errors='replace')
                    if decoded.startswith('v=DMARC1'):
                        return decoded
        except dns.exception.DNSException:
            pass
        return None

    def get_a_records(self, domain: str) -> List[str]:
        """
        Get A records (IPv4 addresses) for a domain.

        Args:
            domain: Domain name

        Returns:
            List of IP address strings
        """
        if not DNS_AVAILABLE:
            try:
                return [r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)]
            except OSError:
                return []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(r.address) for r in answers]
        except dns.exception.DNSException:
            return []

    # ------------------------------------------------------------------
    # SMTP Verification
    # ------------------------------------------------------------------

    def smtp_verify(
        self,
        email_address: str,
        mx_host: str,
        from_address: str = SMTP_FROM_ADDRESS,
    ) -> Tuple[bool, str]:
        """
        Attempt SMTP RCPT TO verification for an email address.

        Args:
            email_address: Email address to verify
            mx_host: MX server to connect to
            from_address: Sender address for MAIL FROM command

        Returns:
            Tuple of (exists: bool, message: str)
        """
        try:
            with smtplib.SMTP(mx_host, 25, timeout=self.smtp_timeout) as smtp:
                smtp.ehlo_or_helo_if_needed()
                code, _ = smtp.mail(from_address)
                if code != 250:
                    return False, f"MAIL FROM rejected (code {code})"
                code, msg = smtp.rcpt(email_address)
                msg_str = msg.decode('utf-8', errors='replace') if isinstance(msg, bytes) else str(msg)
                if code == 250:
                    return True, "Address accepted by mail server"
                elif code == 550:
                    return False, "Address does not exist (550)"
                elif code in (251, 252):
                    return True, f"Address likely exists (code {code})"
                else:
                    return False, f"Uncertain response: {code} {msg_str}"
        except smtplib.SMTPConnectError as e:
            return False, f"SMTP connection failed: {e}"
        except smtplib.SMTPServerDisconnected:
            return False, "Server disconnected during verification"
        except socket.timeout:
            return False, "SMTP connection timed out"
        except OSError as e:
            return False, f"Network error: {e}"

    def check_catch_all(self, domain: str, mx_host: str) -> bool:
        """
        Detect if a domain accepts all email addresses (catch-all).

        Args:
            domain: Domain to test
            mx_host: MX server host

        Returns:
            True if catch-all is detected, False otherwise
        """
        test_address = f"definitely_does_not_exist_{domain.replace('.', '_')}@{domain}"
        exists, _ = self.smtp_verify(test_address, mx_host)
        return exists

    # ------------------------------------------------------------------
    # Disposable Email Detection
    # ------------------------------------------------------------------

    def is_disposable(self, domain: str) -> bool:
        """
        Check if a domain is a known disposable email provider.

        Args:
            domain: Domain name to check

        Returns:
            True if disposable, False otherwise
        """
        return domain.lower() in DISPOSABLE_DOMAINS

    # ------------------------------------------------------------------
    # Full Domain Analysis
    # ------------------------------------------------------------------

    def analyze_domain(self, domain: str) -> Dict:
        """
        Perform comprehensive domain analysis for email verification.

        Args:
            domain: Domain name

        Returns:
            Dict with full domain analysis results
        """
        mx_records = self.get_mx_records(domain)
        spf_record = self.get_spf_record(domain)
        dmarc_record = self.get_dmarc_record(domain)
        a_records = self.get_a_records(domain)
        disposable = self.is_disposable(domain)

        # Try DKIM with common selectors
        dkim_record = None
        for selector in ['default', 'google', 'mail', 'k1', 'selector1', 'selector2']:
            dkim_record = self.get_dkim_record(domain, selector)
            if dkim_record:
                break

        # Determine catch-all if MX records exist
        catch_all = False
        if mx_records:
            catch_all = self.check_catch_all(domain, mx_records[0]['host'])

        return {
            'domain': domain,
            'has_mx': len(mx_records) > 0,
            'mx_records': mx_records,
            'has_spf': spf_record is not None,
            'spf_record': spf_record,
            'has_dkim': dkim_record is not None,
            'dkim_record': dkim_record,
            'has_dmarc': dmarc_record is not None,
            'dmarc_record': dmarc_record,
            'a_records': a_records,
            'is_disposable': disposable,
            'catch_all': catch_all,
        }
