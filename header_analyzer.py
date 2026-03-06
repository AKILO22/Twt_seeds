#!/usr/bin/env python3
"""
Email Header Analyzer Module
Parses RFC 2822 email headers, extracts authentication results,
routing info, and performs security analysis.
"""

import email
import logging
import re
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Regex patterns for security analysis
_URL_REGEX = re.compile(
    r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)',
    re.IGNORECASE
)
_IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Common free/suspicious TLDs associated with phishing (not exhaustive)
_SUSPICIOUS_TLDS = frozenset({
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.loan', '.win', '.download', '.review', '.country', '.stream',
    '.racing', '.science', '.party', '.trade', '.date',
})

# Indicators in URLs or subjects that may suggest phishing
_PHISHING_KEYWORDS = frozenset({
    'verify', 'update', 'suspend', 'suspended', 'confirm', 'login', 'account',
    'secure', 'security', 'urgent', 'immediately', 'expire', 'expired',
    'unusual', 'activity', 'reactivate', 'validate', 'limited', 'alert',
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank', 'invoice',
    'refund', 'prize', 'won', 'winner', 'click here', 'act now',
})


class HeaderAnalyzer:
    """
    Parses and analyzes RFC 2822 email headers.

    Extracts:
    - Authentication results (SPF, DKIM, DMARC)
    - Routing information (Received headers)
    - Sender verification
    - Security indicators
    - Attachment listing
    - Encoding/Content-Type info
    """

    def analyze_raw(self, raw_email: str) -> Dict:
        """
        Analyze a raw email string (headers + optional body).

        Args:
            raw_email: Raw email content as string

        Returns:
            Comprehensive analysis dict
        """
        if isinstance(raw_email, bytes):
            msg = email.message_from_bytes(raw_email)
        else:
            msg = email.message_from_string(raw_email)
        return self.analyze_message(msg)

    def analyze_message(self, msg: email.message.Message) -> Dict:
        """
        Analyze a parsed email.message.Message object.

        Args:
            msg: Parsed email message

        Returns:
            Comprehensive analysis dict
        """
        headers = self._extract_headers(msg)
        auth_results = self._parse_authentication_results(msg)
        routing = self._parse_routing(msg)
        sender_info = self._analyze_sender(msg)
        security = self._security_analysis(msg, headers)
        metadata = self._extract_metadata(msg)
        attachments = self._list_attachments(msg)

        return {
            'headers': headers,
            'authentication': auth_results,
            'routing': routing,
            'sender': sender_info,
            'security': security,
            'metadata': metadata,
            'attachments': attachments,
        }

    def analyze_headers_dict(self, headers: Dict[str, str]) -> Dict:
        """
        Analyze a dict of header name -> value pairs.

        Args:
            headers: Dict of header key/value pairs

        Returns:
            Authentication and routing analysis dict
        """
        # Build a minimal email message from the dict
        raw = '\r\n'.join(f"{k}: {v}" for k, v in headers.items()) + '\r\n\r\n'
        return self.analyze_raw(raw)

    # ------------------------------------------------------------------
    # Header Extraction
    # ------------------------------------------------------------------

    def _extract_headers(self, msg: email.message.Message) -> Dict[str, str]:
        """Extract and decode all headers into a dict."""
        result = {}
        for name, value in msg.items():
            decoded = self._decode_header_value(value)
            # For duplicate headers (e.g., Received), concatenate
            if name in result:
                result[name] = result[name] + '\n' + decoded
            else:
                result[name] = decoded
        return result

    def _decode_header_value(self, value: str) -> str:
        """Decode an encoded header value."""
        try:
            parts = decode_header(value)
            decoded = []
            for part, charset in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(charset or 'utf-8', errors='replace'))
                else:
                    decoded.append(str(part))
            return ''.join(decoded)
        except Exception:
            return str(value)

    # ------------------------------------------------------------------
    # Authentication Results (SPF, DKIM, DMARC)
    # ------------------------------------------------------------------

    def _parse_authentication_results(self, msg: email.message.Message) -> Dict:
        """Parse Authentication-Results header for SPF/DKIM/DMARC."""
        auth_header = msg.get('Authentication-Results', '')
        result = {
            'spf': self._extract_auth_result(auth_header, 'spf'),
            'dkim': self._extract_auth_result(auth_header, 'dkim'),
            'dmarc': self._extract_auth_result(auth_header, 'dmarc'),
            'raw': auth_header,
        }

        # Also check ARC headers
        arc_auth = msg.get('ARC-Authentication-Results', '')
        if arc_auth:
            result['arc'] = {
                'spf': self._extract_auth_result(arc_auth, 'spf'),
                'dkim': self._extract_auth_result(arc_auth, 'dkim'),
                'dmarc': self._extract_auth_result(arc_auth, 'dmarc'),
                'raw': arc_auth,
            }

        # X-Google-DKIM / X-Received for Gmail
        dkim_signature = msg.get('DKIM-Signature', '')
        result['has_dkim_signature'] = bool(dkim_signature)

        return result

    def _extract_auth_result(self, auth_header: str, protocol: str) -> Optional[str]:
        """Extract a specific protocol result from Authentication-Results."""
        if not auth_header:
            return None
        pattern = re.compile(
            rf'{re.escape(protocol)}\s*=\s*(\w+)',
            re.IGNORECASE
        )
        match = pattern.search(auth_header)
        return match.group(1).lower() if match else None

    # ------------------------------------------------------------------
    # Routing Analysis
    # ------------------------------------------------------------------

    def _parse_routing(self, msg: email.message.Message) -> List[Dict]:
        """Parse Received headers to extract routing hops."""
        received_headers = msg.get_all('Received', [])
        hops = []

        for header in received_headers:
            hop = self._parse_received_header(header)
            if hop:
                hops.append(hop)

        return list(reversed(hops))  # Chronological order (oldest first)

    def _parse_received_header(self, header: str) -> Dict:
        """Parse a single Received header."""
        hop = {'raw': header.strip()}

        # Extract 'from' hostname/IP
        from_match = re.search(r'from\s+(\S+)\s+\(([^)]+)\)', header, re.IGNORECASE)
        if from_match:
            hop['from_host'] = from_match.group(1)
            hop['from_info'] = from_match.group(2)
            # Extract IP from info
            ip_match = _IP_REGEX.search(from_match.group(2))
            hop['from_ip'] = ip_match.group(0) if ip_match else None
        else:
            hop['from_host'] = None
            hop['from_ip'] = None

        # Extract 'by' server
        by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
        hop['by_server'] = by_match.group(1) if by_match else None

        # Extract date
        date_match = re.search(r';\s*(.+)$', header.strip(), re.MULTILINE)
        if date_match:
            hop['date'] = date_match.group(1).strip()
            try:
                hop['date_iso'] = parsedate_to_datetime(hop['date']).isoformat()
            except Exception:
                hop['date_iso'] = None
        else:
            hop['date'] = None
            hop['date_iso'] = None

        # Detect TLS usage
        hop['tls'] = bool(re.search(r'TLS|SSL|STARTTLS', header, re.IGNORECASE))

        # Detect protocol
        proto_match = re.search(r'with\s+(ESMTP[A-Z]*|SMTP[A-Z]*|HTTP)', header, re.IGNORECASE)
        hop['protocol'] = proto_match.group(1).upper() if proto_match else None

        return hop

    # ------------------------------------------------------------------
    # Sender Analysis
    # ------------------------------------------------------------------

    def _analyze_sender(self, msg: email.message.Message) -> Dict:
        """Analyze sender-related headers for consistency."""
        from_header = self._decode_header_value(msg.get('From', ''))
        reply_to = self._decode_header_value(msg.get('Reply-To', ''))
        return_path = self._decode_header_value(msg.get('Return-Path', ''))
        sender = self._decode_header_value(msg.get('Sender', ''))

        # Extract email addresses
        from_email = self._extract_email_from_header(from_header)
        reply_to_email = self._extract_email_from_header(reply_to)
        return_path_email = self._extract_email_from_header(return_path)

        # Check for inconsistencies
        inconsistencies = []
        if reply_to_email and from_email and reply_to_email != from_email:
            inconsistencies.append(
                f"Reply-To ({reply_to_email}) differs from From ({from_email})"
            )
        if return_path_email and from_email and return_path_email != from_email:
            inconsistencies.append(
                f"Return-Path ({return_path_email}) differs from From ({from_email})"
            )

        from_domain = from_email.split('@')[-1] if from_email and '@' in from_email else ''
        reply_to_domain = reply_to_email.split('@')[-1] if reply_to_email and '@' in reply_to_email else ''

        domain_mismatch = bool(
            from_domain and reply_to_domain and from_domain != reply_to_domain
        )

        return {
            'from': from_header,
            'from_email': from_email,
            'from_domain': from_domain,
            'reply_to': reply_to,
            'reply_to_email': reply_to_email,
            'return_path': return_path,
            'return_path_email': return_path_email,
            'sender': sender,
            'inconsistencies': inconsistencies,
            'domain_mismatch': domain_mismatch,
        }

    def _extract_email_from_header(self, header_value: str) -> Optional[str]:
        """Extract email address from a header value like 'Name <email@domain.com>'."""
        if not header_value:
            return None
        match = re.search(r'<([^>]+)>', header_value)
        if match:
            return match.group(1).strip().lower()
        # Bare email address
        match = re.search(r'[\w._%+\-]+@[\w.\-]+\.\w+', header_value)
        return match.group(0).lower() if match else None

    # ------------------------------------------------------------------
    # Metadata Extraction
    # ------------------------------------------------------------------

    def _extract_metadata(self, msg: email.message.Message) -> Dict:
        """Extract email metadata."""
        subject = self._decode_header_value(msg.get('Subject', ''))
        date_str = msg.get('Date', '')
        date_iso = None
        try:
            if date_str:
                date_iso = parsedate_to_datetime(date_str).isoformat()
        except Exception:
            pass

        return {
            'subject': subject,
            'date': date_str,
            'date_iso': date_iso,
            'message_id': msg.get('Message-ID', ''),
            'content_type': msg.get_content_type(),
            'content_transfer_encoding': msg.get('Content-Transfer-Encoding', ''),
            'mime_version': msg.get('MIME-Version', ''),
            'x_mailer': msg.get('X-Mailer', '') or msg.get('User-Agent', ''),
            'x_originating_ip': msg.get('X-Originating-IP', ''),
            'priority': msg.get('X-Priority', '') or msg.get('Importance', ''),
            'is_multipart': msg.is_multipart(),
        }

    # ------------------------------------------------------------------
    # Attachment Detection
    # ------------------------------------------------------------------

    def _list_attachments(self, msg: email.message.Message) -> List[Dict]:
        """List all attachments in the email."""
        attachments = []
        for part in msg.walk():
            disposition = part.get('Content-Disposition', '')
            if 'attachment' in disposition.lower():
                filename = part.get_filename()
                if filename:
                    filename = self._decode_header_value(filename)
                attachments.append({
                    'filename': filename or 'unnamed',
                    'content_type': part.get_content_type(),
                    'content_transfer_encoding': part.get('Content-Transfer-Encoding', ''),
                    'size': len(part.get_payload(decode=True) or b''),
                })
        return attachments

    # ------------------------------------------------------------------
    # Security Analysis
    # ------------------------------------------------------------------

    def _security_analysis(self, msg: email.message.Message, headers: Dict) -> Dict:
        """
        Perform security analysis: phishing, malicious links, spoofing.

        Args:
            msg: Parsed email message
            headers: Extracted headers dict

        Returns:
            Security analysis dict
        """
        subject = self._decode_header_value(msg.get('Subject', ''))
        from_header = self._decode_header_value(msg.get('From', ''))
        body_text = self._extract_body_text(msg)

        # Phishing keyword detection
        phishing_triggers = []
        combined_text = (subject + ' ' + body_text).lower()
        for kw in _PHISHING_KEYWORDS:
            if kw in combined_text:
                phishing_triggers.append(kw)

        # URL extraction
        all_urls = _URL_REGEX.findall(body_text)
        suspicious_urls = [
            url for url in all_urls
            if any(url.lower().endswith(tld) or f'{tld}/' in url.lower() for tld in _SUSPICIOUS_TLDS)
        ]

        # Domain spoofing: check if From domain matches Received header IPs
        auth_results = self._parse_authentication_results(msg)
        spf_result = auth_results.get('spf')
        dkim_result = auth_results.get('dkim')
        dmarc_result = auth_results.get('dmarc')

        spoofing_risk = False
        spoofing_reasons = []
        if spf_result and spf_result not in ('pass', 'neutral'):
            spoofing_risk = True
            spoofing_reasons.append(f"SPF result: {spf_result}")
        if dkim_result and dkim_result != 'pass':
            spoofing_risk = True
            spoofing_reasons.append(f"DKIM result: {dkim_result}")
        if dmarc_result and dmarc_result != 'pass':
            spoofing_risk = True
            spoofing_reasons.append(f"DMARC result: {dmarc_result}")

        # Reply-To mismatch
        reply_to = self._decode_header_value(msg.get('Reply-To', ''))
        from_email = self._extract_email_from_header(from_header)
        reply_to_email = self._extract_email_from_header(reply_to)
        reply_to_mismatch = bool(
            reply_to_email and from_email and reply_to_email != from_email
        )

        # Calculate risk score (0 = low, 10 = high)
        risk_score = 0
        if phishing_triggers:
            risk_score += min(len(phishing_triggers), 3)
        if suspicious_urls:
            risk_score += 3
        if spoofing_risk:
            risk_score += 3
        if reply_to_mismatch:
            risk_score += 1

        return {
            'phishing_keywords': phishing_triggers,
            'phishing_keyword_count': len(phishing_triggers),
            'urls': all_urls[:20],  # Limit to first 20
            'url_count': len(all_urls),
            'suspicious_urls': suspicious_urls[:10],
            'suspicious_url_count': len(suspicious_urls),
            'spf_result': spf_result,
            'dkim_result': dkim_result,
            'dmarc_result': dmarc_result,
            'spoofing_risk': spoofing_risk,
            'spoofing_reasons': spoofing_reasons,
            'reply_to_mismatch': reply_to_mismatch,
            'risk_score': risk_score,
            'risk_level': self._risk_level(risk_score),
        }

    def _extract_body_text(self, msg: email.message.Message) -> str:
        """Extract plain text body from email message."""
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        parts.append(payload.decode(charset, errors='replace'))
                    except Exception:
                        continue
            return '\n'.join(parts)
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    return payload.decode(charset, errors='replace')
            except Exception:
                pass
        return ''

    def _risk_level(self, score: int) -> str:
        """Convert risk score to human-readable level."""
        if score == 0:
            return 'low'
        elif score <= 3:
            return 'medium'
        elif score <= 6:
            return 'high'
        else:
            return 'critical'
