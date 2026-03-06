#!/usr/bin/env python3
"""
IMAP Handler
Generic IMAP email handler supporting any IMAP-compatible provider.
Provides secure SSL/TLS connections and email parsing.
"""

import email
import imaplib
import logging
import re
import ssl
from email.header import decode_header
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class IMAPError(Exception):
    """IMAP connection or operation error"""
    pass


class IMAPHandler:
    """
    Generic IMAP email handler.
    Supports any IMAP-compatible email provider with SSL/TLS.
    """

    DEFAULT_PORT_SSL = 993
    DEFAULT_PORT_STARTTLS = 143

    # Common IMAP server configurations
    KNOWN_SERVERS = {
        'gmail.com': {'host': 'imap.gmail.com', 'port': 993},
        'googlemail.com': {'host': 'imap.gmail.com', 'port': 993},
        'yahoo.com': {'host': 'imap.mail.yahoo.com', 'port': 993},
        'yahoo.co.uk': {'host': 'imap.mail.yahoo.com', 'port': 993},
        'outlook.com': {'host': 'outlook.office365.com', 'port': 993},
        'hotmail.com': {'host': 'outlook.office365.com', 'port': 993},
        'live.com': {'host': 'outlook.office365.com', 'port': 993},
        'icloud.com': {'host': 'imap.mail.me.com', 'port': 993},
        'me.com': {'host': 'imap.mail.me.com', 'port': 993},
        'aol.com': {'host': 'imap.aol.com', 'port': 993},
        'zoho.com': {'host': 'imap.zoho.com', 'port': 993},
        'protonmail.com': {'host': '127.0.0.1', 'port': 1143},  # via Bridge
        'proton.me': {'host': '127.0.0.1', 'port': 1143},
    }

    def __init__(self, host: str, port: int = None, use_ssl: bool = True):
        """
        Initialize IMAP handler.

        Args:
            host: IMAP server hostname
            port: IMAP server port (default: 993 for SSL, 143 for STARTTLS)
            use_ssl: Use SSL/TLS connection (recommended)
        """
        self.host = host
        self.use_ssl = use_ssl
        self.port = port or (self.DEFAULT_PORT_SSL if use_ssl else self.DEFAULT_PORT_STARTTLS)
        self._connection: Optional[imaplib.IMAP4] = None

    @classmethod
    def from_email_address(cls, email_address: str) -> "IMAPHandler":
        """
        Create an IMAP handler based on email domain.

        Args:
            email_address: Email address to extract domain from

        Returns:
            Configured IMAPHandler instance
        """
        domain = email_address.split('@')[-1].lower() if '@' in email_address else email_address.lower()
        config = cls.KNOWN_SERVERS.get(domain)
        if config:
            return cls(host=config['host'], port=config['port'])
        # Generic fallback
        return cls(host=f"imap.{domain}")

    def connect(self, username: str, password: str) -> None:
        """
        Connect and authenticate to the IMAP server.

        Args:
            username: Email address or IMAP username
            password: Password or app-specific password

        Raises:
            IMAPError: If connection or authentication fails
        """
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                self._connection = imaplib.IMAP4_SSL(
                    self.host, self.port, ssl_context=context
                )
            else:
                self._connection = imaplib.IMAP4(self.host, self.port)
                self._connection.starttls()

            self._connection.login(username, password)
            logger.info("Connected to IMAP server: %s as %s", self.host, username)
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"IMAP authentication failed: {e}") from e
        except ssl.SSLError as e:
            raise IMAPError(f"SSL error connecting to {self.host}: {e}") from e
        except OSError as e:
            raise IMAPError(f"Network error connecting to {self.host}:{self.port}: {e}") from e

    def disconnect(self) -> None:
        """Close the IMAP connection gracefully."""
        if self._connection:
            try:
                self._connection.close()
                self._connection.logout()
            except Exception:
                pass
            self._connection = None
            logger.info("Disconnected from IMAP server: %s", self.host)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def list_folders(self) -> List[str]:
        """
        List all available IMAP folders/mailboxes.

        Returns:
            List of folder names
        """
        self._require_connection()
        status, folders = self._connection.list()
        if status != 'OK':
            return []
        result = []
        for folder in folders:
            if isinstance(folder, bytes):
                parts = folder.decode().split('"')
                name = parts[-1].strip() if parts else folder.decode()
                result.append(name)
        return result

    def select_folder(self, folder: str = "INBOX") -> int:
        """
        Select a mailbox folder.

        Args:
            folder: Folder name (default: INBOX)

        Returns:
            Number of messages in the folder
        """
        self._require_connection()
        status, data = self._connection.select(folder)
        if status != 'OK':
            raise IMAPError(f"Failed to select folder '{folder}': {data}")
        return int(data[0]) if data and data[0] else 0

    def fetch_emails(
        self,
        max_results: int = 10,
        folder: str = "INBOX",
        unread_only: bool = False,
        search_criteria: str = None,
    ) -> List[Dict]:
        """
        Fetch emails from a mailbox folder.

        Args:
            max_results: Maximum number of emails to fetch
            folder: Mailbox folder to search
            unread_only: Only fetch unseen/unread emails
            search_criteria: Custom IMAP search criteria string

        Returns:
            List of parsed email data dicts
        """
        self._require_connection()
        self.select_folder(folder)

        if search_criteria:
            criteria = search_criteria
        elif unread_only:
            criteria = 'UNSEEN'
        else:
            criteria = 'ALL'

        status, message_ids = self._connection.search(None, criteria)
        if status != 'OK':
            return []

        ids = message_ids[0].split()
        # Take the last N (most recent)
        ids = ids[-max_results:] if len(ids) > max_results else ids
        ids = list(reversed(ids))  # Most recent first

        emails = []
        for uid in ids:
            try:
                email_data = self._fetch_single(uid)
                if email_data:
                    emails.append(email_data)
            except Exception as e:
                logger.warning("Failed to fetch message %s: %s", uid, e)

        return emails

    def _fetch_single(self, uid: bytes) -> Optional[Dict]:
        """
        Fetch and parse a single email by UID.

        Args:
            uid: Message UID bytes

        Returns:
            Parsed email data dict
        """
        status, data = self._connection.fetch(uid, '(RFC822 FLAGS)')
        if status != 'OK' or not data:
            return None

        # Parse flags
        flags = []
        raw_flags = data[0][0] if isinstance(data[0], tuple) else b''
        if isinstance(raw_flags, bytes):
            flag_match = re.search(rb'FLAGS \(([^)]*)\)', raw_flags)
            if flag_match:
                flags = flag_match.group(1).decode().split()

        # Parse message
        raw_msg = data[0][1] if isinstance(data[0], tuple) else data[0]
        if not isinstance(raw_msg, bytes):
            return None

        msg = email.message_from_bytes(raw_msg)

        return {
            'id': uid.decode() if isinstance(uid, bytes) else str(uid),
            'from': self._decode_header(msg.get('From', '')),
            'to': self._decode_header(msg.get('To', '')),
            'subject': self._decode_header(msg.get('Subject', '(No Subject)')),
            'date': self._parse_date(msg.get('Date', '')),
            'preview': self._extract_preview(msg),
            'is_unread': '\\Seen' not in flags,
            'has_attachments': self._has_attachments(msg),
            'content_type': msg.get_content_type(),
            'message_id': msg.get('Message-ID', ''),
            'reply_to': self._decode_header(msg.get('Reply-To', '')),
            'flags': flags,
            'source': 'imap',
            'raw_headers': dict(msg.items()),
        }

    def _decode_header(self, value: str) -> str:
        """Decode potentially encoded email header value."""
        if not value:
            return ''
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
            return value

    def _parse_date(self, date_str: str) -> str:
        """Parse email date string to ISO format."""
        if not date_str:
            return ''
        try:
            return parsedate_to_datetime(date_str).isoformat()
        except Exception:
            return date_str

    def _extract_preview(self, msg: email.message.Message, max_chars: int = 200) -> str:
        """Extract text preview from email body."""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        return text[:max_chars].strip()
                    except Exception:
                        continue
        else:
            if msg.get_content_type() == 'text/plain':
                try:
                    payload = msg.get_payload(decode=True)
                    charset = msg.get_content_charset() or 'utf-8'
                    return payload.decode(charset, errors='replace')[:max_chars].strip()
                except Exception:
                    pass
        return ''

    def _has_attachments(self, msg: email.message.Message) -> bool:
        """Check if email has attachments."""
        for part in msg.walk():
            disposition = part.get('Content-Disposition', '')
            if 'attachment' in disposition.lower():
                return True
        return False

    def get_unread_count(self, folder: str = "INBOX") -> int:
        """
        Get count of unread messages in a folder.

        Args:
            folder: Mailbox folder

        Returns:
            Number of unread messages
        """
        self._require_connection()
        self.select_folder(folder)
        status, data = self._connection.search(None, 'UNSEEN')
        if status != 'OK':
            return 0
        return len(data[0].split()) if data and data[0] else 0

    def _require_connection(self) -> None:
        """Raise IMAPError if not connected."""
        if not self._connection:
            raise IMAPError("Not connected. Call connect() first.")
