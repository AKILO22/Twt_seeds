#!/usr/bin/env python3
"""
Gmail Authentication Handler
Manages OAuth2 authentication for Gmail accounts using google-auth-oauthlib
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    logger.warning("google-auth libraries not available. Gmail features disabled.")


# Gmail API scopes
GMAIL_SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.metadata',
]


class GmailAuthError(Exception):
    """Gmail authentication error"""
    pass


class GmailAuth:
    """
    Handles OAuth2 authentication for Gmail accounts.
    Supports multiple accounts via separate token files.
    """

    TOKEN_DIR = "email_tokens"
    TOKEN_PREFIX = "gmail_token_"

    def __init__(self, token_dir: str = None):
        """
        Initialize Gmail authentication handler.

        Args:
            token_dir: Directory to store OAuth2 tokens
        """
        if not GOOGLE_AUTH_AVAILABLE:
            raise GmailAuthError(
                "google-auth-oauthlib is not installed. "
                "Run: pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client"
            )
        self.token_dir = Path(token_dir or self.TOKEN_DIR)
        self.token_dir.mkdir(parents=True, exist_ok=True)

    def authenticate(
        self,
        credentials_file: str,
        account_name: str = "default",
        force_refresh: bool = False,
    ) -> "Credentials":
        """
        Authenticate a Gmail account using OAuth2.

        Args:
            credentials_file: Path to OAuth2 client credentials JSON file
            account_name: Identifier for the account (for multi-account support)
            force_refresh: Force re-authentication even if token exists

        Returns:
            Google OAuth2 Credentials object
        """
        token_path = self.token_dir / f"{self.TOKEN_PREFIX}{account_name}.json"
        creds = None

        if not force_refresh and token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)
            except Exception as e:
                logger.warning("Failed to load cached token for %s: %s", account_name, e)
                creds = None

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    logger.info("Refreshed access token for account: %s", account_name)
                except Exception as e:
                    logger.warning("Token refresh failed for %s: %s. Re-authenticating.", account_name, e)
                    creds = None

            if not creds:
                if not os.path.exists(credentials_file):
                    raise GmailAuthError(
                        f"Credentials file not found: {credentials_file}\n"
                        "Download OAuth2 credentials from Google Cloud Console."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_file, GMAIL_SCOPES
                )
                creds = flow.run_local_server(port=0)
                logger.info("New OAuth2 authentication completed for account: %s", account_name)

            # Save token for future use
            token_path.write_text(creds.to_json())
            logger.info("Token saved for account: %s", account_name)

        return creds

    def build_service(self, credentials: "Credentials"):
        """
        Build Gmail API service client.

        Args:
            credentials: Valid OAuth2 credentials

        Returns:
            Gmail API service object
        """
        return build('gmail', 'v1', credentials=credentials)

    def list_accounts(self) -> List[str]:
        """
        List all authenticated Gmail accounts.

        Returns:
            List of account names with stored tokens
        """
        accounts = []
        for token_file in self.token_dir.glob(f"{self.TOKEN_PREFIX}*.json"):
            name = token_file.stem.replace(self.TOKEN_PREFIX, "")
            accounts.append(name)
        return accounts

    def revoke_account(self, account_name: str) -> bool:
        """
        Revoke and remove stored token for an account.

        Args:
            account_name: Account identifier to revoke

        Returns:
            True if token was removed, False if not found
        """
        token_path = self.token_dir / f"{self.TOKEN_PREFIX}{account_name}.json"
        if token_path.exists():
            token_path.unlink()
            logger.info("Revoked token for Gmail account: %s", account_name)
            return True
        return False

    def get_account_info(self, service) -> Dict:
        """
        Get authenticated Gmail account information.

        Args:
            service: Gmail API service object

        Returns:
            Dict with account profile info
        """
        try:
            profile = service.users().getProfile(userId='me').execute()
            return {
                "email": profile.get("emailAddress", ""),
                "messages_total": profile.get("messagesTotal", 0),
                "threads_total": profile.get("threadsTotal", 0),
                "history_id": profile.get("historyId", ""),
            }
        except Exception as e:
            logger.error("Failed to get account info: %s", e)
            return {}

    def fetch_emails(
        self,
        service,
        max_results: int = 10,
        label_ids: Optional[List[str]] = None,
        unread_only: bool = False,
    ) -> List[Dict]:
        """
        Fetch emails from Gmail inbox.

        Args:
            service: Gmail API service object
            max_results: Maximum number of emails to fetch
            label_ids: List of label IDs to filter (default: INBOX)
            unread_only: Only fetch unread emails

        Returns:
            List of email data dicts
        """
        label_ids = label_ids or ['INBOX']
        query = 'is:unread' if unread_only else ''

        try:
            result = service.users().messages().list(
                userId='me',
                maxResults=max_results,
                labelIds=label_ids,
                q=query,
            ).execute()
        except Exception as e:
            logger.error("Failed to list Gmail messages: %s", e)
            return []

        messages = result.get('messages', [])
        emails = []

        for msg_ref in messages:
            try:
                email_data = self._fetch_message(service, msg_ref['id'])
                if email_data:
                    emails.append(email_data)
            except Exception as e:
                logger.warning("Failed to fetch message %s: %s", msg_ref['id'], e)

        return emails

    def _fetch_message(self, service, message_id: str) -> Optional[Dict]:
        """
        Fetch a single Gmail message.

        Args:
            service: Gmail API service object
            message_id: Gmail message ID

        Returns:
            Email data dict or None
        """
        msg = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full',
        ).execute()

        headers = {
            h['name'].lower(): h['value']
            for h in msg.get('payload', {}).get('headers', [])
        }

        # Extract body preview
        snippet = msg.get('snippet', '')

        # Determine unread status
        label_ids = msg.get('labelIds', [])
        is_unread = 'UNREAD' in label_ids

        # Parse date
        date_str = headers.get('date', '')
        try:
            from email.utils import parsedate_to_datetime
            date = parsedate_to_datetime(date_str).isoformat() if date_str else ''
        except Exception:
            date = date_str

        return {
            'id': message_id,
            'thread_id': msg.get('threadId', ''),
            'from': headers.get('from', ''),
            'to': headers.get('to', ''),
            'subject': headers.get('subject', '(No Subject)'),
            'date': date,
            'preview': snippet[:200] if snippet else '',
            'is_unread': is_unread,
            'labels': label_ids,
            'size': msg.get('sizeEstimate', 0),
            'source': 'gmail',
        }
