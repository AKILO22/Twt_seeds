#!/usr/bin/env python3
"""
Outlook Authentication Handler
Manages OAuth2 authentication for Outlook/Microsoft 365 accounts via Microsoft Graph API
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False
    logger.warning("msal not available. Outlook features disabled.")

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Microsoft Graph API endpoint
GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"

# OAuth2 scopes for Microsoft Graph
OUTLOOK_SCOPES = [
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/User.Read",
]


class OutlookAuthError(Exception):
    """Outlook authentication error"""
    pass


class OutlookAuth:
    """
    Handles OAuth2 authentication for Outlook/Microsoft 365 accounts.
    Uses MSAL (Microsoft Authentication Library) for token management.
    Supports multiple accounts via separate token caches.
    """

    TOKEN_DIR = "email_tokens"
    TOKEN_PREFIX = "outlook_token_"
    AUTHORITY_BASE = "https://login.microsoftonline.com/"
    TENANT_ID = "consumers"  # Use 'common' for work/school + personal accounts

    def __init__(self, token_dir: str = None):
        """
        Initialize Outlook authentication handler.

        Args:
            token_dir: Directory to store token caches
        """
        if not MSAL_AVAILABLE:
            raise OutlookAuthError(
                "msal is not installed. Run: pip install msal"
            )
        if not REQUESTS_AVAILABLE:
            raise OutlookAuthError(
                "requests is not installed. Run: pip install requests"
            )
        self.token_dir = Path(token_dir or self.TOKEN_DIR)
        self.token_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, account_name: str) -> Path:
        """Get path to token cache file for an account."""
        return self.token_dir / f"{self.TOKEN_PREFIX}{account_name}.bin"

    def _load_cache(self, account_name: str) -> "msal.SerializableTokenCache":
        """Load token cache from disk."""
        cache = msal.SerializableTokenCache()
        cache_path = self._get_cache_path(account_name)
        if cache_path.exists():
            cache.deserialize(cache_path.read_text())
        return cache

    def _save_cache(self, cache: "msal.SerializableTokenCache", account_name: str) -> None:
        """Save token cache to disk if it has changed."""
        if cache.has_state_changed:
            cache_path = self._get_cache_path(account_name)
            cache_path.write_text(cache.serialize())

    def authenticate(
        self,
        client_id: str,
        account_name: str = "default",
        tenant_id: str = None,
        force_refresh: bool = False,
    ) -> str:
        """
        Authenticate an Outlook account using OAuth2 device code flow.

        Args:
            client_id: Azure AD application (client) ID
            account_name: Identifier for the account
            tenant_id: Azure AD tenant ID (default: consumers)
            force_refresh: Force re-authentication

        Returns:
            Access token string
        """
        authority = self.AUTHORITY_BASE + (tenant_id or self.TENANT_ID)
        cache = self._load_cache(account_name)

        app = msal.PublicClientApplication(
            client_id,
            authority=authority,
            token_cache=cache,
        )

        access_token = None

        if not force_refresh:
            accounts = app.get_accounts()
            if accounts:
                result = app.acquire_token_silent(OUTLOOK_SCOPES, account=accounts[0])
                if result and 'access_token' in result:
                    access_token = result['access_token']
                    self._save_cache(cache, account_name)
                    logger.info("Using cached token for Outlook account: %s", account_name)

        if not access_token:
            # Device code flow for Termux/mobile compatibility
            flow = app.initiate_device_flow(scopes=OUTLOOK_SCOPES)
            if 'error' in flow:
                raise OutlookAuthError(
                    f"Failed to initiate device flow: {flow.get('error_description', flow['error'])}"
                )

            # Print device code instructions for user
            print("\n" + "=" * 60)
            print("OUTLOOK AUTHENTICATION REQUIRED")
            print("=" * 60)
            print(flow['message'])
            print("=" * 60 + "\n")

            result = app.acquire_token_by_device_flow(flow)
            if 'access_token' not in result:
                raise OutlookAuthError(
                    f"Authentication failed: {result.get('error_description', result.get('error', 'Unknown error'))}"
                )

            access_token = result['access_token']
            self._save_cache(cache, account_name)
            logger.info("New authentication completed for Outlook account: %s", account_name)

        return access_token

    def list_accounts(self) -> List[str]:
        """
        List all authenticated Outlook accounts.

        Returns:
            List of account names with stored tokens
        """
        accounts = []
        for token_file in self.token_dir.glob(f"{self.TOKEN_PREFIX}*.bin"):
            name = token_file.stem.replace(self.TOKEN_PREFIX, "")
            accounts.append(name)
        return accounts

    def revoke_account(self, account_name: str) -> bool:
        """
        Remove stored token cache for an account.

        Args:
            account_name: Account identifier to revoke

        Returns:
            True if cache was removed, False if not found
        """
        cache_path = self._get_cache_path(account_name)
        if cache_path.exists():
            cache_path.unlink()
            logger.info("Revoked token for Outlook account: %s", account_name)
            return True
        return False

    def get_account_info(self, access_token: str) -> Dict:
        """
        Get authenticated Outlook account information.

        Args:
            access_token: Valid access token

        Returns:
            Dict with account info
        """
        import requests
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            resp = requests.get(f"{GRAPH_API_ENDPOINT}/me", headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            return {
                "email": data.get("mail") or data.get("userPrincipalName", ""),
                "display_name": data.get("displayName", ""),
                "id": data.get("id", ""),
            }
        except Exception as e:
            logger.error("Failed to get Outlook account info: %s", e)
            return {}

    def fetch_emails(
        self,
        access_token: str,
        max_results: int = 10,
        folder: str = "inbox",
        unread_only: bool = False,
    ) -> List[Dict]:
        """
        Fetch emails from Outlook inbox.

        Args:
            access_token: Valid access token
            max_results: Maximum number of emails to fetch
            folder: Mail folder name (default: inbox)
            unread_only: Only fetch unread emails

        Returns:
            List of email data dicts
        """
        import requests
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        }
        params = {
            '$top': max_results,
            '$orderby': 'receivedDateTime desc',
            '$select': 'id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,hasAttachments,size',
        }
        if unread_only:
            params['$filter'] = 'isRead eq false'

        url = f"{GRAPH_API_ENDPOINT}/me/mailFolders/{folder}/messages"

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
            messages = resp.json().get('value', [])
        except Exception as e:
            logger.error("Failed to fetch Outlook emails: %s", e)
            return []

        emails = []
        for msg in messages:
            sender = msg.get('from', {}).get('emailAddress', {})
            email_data = {
                'id': msg.get('id', ''),
                'from': f"{sender.get('name', '')} <{sender.get('address', '')}>".strip(" <>"),
                'to': ', '.join(
                    f"{r['emailAddress'].get('name', '')} <{r['emailAddress'].get('address', '')}>".strip(" <>")
                    for r in msg.get('toRecipients', [])
                ),
                'subject': msg.get('subject', '(No Subject)'),
                'date': msg.get('receivedDateTime', ''),
                'preview': msg.get('bodyPreview', '')[:200],
                'is_unread': not msg.get('isRead', True),
                'has_attachments': msg.get('hasAttachments', False),
                'size': msg.get('size', 0),
                'source': 'outlook',
            }
            emails.append(email_data)

        return emails
