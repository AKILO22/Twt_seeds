#!/usr/bin/env python3
"""
Email Monitor Module
Main orchestration module for monitoring email accounts.
Coordinates Gmail, Outlook, and IMAP integrations.
"""

import logging
from typing import Dict, List, Optional, Tuple

from colorama import Fore, Style, init as colorama_init

from imap_handler import IMAPHandler, IMAPError
from email_data_manager import EmailDataManager
from email_reporter import EmailReporter

colorama_init(autoreset=True)
logger = logging.getLogger(__name__)


class EmailMonitor:
    """
    Main email monitoring class.
    Coordinates fetching emails from Gmail, Outlook, and IMAP accounts.
    """

    def __init__(self, data_dir: str = "email_data", output_dir: str = "output"):
        """
        Initialize the email monitor.

        Args:
            data_dir: Directory for storing email data
            output_dir: Directory for reports
        """
        self.data_manager = EmailDataManager(data_dir)
        self.reporter = EmailReporter(output_dir)

    # ------------------------------------------------------------------
    # Gmail Monitoring
    # ------------------------------------------------------------------

    def monitor_gmail(
        self,
        credentials_file: str,
        account_name: str = "default",
        max_results: int = 10,
        unread_only: bool = False,
        save: bool = False,
    ) -> List[Dict]:
        """
        Fetch and display emails from a Gmail account.

        Args:
            credentials_file: Path to Google OAuth2 credentials JSON
            account_name: Account identifier
            max_results: Max number of emails to fetch
            unread_only: Only fetch unread emails
            save: Save emails to local storage

        Returns:
            List of email data dicts
        """
        try:
            from gmail_auth import GmailAuth, GmailAuthError
        except ImportError:
            logger.error("gmail_auth module not found")
            return []

        try:
            auth = GmailAuth()
            creds = auth.authenticate(credentials_file, account_name)
            service = auth.build_service(creds)
            account_info = auth.get_account_info(service)
            logger.info("Gmail account: %s", account_info.get('email', ''))

            emails = auth.fetch_emails(service, max_results=max_results, unread_only=unread_only)

            if save:
                self.data_manager.save_emails(emails, account=account_name)

            return emails

        except Exception as e:
            logger.error("Gmail monitoring error: %s", e)
            raise

    # ------------------------------------------------------------------
    # Outlook Monitoring
    # ------------------------------------------------------------------

    def monitor_outlook(
        self,
        client_id: str,
        account_name: str = "default",
        max_results: int = 10,
        unread_only: bool = False,
        save: bool = False,
    ) -> List[Dict]:
        """
        Fetch and display emails from an Outlook account.

        Args:
            client_id: Azure AD application client ID
            account_name: Account identifier
            max_results: Max number of emails to fetch
            unread_only: Only fetch unread emails
            save: Save emails to local storage

        Returns:
            List of email data dicts
        """
        try:
            from outlook_auth import OutlookAuth, OutlookAuthError
        except ImportError:
            logger.error("outlook_auth module not found")
            return []

        try:
            auth = OutlookAuth()
            access_token = auth.authenticate(client_id, account_name)
            account_info = auth.get_account_info(access_token)
            logger.info("Outlook account: %s", account_info.get('email', ''))

            emails = auth.fetch_emails(
                access_token, max_results=max_results, unread_only=unread_only
            )

            if save:
                self.data_manager.save_emails(emails, account=account_name)

            return emails

        except Exception as e:
            logger.error("Outlook monitoring error: %s", e)
            raise

    # ------------------------------------------------------------------
    # IMAP Monitoring
    # ------------------------------------------------------------------

    def monitor_imap(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 993,
        folder: str = "INBOX",
        max_results: int = 10,
        unread_only: bool = False,
        use_ssl: bool = True,
        save: bool = False,
    ) -> List[Dict]:
        """
        Fetch emails from a generic IMAP server.

        Args:
            host: IMAP server hostname
            username: Login username
            password: Login password
            port: IMAP server port
            folder: Mailbox folder to monitor
            max_results: Max number of emails to fetch
            unread_only: Only fetch unread emails
            use_ssl: Use SSL/TLS
            save: Save emails to local storage

        Returns:
            List of email data dicts
        """
        handler = IMAPHandler(host=host, port=port, use_ssl=use_ssl)
        with handler:
            handler.connect(username, password)
            emails = handler.fetch_emails(
                max_results=max_results,
                folder=folder,
                unread_only=unread_only,
            )

        if save:
            self.data_manager.save_emails(emails, account=username)

        return emails

    def monitor_imap_auto(
        self,
        email_address: str,
        password: str,
        folder: str = "INBOX",
        max_results: int = 10,
        unread_only: bool = False,
        save: bool = False,
    ) -> List[Dict]:
        """
        Auto-detect IMAP server from email domain and fetch emails.

        Args:
            email_address: Full email address (used for server auto-detection)
            password: Login password
            folder: Mailbox folder
            max_results: Max emails to fetch
            unread_only: Only fetch unread
            save: Save to local storage

        Returns:
            List of email data dicts
        """
        handler = IMAPHandler.from_email_address(email_address)
        with handler:
            handler.connect(email_address, password)
            emails = handler.fetch_emails(
                max_results=max_results,
                folder=folder,
                unread_only=unread_only,
            )

        if save:
            self.data_manager.save_emails(emails, account=email_address)

        return emails

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def display_emails(self, emails: List[Dict], mask: bool = False) -> None:
        """
        Display emails in a formatted console view.

        Args:
            emails: List of email data dicts
            mask: Mask sender addresses
        """
        if not emails:
            print(f"{Fore.YELLOW}No emails found.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  📬 Found {len(emails)} email(s){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

        for i, email_data in enumerate(emails, 1):
            unread_indicator = f"{Fore.BLUE}● {Style.RESET_ALL}" if email_data.get('is_unread') else "  "
            attach_indicator = " 📎" if email_data.get('has_attachments') else ""

            sender = email_data.get('from', '')
            if mask and sender:
                sender = self._mask_email(sender)

            print(f"{unread_indicator}{Fore.WHITE}{i:2}. {Style.RESET_ALL}"
                  f"{Fore.GREEN}{email_data.get('subject', '(No Subject)')}{Style.RESET_ALL}{attach_indicator}")
            print(f"     {Fore.YELLOW}From:{Style.RESET_ALL} {sender}")
            print(f"     {Fore.YELLOW}Date:{Style.RESET_ALL} {email_data.get('date', '')}")
            if email_data.get('preview'):
                preview = email_data['preview'][:100].replace('\n', ' ')
                print(f"     {Fore.YELLOW}Preview:{Style.RESET_ALL} {preview}...")
            print()

    def _mask_email(self, email_str: str) -> str:
        """Mask an email address for display."""
        import re
        def mask(m):
            addr = m.group(0)
            parts = addr.split('@')
            if len(parts) == 2:
                local = parts[0]
                masked = local[:2] + '***' + local[-1:] if len(local) > 3 else '***'
                return f"{masked}@{parts[1]}"
            return addr
        return re.sub(r'[\w._%+\-]+@[\w.\-]+\.\w+', mask, email_str)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        return self.data_manager.get_email_stats()
