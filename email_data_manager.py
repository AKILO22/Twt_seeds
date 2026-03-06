#!/usr/bin/env python3
"""
Email Data Manager Module
Handles storage, export, and audit logging for email monitoring data.
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class EmailDataManager:
    """
    Manages persistent storage, export, and audit logging for email data.

    Supports:
    - JSON and CSV export
    - Email history tracking
    - Activity audit logging
    - HTML report export
    """

    DEFAULT_DIR = "email_data"
    HISTORY_FILE = "email_history.json"
    AUDIT_FILE = "email_audit.log"
    VERIFICATIONS_FILE = "email_verifications.json"

    def __init__(self, data_dir: str = None):
        """
        Initialize the email data manager.

        Args:
            data_dir: Directory for storing data files
        """
        self.data_dir = Path(data_dir or self.DEFAULT_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Set up audit logger."""
        log_path = self.data_dir / self.AUDIT_FILE
        self.logger = logging.getLogger("email_data_manager")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(str(log_path))
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _audit(self, action: str, details: str = "") -> None:
        """Write an audit log entry."""
        self.logger.info("%s | %s", action, details)

    # ------------------------------------------------------------------
    # Email History
    # ------------------------------------------------------------------

    def save_emails(self, emails: List[Dict], account: str = "default") -> str:
        """
        Save fetched emails to history storage.

        Args:
            emails: List of email data dicts
            account: Account identifier

        Returns:
            Path to saved file
        """
        history = self.load_emails()
        timestamp = datetime.now().isoformat()

        for em in emails:
            em['_saved_at'] = timestamp
            em['_account'] = account

        history.extend(emails)

        filepath = self.data_dir / self.HISTORY_FILE
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False, default=str)

        self._audit("SAVE_EMAILS", f"Saved {len(emails)} email(s) for account '{account}'")
        return str(filepath)

    def load_emails(self) -> List[Dict]:
        """
        Load email history from storage.

        Returns:
            List of email data dicts
        """
        filepath = self.data_dir / self.HISTORY_FILE
        if not filepath.exists():
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    def save_verification(self, result: Dict) -> str:
        """
        Save an email verification result.

        Args:
            result: Verification result dict

        Returns:
            Path to saved file
        """
        history = self.load_verifications()
        result['_saved_at'] = datetime.now().isoformat()
        history.append(result)

        filepath = self.data_dir / self.VERIFICATIONS_FILE
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False, default=str)

        self._audit("SAVE_VERIFICATION", f"Saved verification for {result.get('email', 'unknown')}")
        return str(filepath)

    def load_verifications(self) -> List[Dict]:
        """Load saved verification results."""
        filepath = self.data_dir / self.VERIFICATIONS_FILE
        if not filepath.exists():
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_emails_json(self, emails: List[Dict], filepath: str = None) -> str:
        """
        Export emails to JSON file.

        Args:
            emails: List of email data dicts
            filepath: Output file path (auto-generated if None)

        Returns:
            Absolute path to saved file
        """
        if not filepath:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = str(self.data_dir / f"emails_{ts}.json")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(emails, f, indent=2, ensure_ascii=False, default=str)
        self._audit("EXPORT_JSON", f"Exported {len(emails)} emails to {filepath}")
        return os.path.abspath(filepath)

    def export_emails_csv(self, emails: List[Dict], filepath: str = None) -> str:
        """
        Export emails to CSV file.

        Args:
            emails: List of email data dicts
            filepath: Output file path (auto-generated if None)

        Returns:
            Absolute path to saved file
        """
        if not filepath:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = str(self.data_dir / f"emails_{ts}.csv")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        # Flatten nested structures for CSV
        flat_emails = [self._flatten_dict(em) for em in emails]
        if not flat_emails:
            return os.path.abspath(filepath)

        fieldnames = list(flat_emails[0].keys())
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(flat_emails)

        self._audit("EXPORT_CSV", f"Exported {len(emails)} emails to {filepath}")
        return os.path.abspath(filepath)

    def export_verifications_json(self, filepath: str = None) -> str:
        """Export all verifications to JSON."""
        verifications = self.load_verifications()
        if not filepath:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = str(self.data_dir / f"verifications_{ts}.json")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(verifications, f, indent=2, ensure_ascii=False, default=str)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_email_stats(self) -> Dict:
        """Get summary statistics for stored emails."""
        emails = self.load_emails()
        total = len(emails)
        unread = sum(1 for e in emails if e.get('is_unread', False))
        sources = {}
        for e in emails:
            src = e.get('source', 'unknown')
            sources[src] = sources.get(src, 0) + 1

        return {
            'total_emails': total,
            'unread_emails': unread,
            'by_source': sources,
            'generated_at': datetime.now().isoformat(),
        }

    def get_verification_stats(self) -> Dict:
        """Get summary statistics for email verifications."""
        verifications = self.load_verifications()
        total = len(verifications)
        valid_format = sum(1 for v in verifications if v.get('format_valid', False))
        deliverable = sum(1 for v in verifications if v.get('is_deliverable', False))
        disposable = sum(1 for v in verifications if v.get('is_disposable', False))

        return {
            'total_verified': total,
            'valid_format': valid_format,
            'deliverable': deliverable,
            'disposable': disposable,
            'generated_at': datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _flatten_dict(self, d: Dict, prefix: str = '') -> Dict:
        """Flatten a nested dict for CSV export."""
        flat = {}
        for key, value in d.items():
            full_key = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                flat.update(self._flatten_dict(value, f"{full_key}_"))
            elif isinstance(value, list):
                flat[full_key] = str(value)
            else:
                flat[full_key] = value
        return flat

    def purge_history(self) -> None:
        """Delete all stored email history and verifications."""
        for filename in [self.HISTORY_FILE, self.VERIFICATIONS_FILE]:
            path = self.data_dir / filename
            if path.exists():
                path.unlink()
        self._audit("PURGE", "All email history and verification data purged")
