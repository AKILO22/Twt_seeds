#!/usr/bin/env python3
"""
Data Management Module
Handles secure storage, organization, audit logging, and export of seed data
"""

import json
import csv
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from security import SecurityManager
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False


class DataManager:
    """Manage storage, retrieval, and export of seed phrase data"""

    DEFAULT_STORAGE_DIR = "data"
    AUDIT_LOG_FILE = "audit.log"
    PHRASES_FILE = "phrases.json"
    ENCRYPTED_FILE = "phrases.enc"
    SALT_FILE = "salt.bin"

    def __init__(self, storage_dir: str = None, enable_encryption: bool = False):
        """
        Initialize data manager

        Args:
            storage_dir: Directory for storing data files
            enable_encryption: Whether to encrypt stored data
        """
        self.storage_dir = Path(storage_dir or self.DEFAULT_STORAGE_DIR)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.enable_encryption = enable_encryption and SECURITY_AVAILABLE
        self.security = SecurityManager() if SECURITY_AVAILABLE else None
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Set up audit logger"""
        log_path = self.storage_dir / self.AUDIT_LOG_FILE
        self.logger = logging.getLogger("data_manager")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(str(log_path))
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _audit(self, action: str, details: str = "") -> None:
        """Write an audit log entry"""
        self.logger.info("%s | %s", action, details)

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def save_phrases(self, phrases: List[Dict], password: Optional[str] = None) -> str:
        """
        Save phrase data to storage

        Args:
            phrases: List of phrase data dicts
            password: Encryption password (required if encryption enabled)

        Returns:
            Path to saved file
        """
        if self.enable_encryption:
            if not password:
                raise ValueError("Password required for encrypted storage")
            return self._save_encrypted(phrases, password)
        return self._save_plaintext(phrases)

    def _save_plaintext(self, phrases: List[Dict]) -> str:
        filepath = self.storage_dir / self.PHRASES_FILE
        existing = self._load_plaintext()
        existing.extend(phrases)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        self._audit("SAVE_PLAINTEXT", f"Saved {len(phrases)} phrase(s)")
        return str(filepath)

    def _save_encrypted(self, phrases: List[Dict], password: str) -> str:
        """Save phrases in encrypted form using Fernet"""
        enc_path = self.storage_dir / self.ENCRYPTED_FILE
        salt_path = self.storage_dir / self.SALT_FILE

        # Load existing data if any
        existing = self._load_encrypted(password) if enc_path.exists() else []
        existing.extend(phrases)

        data_str = json.dumps(existing, ensure_ascii=False)
        encrypted, salt = self.security.encrypt(data_str, password)

        enc_path.write_bytes(encrypted)
        salt_path.write_bytes(salt)
        self._audit("SAVE_ENCRYPTED", f"Saved {len(phrases)} phrase(s) (encrypted)")
        return str(enc_path)

    def load_phrases(self, password: Optional[str] = None) -> List[Dict]:
        """
        Load phrase data from storage

        Args:
            password: Decryption password (required if encryption enabled)

        Returns:
            List of phrase data dicts
        """
        if self.enable_encryption:
            if not password:
                raise ValueError("Password required to decrypt stored data")
            return self._load_encrypted(password)
        return self._load_plaintext()

    def _load_plaintext(self) -> List[Dict]:
        filepath = self.storage_dir / self.PHRASES_FILE
        if not filepath.exists():
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _load_encrypted(self, password: str) -> List[Dict]:
        enc_path = self.storage_dir / self.ENCRYPTED_FILE
        salt_path = self.storage_dir / self.SALT_FILE
        if not enc_path.exists():
            return []
        encrypted = enc_path.read_bytes()
        salt = salt_path.read_bytes()
        data_str = self.security.decrypt(encrypted, password, salt)
        self._audit("LOAD_ENCRYPTED", "Loaded encrypted phrases")
        return json.loads(data_str)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, phrases: List[Dict], filepath: str) -> str:
        """Export data to JSON file"""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(phrases, f, indent=2, ensure_ascii=False)
        self._audit("EXPORT_JSON", f"Exported {len(phrases)} phrase(s) to {filepath}")
        return os.path.abspath(filepath)

    def export_csv(self, phrases: List[Dict], filepath: str) -> str:
        """Export data to CSV file"""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        if phrases:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=phrases[0].keys())
                writer.writeheader()
                writer.writerows(phrases)
        self._audit("EXPORT_CSV", f"Exported {len(phrases)} phrase(s) to {filepath}")
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # Deletion / Purge
    # ------------------------------------------------------------------

    def delete_all(self) -> None:
        """Securely delete all stored phrase data"""
        for filename in [self.PHRASES_FILE, self.ENCRYPTED_FILE, self.SALT_FILE]:
            path = self.storage_dir / filename
            if path.exists():
                # Overwrite with zeros before deletion
                size = path.stat().st_size
                with open(path, 'wb') as f:
                    f.write(b'\x00' * size)
                path.unlink()
        self._audit("DELETE_ALL", "All stored data purged")

    # ------------------------------------------------------------------
    # Organisation
    # ------------------------------------------------------------------

    def group_by_wallet_type(self, phrases: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group phrases by wallet type

        Args:
            phrases: List of phrase data dicts (must contain 'wallet_type' key)

        Returns:
            Dict mapping wallet type -> list of phrase dicts
        """
        groups: Dict[str, List[Dict]] = {}
        for phrase in phrases:
            wallet = phrase.get("wallet_type", "Unknown")
            groups.setdefault(wallet, []).append(phrase)
        return groups

    def get_stats(self, phrases: List[Dict]) -> Dict:
        """
        Calculate summary statistics for stored phrases

        Args:
            phrases: List of phrase data dicts

        Returns:
            Stats dictionary
        """
        total = len(phrases)
        valid = sum(1 for p in phrases if p.get("is_valid", False))
        word_counts: Dict[int, int] = {}
        for p in phrases:
            wc = p.get("word_count", 0)
            word_counts[wc] = word_counts.get(wc, 0) + 1

        return {
            "total": total,
            "valid": valid,
            "invalid": total - valid,
            "word_count_distribution": word_counts,
            "generated_at": datetime.now().isoformat(),
        }
