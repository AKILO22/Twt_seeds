#!/usr/bin/env python3
"""
Seed Phrase Capture Module
Handles interactive input, clipboard integration, and file import
"""

import os
import re
import subprocess
from typing import List, Optional


class SeedPhraseCapture:
    """Capture seed phrases from various input sources"""

    def __init__(self, mask_output: bool = False):
        """
        Initialize capture module

        Args:
            mask_output: Whether to mask sensitive output
        """
        self.mask_output = mask_output
        self._termux = self._detect_termux()

    @staticmethod
    def _detect_termux() -> bool:
        """Detect if running in Termux environment"""
        return (
            os.path.exists('/data/data/com.termux') or
            'TERMUX_VERSION' in os.environ or
            os.path.exists('/data/data/com.termux/files/usr')
        )

    def capture_interactive(self, prompt: str = "Enter seed phrase: ") -> str:
        """
        Capture a seed phrase via interactive prompt

        Args:
            prompt: Prompt text to display

        Returns:
            Captured seed phrase string (stripped and lowercased)
        """
        print(prompt, end='', flush=True)
        phrase = input().strip().lower()
        return phrase

    def capture_hidden(self, prompt: str = "Paste seed phrase (hidden): ") -> str:
        """
        Capture a seed phrase without echoing to screen

        Args:
            prompt: Prompt text to display

        Returns:
            Captured seed phrase string
        """
        import getpass
        phrase = getpass.getpass(prompt).strip().lower()
        return phrase

    def capture_from_clipboard(self) -> Optional[str]:
        """
        Capture seed phrase from clipboard

        Returns:
            Clipboard contents or None if unavailable
        """
        # Try Termux clipboard first
        if self._termux:
            try:
                result = subprocess.run(
                    ['termux-clipboard-get'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return result.stdout.strip().lower()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try pyperclip (cross-platform)
        try:
            import pyperclip
            content = pyperclip.paste()
            if content:
                return content.strip().lower()
        except Exception:
            pass

        # Try xclip / xsel for Linux
        for cmd in [['xclip', '-selection', 'clipboard', '-o'],
                    ['xsel', '--clipboard', '--output'],
                    ['wl-paste']]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().lower()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    def clear_clipboard(self) -> bool:
        """
        Clear clipboard contents for security

        Returns:
            True if clipboard was cleared successfully
        """
        if self._termux:
            try:
                subprocess.run(
                    ['termux-clipboard-set', ''],
                    timeout=5, check=True
                )
                return True
            except (FileNotFoundError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired):
                pass

        try:
            import pyperclip
            pyperclip.copy('')
            return True
        except Exception:
            pass

        for cmd in [['xclip', '-selection', 'clipboard', '-i'],
                    ['xsel', '--clipboard', '--input']]:
            try:
                result = subprocess.run(
                    cmd, input='', capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return False

    def capture_from_file(self, filepath: str) -> List[str]:
        """
        Import one or more seed phrases from a file

        Each non-empty line is treated as a separate seed phrase.

        Args:
            filepath: Path to the input file

        Returns:
            List of seed phrase strings
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        phrases = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                # Skip empty lines and comment lines
                if line and not line.startswith('#'):
                    phrases.append(line)

        return phrases

    def capture_batch_interactive(self, count: Optional[int] = None) -> List[str]:
        """
        Interactively capture multiple seed phrases

        Args:
            count: Number of phrases to capture (None = until empty line)

        Returns:
            List of captured seed phrase strings
        """
        phrases = []
        index = 1

        if count is not None:
            for i in range(count):
                phrase = self.capture_interactive(
                    f"Enter seed phrase #{i + 1}: "
                )
                if phrase:
                    phrases.append(phrase)
        else:
            print("Enter seed phrases one per line. Press Enter twice to finish.")
            while True:
                phrase = self.capture_interactive(f"Phrase #{index} (blank to finish): ")
                if not phrase:
                    break
                phrases.append(phrase)
                index += 1

        return phrases

    @staticmethod
    def sanitize_phrase(phrase: str) -> str:
        """
        Sanitize a seed phrase string

        - Strip leading/trailing whitespace
        - Normalize to lowercase
        - Collapse multiple spaces to single spaces

        Args:
            phrase: Raw seed phrase string

        Returns:
            Sanitized seed phrase
        """
        phrase = phrase.strip().lower()
        phrase = re.sub(r'\s+', ' ', phrase)
        return phrase
