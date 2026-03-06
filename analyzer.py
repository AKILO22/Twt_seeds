#!/usr/bin/env python3
"""
Seed Phrase Analysis Module
Extracts entropy, calculates checksums, shows word indices, generates reports
"""

import hashlib
import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from mnemonic import Mnemonic
from security import SecurityManager


class SeedPhraseAnalyzer:
    """Analyze BIP39 seed phrases and generate reports"""

    def __init__(self):
        self.mnemo = Mnemonic("english")
        self.wordlist = self.mnemo.wordlist
        self.word_to_index = {w: i for i, w in enumerate(self.wordlist)}

    def analyze(self, phrase: str) -> Dict:
        """
        Perform comprehensive analysis of a seed phrase

        Args:
            phrase: BIP39 seed phrase string

        Returns:
            Analysis result dictionary
        """
        words = phrase.strip().lower().split()
        word_count = len(words)

        # Word indices
        word_indices = []
        invalid_words = []
        for word in words:
            idx = self.word_to_index.get(word)
            if idx is not None:
                word_indices.append({"word": word, "index": idx})
            else:
                word_indices.append({"word": word, "index": None})
                invalid_words.append(word)

        # Entropy extraction
        entropy_hex = None
        entropy_bits = None
        checksum_bits = None
        checksum_hex = None
        bip39_seed_hex = None
        is_valid = False

        if not invalid_words and word_count in (12, 15, 18, 21, 24):
            is_valid = self.mnemo.check(phrase)
            if is_valid:
                entropy_bytes = self.mnemo.to_entropy(words)
                entropy_hex = entropy_bytes.hex()
                entropy_bits = len(entropy_bytes) * 8
                checksum_bits = entropy_bits // 32

                # SHA256 checksum of entropy
                sha = hashlib.sha256(entropy_bytes).digest()
                checksum_byte = sha[0]
                # Extract the top checksum_bits from the first byte
                checksum_val = checksum_byte >> (8 - checksum_bits)
                checksum_hex = hex(checksum_val)

                # BIP39 seed (PBKDF2-HMAC-SHA512)
                bip39_seed_hex = self.mnemo.to_seed(phrase, "").hex()

        return {
            "phrase": phrase,
            "word_count": word_count,
            "words": word_indices,
            "invalid_words": invalid_words,
            "is_valid": is_valid,
            "entropy_hex": entropy_hex,
            "entropy_bits": entropy_bits,
            "checksum_bits": checksum_bits,
            "checksum_value": checksum_hex,
            "bip39_seed_hex": bip39_seed_hex,
            "timestamp": datetime.now().isoformat(),
        }

    def get_entropy_bits(self, phrase: str) -> Optional[int]:
        """
        Get the entropy bit count for a valid seed phrase

        Args:
            phrase: BIP39 seed phrase

        Returns:
            Entropy bit count or None if invalid
        """
        result = self.analyze(phrase)
        return result.get("entropy_bits")

    def display_analysis(self, result: Dict, mask: bool = False) -> None:
        """
        Print a formatted analysis report to console

        Args:
            result: Analysis result from analyze()
            mask: Whether to mask the phrase and entropy
        """
        phrase = result["phrase"]
        if mask:
            phrase_display = SecurityManager().mask_phrase(phrase)
        else:
            phrase_display = phrase

        print("\n" + "=" * 70)
        print("  SEED PHRASE ANALYSIS REPORT")
        print("=" * 70)
        print(f"  Phrase       : {phrase_display}")
        print(f"  Word Count   : {result['word_count']}")
        print(f"  Valid        : {'✅ Yes' if result['is_valid'] else '❌ No'}")

        if result["invalid_words"]:
            print(f"  Invalid Words: {', '.join(result['invalid_words'])}")

        if result["entropy_bits"]:
            entropy_display = result["entropy_hex"] if not mask else "****"
            print(f"  Entropy Bits : {result['entropy_bits']}")
            print(f"  Entropy Hex  : {entropy_display}")
            print(f"  Checksum Bits: {result['checksum_bits']}")
            print(f"  Checksum     : {result['checksum_value']}")

        print(f"\n  Timestamp    : {result['timestamp']}")

        print("\n  Word Index Table:")
        print("  " + "-" * 40)
        for i, entry in enumerate(result["words"], 1):
            idx_str = str(entry["index"]) if entry["index"] is not None else "INVALID"
            word_display = entry["word"] if not mask or i <= 2 else "****"
            print(f"  {i:>3}. {word_display:<12}  index: {idx_str}")
        print("=" * 70)

    def export_json(self, results: List[Dict], filepath: str) -> str:
        """
        Export analysis results to JSON

        Args:
            results: List of analysis result dicts
            filepath: Output file path

        Returns:
            Absolute path to saved file
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        return os.path.abspath(filepath)

    def export_csv(self, results: List[Dict], filepath: str) -> str:
        """
        Export analysis results to CSV

        Args:
            results: List of analysis result dicts
            filepath: Output file path

        Returns:
            Absolute path to saved file
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        # Flatten for CSV: omit nested word_indices list
        flat = []
        for r in results:
            flat.append({
                "phrase": r["phrase"],
                "word_count": r["word_count"],
                "is_valid": r["is_valid"],
                "entropy_bits": r.get("entropy_bits", ""),
                "entropy_hex": r.get("entropy_hex", ""),
                "checksum_bits": r.get("checksum_bits", ""),
                "checksum_value": r.get("checksum_value", ""),
                "invalid_words": ", ".join(r.get("invalid_words", [])),
                "timestamp": r.get("timestamp", ""),
            })

        if flat:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=flat[0].keys())
                writer.writeheader()
                writer.writerows(flat)

        return os.path.abspath(filepath)

    def export_html(self, results: List[Dict], filepath: str,
                    mask: bool = False) -> str:
        """
        Export analysis results to an HTML report

        Args:
            results: List of analysis result dicts
            filepath: Output file path
            mask: Whether to mask sensitive data

        Returns:
            Absolute path to saved file
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        rows = []
        for idx, r in enumerate(results, 1):
            phrase = r["phrase"]
            if mask:
                phrase_display = SecurityManager().mask_phrase(phrase)
                entropy_display = "****"
            else:
                phrase_display = phrase
                entropy_display = r.get("entropy_hex", "N/A")

            valid_label = (
                '<span style="color:green">✅ Valid</span>'
                if r["is_valid"]
                else '<span style="color:red">❌ Invalid</span>'
            )
            rows.append(
                f"<tr>"
                f"<td>{idx}</td>"
                f"<td style='font-family:monospace'>{phrase_display}</td>"
                f"<td>{r['word_count']}</td>"
                f"<td>{valid_label}</td>"
                f"<td>{r.get('entropy_bits', 'N/A')}</td>"
                f"<td style='font-family:monospace;font-size:0.8em'>{entropy_display}</td>"
                f"<td>{r.get('timestamp', '')}</td>"
                f"</tr>"
            )

        table_rows = "\n".join(rows)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Seed Phrase Analysis Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 2em; background: #f5f5f5; }}
  h1 {{ color: #333; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th {{ background: #4a90d9; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #ddd; }}
  tr:hover {{ background: #f0f7ff; }}
  .meta {{ color: #666; font-size: 0.9em; margin-bottom: 1em; }}
</style>
</head>
<body>
<h1>🔍 Seed Phrase Analysis Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
Total phrases: {len(results)} &nbsp;|&nbsp;
Valid: {sum(1 for r in results if r['is_valid'])}</p>
<table>
<thead>
<tr>
  <th>#</th>
  <th>Seed Phrase</th>
  <th>Words</th>
  <th>Valid</th>
  <th>Entropy (bits)</th>
  <th>Entropy (hex)</th>
  <th>Timestamp</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        return os.path.abspath(filepath)
