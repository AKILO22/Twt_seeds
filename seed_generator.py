#!/usr/bin/env python3
"""
BIP39 Seed Phrase Generator
Generates cryptographically secure seed phrases with validation
"""

import os
import json
import csv
import secrets
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict
from mnemonic import Mnemonic

class SeedPhraseGenerator:
    """Generate and validate BIP39 seed phrases"""
    
    # Entropy bits to word count mapping
    ENTROPY_WORD_MAP = {
        128: 12,   # 128 bits = 12 words
        160: 15,   # 160 bits = 15 words
        192: 18,   # 192 bits = 18 words
        256: 24    # 256 bits = 24 words
    }
    
    def __init__(self, wordlist_path: str = None):
        """
        Initialize the seed phrase generator
        
        Args:
            wordlist_path: Path to BIP39 wordlist file
        """
        self.mnemo = Mnemonic("english")
        self.wordlist = self.mnemo.wordlist
        
    def generate_seed_phrase(self, entropy_bits: int = 128) -> Tuple[str, str]:
        """
        Generate a single BIP39 seed phrase
        
        Args:
            entropy_bits: Entropy strength (128, 160, 192, 256)
            
        Returns:
            Tuple of (seed_phrase, entropy_hex)
        """
        if entropy_bits not in self.ENTROPY_WORD_MAP:
            raise ValueError(f"Invalid entropy: {entropy_bits}. Must be one of {list(self.ENTROPY_WORD_MAP.keys())}")
        
        # Generate random entropy
        entropy_bytes = secrets.token_bytes(entropy_bits // 8)
        entropy_hex = entropy_bytes.hex()
        
        # Convert entropy to seed phrase using mnemonic
        mnemonic_phrase = self.mnemo.to_mnemonic(entropy_bytes)
        
        return mnemonic_phrase, entropy_hex
    
    def validate_seed_phrase(self, phrase: str) -> Tuple[bool, str]:
        """
        Validate a seed phrase against BIP39 standard
        
        Args:
            phrase: The seed phrase to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Check if phrase is valid mnemonic
            if not self.mnemo.check(phrase):
                return False, "Invalid checksum or word list"
            
            # Check word count
            words = phrase.split()
            if len(words) not in self.ENTROPY_WORD_MAP.values():
                return False, f"Invalid word count: {len(words)}"
            
            # Check all words exist in wordlist
            for word in words:
                if word not in self.wordlist:
                    return False, f"Invalid word in phrase: {word}"
            
            return True, "Valid BIP39 seed phrase"
        
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def generate_multiple(self, count: int, entropy_bits: int = 128) -> List[Dict]:
        """
        Generate multiple seed phrases
        
        Args:
            count: Number of phrases to generate
            entropy_bits: Entropy strength per phrase
            
        Returns:
            List of dictionaries with phrase data
        """
        results = []
        for i in range(count):
            phrase, entropy = self.generate_seed_phrase(entropy_bits)
            is_valid, message = self.validate_seed_phrase(phrase)
            
            results.append({
                'index': i + 1,
                'phrase': phrase,
                'entropy': entropy,
                'word_count': len(phrase.split()),
                'entropy_bits': entropy_bits,
                'valid': is_valid,
                'timestamp': datetime.now().isoformat(),
                'validation_message': message
            })
        
        return results
    
    def calculate_checksum(self, entropy_hex: str) -> str:
        """
        Calculate SHA256 checksum of entropy
        
        Args:
            entropy_hex: Entropy in hex format
            
        Returns:
            SHA256 hash
        """
        entropy_bytes = bytes.fromhex(entropy_hex)
        return hashlib.sha256(entropy_bytes).hexdigest()
    
    def save_to_json(self, data: List[Dict], filename: str = None) -> str:
        """
        Save seed phrases to JSON file
        
        Args:
            data: List of seed phrase data
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"seeds_{timestamp}.json"
        
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return str(filepath)
    
    def save_to_csv(self, data: List[Dict], filename: str = None) -> str:
        """
        Save seed phrases to CSV file
        
        Args:
            data: List of seed phrase data
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"seeds_{timestamp}.csv"
        
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        
        if data:
            keys = data[0].keys()
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)
        
        return str(filepath)
    
    def save_to_txt(self, data: List[Dict], filename: str = None) -> str:
        """
        Save seed phrases to plain text file
        
        Args:
            data: List of seed phrase data
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"seeds_{timestamp}.txt"
        
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            for item in data:
                f.write(f"--- Seed #{item['index']} ---\n")
                f.write(f"Phrase: {item['phrase']}\n")
                f.write(f"Entropy: {item['entropy']}\n")
                f.write(f"Word Count: {item['word_count']}\n")
                f.write(f"Entropy Bits: {item['entropy_bits']}\n")
                f.write(f"Valid: {item['valid']}\n")
                f.write(f"Timestamp: {item['timestamp']}\n")
                f.write(f"Message: {item['validation_message']}\n")
                f.write("\n")
        
        return str(filepath)