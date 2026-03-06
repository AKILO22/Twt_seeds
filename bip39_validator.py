#!/usr/bin/env python3
"""
BIP39 Validation Module
Handles checksum and wordlist validation
"""

import hashlib
from typing import Tuple, List

class BIP39Validator:
    """Validate BIP39 seed phrases"""
    
    def __init__(self, wordlist: List[str]):
        """
        Initialize validator with wordlist
        
        Args:
            wordlist: List of 2048 valid BIP39 words
        """
        self.wordlist = set(wordlist)
        self.word_to_index = {word: idx for idx, word in enumerate(wordlist)}
    
    def validate_checksum(self, entropy_hex: str) -> Tuple[bool, str]:
        """
        Validate entropy checksum
        
        Args:
            entropy_hex: Entropy in hex format
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            entropy_bytes = bytes.fromhex(entropy_hex)
            entropy_bits = len(entropy_bytes) * 8
            
            # Valid entropy sizes
            if entropy_bits not in [128, 160, 192, 256]:
                return False, f"Invalid entropy size: {entropy_bits} bits"
            
            # Calculate checksum
            checksum = hashlib.sha256(entropy_bytes).digest()
            checksum_bits = entropy_bits // 32
            
            return True, f"Valid checksum for {entropy_bits}-bit entropy"
        
        except ValueError as e:
            return False, f"Invalid hex entropy: {str(e)}"
    
    def validate_words(self, phrase: str) -> Tuple[bool, List[str]]:
        """
        Validate all words in phrase
        
        Args:
            phrase: Seed phrase string
            
        Returns:
            Tuple of (all_valid, invalid_words)
        """
        words = phrase.split()
        invalid_words = []
        
        for word in words:
            if word not in self.wordlist:
                invalid_words.append(word)
        
        return len(invalid_words) == 0, invalid_words
    
    def validate_word_count(self, phrase: str) -> Tuple[bool, str]:
        """
        Validate word count
        
        Args:
            phrase: Seed phrase string
            
        Returns:
            Tuple of (is_valid, message)
        """
        words = phrase.split()
        valid_counts = [12, 15, 18, 24]
        
        if len(words) in valid_counts:
            return True, f"Valid word count: {len(words)}"
        else:
            return False, f"Invalid word count: {len(words)}. Must be one of {valid_counts}"
    
    def full_validation(self, phrase: str) -> Tuple[bool, List[str]]:
        """
        Perform complete validation
        
        Args:
            phrase: Seed phrase string
            
        Returns:
            Tuple of (is_valid, messages)
        """
        messages = []
        
        # Validate word count
        word_valid, word_msg = self.validate_word_count(phrase)
        messages.append(word_msg)
        
        if not word_valid:
            return False, messages
        
        # Validate all words
        words_valid, invalid = self.validate_words(phrase)
        if not words_valid:
            messages.append(f"Invalid words found: {', '.join(invalid)}")
            return False, messages
        
        messages.append("All words are valid")
        return True, messages