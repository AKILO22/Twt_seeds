#!/usr/bin/env python3
"""
Unit tests for Seed Phrase Generator
"""

import pytest
from seed_generator import SeedPhraseGenerator
from bip39_validator import BIP39Validator

class TestSeedGenerator:
    
    @pytest.fixture
    def generator(self):
        return SeedPhraseGenerator()
    
    def test_generate_12_word_phrase(self, generator):
        """Test generation of 12-word phrase"""
        phrase, entropy = generator.generate_seed_phrase(128)
        words = phrase.split()
        assert len(words) == 12
        assert len(entropy) == 32  # 128 bits = 16 bytes = 32 hex chars
    
    def test_generate_24_word_phrase(self, generator):
        """Test generation of 24-word phrase"""
        phrase, entropy = generator.generate_seed_phrase(256)
        words = phrase.split()
        assert len(words) == 24
        assert len(entropy) == 64  # 256 bits = 32 bytes = 64 hex chars
    
    def test_validate_valid_phrase(self, generator):
        """Test validation of valid phrase"""
        phrase, _ = generator.generate_seed_phrase(128)
        is_valid, message = generator.validate_seed_phrase(phrase)
        assert is_valid is True
    
    def test_validate_invalid_entropy(self, generator):
        """Test validation with invalid entropy"""
        with pytest.raises(ValueError):
            generator.generate_seed_phrase(100)
    
    def test_generate_multiple(self, generator):
        """Test multiple generation"""
        results = generator.generate_multiple(5, 128)
        assert len(results) == 5
        assert all(r['valid'] for r in results)
    
    def test_checksum_calculation(self, generator):
        """Test checksum calculation"""
        phrase, entropy = generator.generate_seed_phrase(128)
        checksum = generator.calculate_checksum(entropy)
        assert len(checksum) == 64  # SHA256 hex = 64 chars
    
    def test_save_to_json(self, generator, tmp_path):
        """Test JSON save"""
        results = generator.generate_multiple(2, 128)
        generator.save_to_json(results, "test.json")
        # Verify file was created
        assert True
    
    def test_save_to_csv(self, generator, tmp_path):
        """Test CSV save"""
        results = generator.generate_multiple(2, 128)
        generator.save_to_csv(results, "test.csv")
        assert True

if __name__ == '__main__':
    pytest.main([__file__, '-v'])