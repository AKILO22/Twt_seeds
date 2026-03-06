#!/usr/bin/env python3
"""
Unit tests for Seed Phrase Tool
"""

import os
import json
import tempfile
import pytest
from seed_generator import SeedPhraseGenerator
from bip39_validator import BIP39Validator
from analyzer import SeedPhraseAnalyzer
from wallet_detector import WalletDetector
from data_manager import DataManager
from capture import SeedPhraseCapture
from security import SecurityManager


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
        """Test JSON save creates file with valid content"""
        results = generator.generate_multiple(2, 128)
        filepath = generator.save_to_json(results, "test_review.json")
        assert os.path.exists(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert len(data) == 2
        assert all(r["valid"] for r in data)

    def test_save_to_csv(self, generator, tmp_path):
        """Test CSV save creates file with valid content"""
        import csv as csv_module
        results = generator.generate_multiple(2, 128)
        filepath = generator.save_to_csv(results, "test_review.csv")
        assert os.path.exists(filepath)
        with open(filepath, newline='') as f:
            reader = csv_module.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert "phrase" in rows[0]


class TestBIP39Validator:

    @pytest.fixture
    def validator(self):
        from mnemonic import Mnemonic
        wordlist = Mnemonic("english").wordlist
        return BIP39Validator(wordlist)

    def test_validate_word_count_valid(self, validator):
        is_valid, msg = validator.validate_word_count("a " * 12)
        assert is_valid is True

    def test_validate_word_count_invalid(self, validator):
        is_valid, msg = validator.validate_word_count("a " * 10)
        assert is_valid is False

    def test_validate_words_valid(self, validator):
        phrase = "abandon " * 11 + "about"
        is_valid, invalid = validator.validate_words(phrase)
        assert is_valid is True
        assert invalid == []

    def test_validate_words_invalid(self, validator):
        phrase = "notaword1 notaword2 " + "abandon " * 10
        is_valid, invalid = validator.validate_words(phrase)
        assert is_valid is False
        assert "notaword1" in invalid

    def test_validate_checksum_valid(self, validator):
        # 16 bytes = 128 bits
        entropy_hex = "0" * 32
        is_valid, msg = validator.validate_checksum(entropy_hex)
        assert is_valid is True

    def test_validate_checksum_invalid_size(self, validator):
        # 10 bytes = 80 bits (not valid)
        entropy_hex = "0" * 20
        is_valid, msg = validator.validate_checksum(entropy_hex)
        assert is_valid is False


class TestSeedPhraseAnalyzer:

    @pytest.fixture
    def analyzer(self):
        return SeedPhraseAnalyzer()

    @pytest.fixture
    def valid_phrase(self):
        gen = SeedPhraseGenerator()
        phrase, _ = gen.generate_seed_phrase(128)
        return phrase

    def test_analyze_valid_phrase(self, analyzer, valid_phrase):
        result = analyzer.analyze(valid_phrase)
        assert result["is_valid"] is True
        assert result["word_count"] == 12
        assert result["entropy_bits"] == 128
        assert result["entropy_hex"] is not None
        assert result["checksum_value"] is not None

    def test_analyze_invalid_phrase(self, analyzer):
        result = analyzer.analyze("notaword " * 12)
        assert result["is_valid"] is False
        assert len(result["invalid_words"]) > 0

    def test_word_indices(self, analyzer, valid_phrase):
        result = analyzer.analyze(valid_phrase)
        for entry in result["words"]:
            assert entry["index"] is not None
            assert 0 <= entry["index"] <= 2047

    def test_export_json(self, analyzer, valid_phrase, tmp_path):
        results = [analyzer.analyze(valid_phrase)]
        out = str(tmp_path / "analysis.json")
        path = analyzer.export_json(results, out)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["is_valid"] is True

    def test_export_csv(self, analyzer, valid_phrase, tmp_path):
        results = [analyzer.analyze(valid_phrase)]
        out = str(tmp_path / "analysis.csv")
        path = analyzer.export_csv(results, out)
        assert os.path.exists(path)

    def test_export_html(self, analyzer, valid_phrase, tmp_path):
        results = [analyzer.analyze(valid_phrase)]
        out = str(tmp_path / "analysis.html")
        path = analyzer.export_html(results, out)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "<html" in content
        assert "Seed Phrase Analysis Report" in content


class TestWalletDetector:

    @pytest.fixture
    def detector(self):
        return WalletDetector()

    @pytest.fixture
    def valid_phrase(self):
        gen = SeedPhraseGenerator()
        phrase, _ = gen.generate_seed_phrase(128)
        return phrase

    def test_detect_compatible_wallets(self, detector, valid_phrase):
        wallets = detector.detect_compatible_wallets(valid_phrase)
        assert len(wallets) > 0
        names = [w["wallet"] for w in wallets]
        assert "Ethereum" in names
        assert "Bitcoin (BIP44 Legacy)" in names
        assert "Solana" in names

    def test_wallet_has_derivation_path(self, detector, valid_phrase):
        wallets = detector.detect_compatible_wallets(valid_phrase)
        for w in wallets:
            assert w["derivation_path"].startswith("m/")

    def test_get_wallet_by_symbol(self, detector):
        info = detector.get_wallet_by_symbol("ETH")
        assert info is not None
        assert info["symbol"] == "ETH"

    def test_get_security_level_128(self, detector):
        sec = detector.get_security_level(12)
        assert sec["entropy_bits"] == 128
        assert sec["level"] == "Standard"

    def test_get_security_level_256(self, detector):
        sec = detector.get_security_level(24)
        assert sec["entropy_bits"] == 256
        assert sec["level"] == "Maximum"

    def test_list_all_wallets(self, detector):
        names = detector.list_all_wallets()
        assert len(names) >= 10


class TestDataManager:

    @pytest.fixture
    def dm(self, tmp_path):
        return DataManager(storage_dir=str(tmp_path))

    @pytest.fixture
    def sample_phrases(self):
        gen = SeedPhraseGenerator()
        results = gen.generate_multiple(2, 128)
        return [
            {
                "phrase": r["phrase"],
                "word_count": r["word_count"],
                "is_valid": r["valid"],
                "timestamp": r["timestamp"],
                "wallet_type": "Ethereum",
            }
            for r in results
        ]

    def test_save_and_load_plaintext(self, dm, sample_phrases):
        dm.save_phrases(sample_phrases)
        loaded = dm.load_phrases()
        assert len(loaded) == 2

    def test_save_appends(self, dm, sample_phrases):
        dm.save_phrases(sample_phrases)
        dm.save_phrases(sample_phrases)
        loaded = dm.load_phrases()
        assert len(loaded) == 4

    def test_export_json(self, dm, sample_phrases, tmp_path):
        out = str(tmp_path / "export.json")
        path = dm.export_json(sample_phrases, out)
        assert os.path.exists(path)

    def test_export_csv(self, dm, sample_phrases, tmp_path):
        out = str(tmp_path / "export.csv")
        path = dm.export_csv(sample_phrases, out)
        assert os.path.exists(path)

    def test_group_by_wallet_type(self, dm, sample_phrases):
        groups = dm.group_by_wallet_type(sample_phrases)
        assert "Ethereum" in groups
        assert len(groups["Ethereum"]) == 2

    def test_stats(self, dm, sample_phrases):
        stats = dm.get_stats(sample_phrases)
        assert stats["total"] == 2
        assert stats["valid"] == 2

    def test_delete_all(self, dm, sample_phrases):
        dm.save_phrases(sample_phrases)
        dm.delete_all()
        loaded = dm.load_phrases()
        assert loaded == []

    def test_encrypted_save_load(self, tmp_path, sample_phrases):
        dm = DataManager(storage_dir=str(tmp_path), enable_encryption=True)
        dm.save_phrases(sample_phrases, password="testpass123")
        loaded = dm.load_phrases(password="testpass123")
        assert len(loaded) == 2

    def test_wrong_password_raises(self, tmp_path, sample_phrases):
        dm = DataManager(storage_dir=str(tmp_path), enable_encryption=True)
        dm.save_phrases(sample_phrases, password="correctpass")
        with pytest.raises(Exception):
            dm.load_phrases(password="wrongpass")


class TestSeedPhraseCapture:

    @pytest.fixture
    def capturer(self):
        return SeedPhraseCapture()

    def test_sanitize_phrase(self, capturer):
        raw = "  ABANDON   ability  ABLE  "
        result = capturer.sanitize_phrase(raw)
        assert result == "abandon ability able"

    def test_sanitize_normalizes_spaces(self, capturer):
        raw = "abandon  ability   able"
        result = capturer.sanitize_phrase(raw)
        assert result == "abandon ability able"

    def test_capture_from_file(self, capturer, tmp_path):
        phrases = [
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
            "# this is a comment",
            "",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ]
        f = tmp_path / "phrases.txt"
        f.write_text("\n".join(phrases))
        result = capturer.capture_from_file(str(f))
        assert len(result) == 2  # comment and blank line excluded
        assert result[0].startswith("abandon")

    def test_capture_from_file_not_found(self, capturer):
        with pytest.raises(FileNotFoundError):
            capturer.capture_from_file("/nonexistent/file.txt")


class TestSecurityManager:

    @pytest.fixture
    def sm(self):
        return SecurityManager()

    def test_generate_salt(self, sm):
        salt = sm.generate_salt()
        assert len(salt) == 32

    def test_encrypt_decrypt(self, sm):
        data = "test seed phrase data"
        encrypted, salt = sm.encrypt(data, "password123")
        decrypted = sm.decrypt(encrypted, "password123", salt)
        assert decrypted == data

    def test_wrong_password_fails(self, sm):
        data = "test data"
        encrypted, salt = sm.encrypt(data, "correctpass")
        with pytest.raises(Exception):
            sm.decrypt(encrypted, "wrongpass", salt)

    def test_mask_phrase(self, sm):
        phrase = "abandon ability able about above absent"
        masked = sm.mask_phrase(phrase, visible_words=2)
        parts = masked.split()
        assert parts[0] == "abandon"
        assert parts[1] == "ability"
        assert all('*' in p for p in parts[2:])

    def test_hash_password(self, sm):
        salt = sm.generate_salt()
        h1 = sm.hash_password("mypassword", salt)
        h2 = sm.hash_password("mypassword", salt)
        assert h1 == h2

    def test_secure_clear(self, sm):
        data = bytearray(b"sensitive data here")
        sm.secure_clear(data)
        assert all(b == 0 for b in data)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
