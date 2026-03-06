#!/usr/bin/env python3
"""
Wallet Detection Module
Detects wallet types and derivation paths compatible with a seed phrase
"""

from typing import Dict, List, Optional


# Standard BIP44/BIP49/BIP84 derivation paths for common wallets
WALLET_TYPES = {
    "Bitcoin (BIP44 Legacy)": {
        "symbol": "BTC",
        "path": "m/44'/0'/0'/0/0",
        "description": "Legacy P2PKH addresses (starts with 1)",
        "slip44": 0,
    },
    "Bitcoin (BIP49 SegWit)": {
        "symbol": "BTC",
        "path": "m/49'/0'/0'/0/0",
        "description": "SegWit P2SH-P2WPKH addresses (starts with 3)",
        "slip44": 0,
    },
    "Bitcoin (BIP84 Native SegWit)": {
        "symbol": "BTC",
        "path": "m/84'/0'/0'/0/0",
        "description": "Native SegWit bech32 addresses (starts with bc1)",
        "slip44": 0,
    },
    "Ethereum": {
        "symbol": "ETH",
        "path": "m/44'/60'/0'/0/0",
        "description": "Ethereum and EVM-compatible chains",
        "slip44": 60,
    },
    "Binance Smart Chain": {
        "symbol": "BNB",
        "path": "m/44'/60'/0'/0/0",
        "description": "BSC uses same derivation as Ethereum",
        "slip44": 60,
    },
    "Polygon (MATIC)": {
        "symbol": "MATIC",
        "path": "m/44'/60'/0'/0/0",
        "description": "Polygon uses same derivation as Ethereum",
        "slip44": 60,
    },
    "Solana": {
        "symbol": "SOL",
        "path": "m/44'/501'/0'/0'",
        "description": "Solana blockchain",
        "slip44": 501,
    },
    "Litecoin": {
        "symbol": "LTC",
        "path": "m/44'/2'/0'/0/0",
        "description": "Litecoin blockchain",
        "slip44": 2,
    },
    "Dogecoin": {
        "symbol": "DOGE",
        "path": "m/44'/3'/0'/0/0",
        "description": "Dogecoin blockchain",
        "slip44": 3,
    },
    "Ripple (XRP)": {
        "symbol": "XRP",
        "path": "m/44'/144'/0'/0/0",
        "description": "XRP Ledger",
        "slip44": 144,
    },
    "Cardano (ADA)": {
        "symbol": "ADA",
        "path": "m/1852'/1815'/0'/0/0",
        "description": "Cardano blockchain (Shelley era)",
        "slip44": 1815,
    },
    "Avalanche": {
        "symbol": "AVAX",
        "path": "m/44'/9000'/0'/0/0",
        "description": "Avalanche C-Chain",
        "slip44": 9000,
    },
    "Cosmos (ATOM)": {
        "symbol": "ATOM",
        "path": "m/44'/118'/0'/0/0",
        "description": "Cosmos Hub",
        "slip44": 118,
    },
    "Tron (TRX)": {
        "symbol": "TRX",
        "path": "m/44'/195'/0'/0/0",
        "description": "Tron blockchain",
        "slip44": 195,
    },
    "Polkadot (DOT)": {
        "symbol": "DOT",
        "path": "m/44'/354'/0'/0/0",
        "description": "Polkadot blockchain",
        "slip44": 354,
    },
}

# Word count to entropy bits mapping
WORD_COUNT_TO_ENTROPY = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}


class WalletDetector:
    """Detect wallet type and derivation path compatibility"""

    def __init__(self):
        self.wallet_types = WALLET_TYPES

    def detect_compatible_wallets(self, phrase: str) -> List[Dict]:
        """
        Detect all wallet types compatible with the seed phrase

        Args:
            phrase: Validated BIP39 seed phrase

        Returns:
            List of compatible wallet type dictionaries
        """
        word_count = len(phrase.split())
        entropy_bits = WORD_COUNT_TO_ENTROPY.get(word_count, 0)

        compatible = []
        for name, info in self.wallet_types.items():
            compatible.append({
                "wallet": name,
                "symbol": info["symbol"],
                "derivation_path": info["path"],
                "description": info["description"],
                "slip44_coin_type": info["slip44"],
                "entropy_bits": entropy_bits,
                "word_count": word_count,
            })

        return compatible

    def get_wallet_by_symbol(self, symbol: str) -> Optional[Dict]:
        """
        Get wallet info by cryptocurrency symbol

        Args:
            symbol: Cryptocurrency symbol (e.g. 'BTC', 'ETH')

        Returns:
            Wallet info dict or None
        """
        symbol_upper = symbol.upper()
        for name, info in self.wallet_types.items():
            if info["symbol"] == symbol_upper:
                return {
                    "wallet": name,
                    **info,
                }
        return None

    def get_security_level(self, word_count: int) -> Dict:
        """
        Get security level information based on word count

        Args:
            word_count: Number of words in seed phrase

        Returns:
            Security level info dict
        """
        entropy_bits = WORD_COUNT_TO_ENTROPY.get(word_count, 0)

        if entropy_bits >= 256:
            level = "Maximum"
            rating = 5
            description = "Extremely high security - suitable for large holdings"
        elif entropy_bits >= 192:
            level = "Very High"
            rating = 4
            description = "Very strong security - recommended for significant holdings"
        elif entropy_bits >= 160:
            level = "High"
            rating = 3
            description = "Strong security - suitable for most use cases"
        elif entropy_bits >= 128:
            level = "Standard"
            rating = 2
            description = "Standard security - minimum recommended for crypto wallets"
        else:
            level = "Unknown"
            rating = 0
            description = "Unknown security level"

        return {
            "level": level,
            "rating": rating,
            "entropy_bits": entropy_bits,
            "word_count": word_count,
            "description": description,
            "combinations": f"2^{entropy_bits}" if entropy_bits else "unknown",
        }

    def list_all_wallets(self) -> List[str]:
        """Return list of all supported wallet names"""
        return list(self.wallet_types.keys())
