# 🌱 Twt_seeds — BIP39 Seed Phrase Tool for Termux

A comprehensive Python tool for capturing, validating, and analyzing BIP39 wallet seed phrases. Built for Termux (Android) with full desktop compatibility.

---

## Features

| Feature | Details |
|---|---|
| **Seed Phrase Generation** | Cryptographically secure BIP39 phrases (12, 15, 18, 24 words) |
| **Seed Phrase Capture** | Interactive input, clipboard paste, hidden input, file import |
| **Comprehensive Validation** | BIP39 wordlist, checksum (SHA256), entropy, word count |
| **Wallet Detection** | 15+ wallets: BTC, ETH, SOL, LTC, DOGE, XRP, ADA, AVAX, … |
| **Derivation Paths** | BIP44/49/84 paths per wallet type |
| **Seed Phrase Analysis** | Entropy extraction, word indices, security level |
| **Multiple Export Formats** | Console, JSON, CSV, HTML reports |
| **Secure Storage** | Plaintext or Fernet-encrypted local storage |
| **Password Protection** | PBKDF2-HMAC-SHA256 key derivation |
| **Audit Logging** | Timestamped audit trail for every operation |
| **Secure Memory Clearing** | Best-effort overwrite of sensitive data in memory |
| **Termux Compatibility** | `termux-clipboard-get/set` integration |

---

## Installation

### Termux (Android)

```bash
pkg update && pkg upgrade
pkg install python git
pip install -r requirements.txt
```

### Linux / macOS / Windows

```bash
git clone https://github.com/AKILO22/Twt_seeds.git
cd Twt_seeds
pip install -r requirements.txt
```

---

## Usage

### Generate a seed phrase

```bash
python cli.py generate --count 1 --entropy 128
python cli.py generate --count 5 --entropy 256 --format json --save
```

### Validate a seed phrase

```bash
python cli.py validate "word1 word2 word3 ... word12"
```

### Capture an existing seed phrase

```bash
# Interactive prompt
python cli.py capture --source interactive

# Paste from clipboard (clears clipboard afterwards)
python cli.py capture --source clipboard

# Hidden input (no echo)
python cli.py capture --source hidden

# Import from file (one phrase per line)
python cli.py capture --source file --file phrases.txt

# Capture + validate + analyze + save (encrypted)
python cli.py capture --source interactive --analyze --save --encrypt

# Batch interactive capture
python cli.py capture --source interactive --batch

# Mask sensitive output
python cli.py capture --source clipboard --mask
```

### Analyze a seed phrase

```bash
# Console report
python cli.py analyze "word1 word2 ... word12"

# Console report with wallet list
python cli.py analyze "word1 ... word12" --wallets

# JSON output
python cli.py analyze "word1 ... word12" --format json --output report.json

# CSV output
python cli.py analyze "word1 ... word12" --format csv

# HTML report
python cli.py analyze "word1 ... word12" --format html --output report.html

# Analyze all phrases in a file
python cli.py analyze --file phrases.txt --format html
```

### Detect compatible wallets

```bash
python cli.py wallets "word1 word2 ... word12"
```

### Manage stored data

```bash
# List stored phrases
python cli.py manage --action list

# Show statistics
python cli.py manage --action stats

# Export to JSON
python cli.py manage --action export-json --output my_export.json

# Export to CSV
python cli.py manage --action export-csv

# Purge all stored data (irreversible)
python cli.py manage --action purge

# Manage encrypted storage
python cli.py manage --action list --encrypt
```

---

## Project Structure

```
Twt_seeds/
├── cli.py              # CLI entry point (all commands)
├── seed_generator.py   # BIP39 seed phrase generation
├── bip39_validator.py  # BIP39 wordlist & checksum validation
├── capture.py          # Seed phrase capture (input/clipboard/file)
├── analyzer.py         # Entropy analysis and report export
├── wallet_detector.py  # Wallet type detection & derivation paths
├── data_manager.py     # Storage, encryption, audit logging, export
├── security.py         # Password protection & secure memory clearing
├── config.py           # Configuration settings
├── test_generator.py   # Test suite
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── SECURITY.md         # Security documentation
```

---

## Configuration (`config.py`)

| Setting | Default | Description |
|---|---|---|
| `ENABLE_ENCRYPTION` | `False` | Encrypt stored phrases |
| `MASK_SENSITIVE_OUTPUT` | `False` | Mask phrases in console output |
| `CLEAR_CLIPBOARD_AFTER_PASTE` | `True` | Auto-clear clipboard after capture |
| `PBKDF2_ITERATIONS` | `480000` | Key derivation iterations |
| `DATA_DIR` | `data/` | Storage directory |
| `OUTPUT_DIR` | `output/` | Export directory |

---

## Running Tests

```bash
python -m pytest test_generator.py -v
```

---

## Security

See [SECURITY.md](SECURITY.md) for full security documentation.

**Quick reminders:**
- Never share seed phrases with anyone
- Never enter seed phrases on websites or untrusted applications
- Keep backups in a physically secure, offline location
- Clear clipboard after pasting seed phrases
- Encrypted storage is strongly recommended for persistent data

