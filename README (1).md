# BIP39 Seed Phrase Generator

A powerful Termux-compatible tool for generating, validating, and managing BIP39 seed phrases with enterprise-grade security.

## Features

✅ **Multiple Entropy Levels**: 12, 15, 18, or 24-word phrases
✅ **BIP39 Compliant**: Full validation against official wordlist
✅ **Checksum Validation**: SHA256-based entropy integrity
✅ **Multiple Formats**: JSON, CSV, Plain Text output
✅ **File Output**: Timestamped saves with organized structure
✅ **Termux Ready**: Seamless Termux integration
✅ **Secure**: Uses Python `secrets` module for cryptographic randomness

## Installation

### Prerequisites
- Python 3.7+
- pip

### Setup

```bash
# Clone or download the repository
cd Twt_seeds

# Install dependencies
pip install -r requirements.txt

# Make CLI executable
chmod +x cli.py
```

## Usage

### Generate Seed Phrases

```bash
# Generate single 12-word phrase
python cli.py generate

# Generate 5 phrases with 12 words each
python cli.py generate --count 5

# Generate 3 phrases with 24 words each
python cli.py generate --count 3 --entropy 256

# Save to JSON file
python cli.py generate --count 10 --format json --save

# Save to CSV file
python cli.py generate --count 5 --format csv --save --output my_seeds.csv
```

### Validate Seed Phrase

```bash
python cli.py validate "abandon ability able about above absent absolute absorb abstract abuse access accident account achieve acid acoustic acquire across act action actress actual"
```

## Entropy Levels

| Entropy | Words | Security Level |
|---------|-------|-----------------|
| 128-bit | 12    | Standard        |
| 160-bit | 15    | High            |
| 192-bit | 18    | Very High       |
| 256-bit | 24    | Maximum         |

## Output Formats

### Console
Direct terminal output with formatted display

### JSON
```json
[
  {
    "index": 1,
    "phrase": "word1 word2 word3 ...",
    "entropy": "abc123...",
    "word_count": 12,
    "entropy_bits": 128,
    "valid": true,
    "timestamp": "2026-03-06T10:30:45.123456",
    "validation_message": "Valid BIP39 seed phrase"
  }
]
```

### CSV
Spreadsheet-compatible comma-separated format

### TXT
Human-readable plain text format

## Security Notes

⚠️ **IMPORTANT**: Seed phrases provide complete access to cryptocurrency wallets

- Never share your seed phrases with anyone
- Store seed phrases securely (offline, encrypted)
- Never store in plain text on internet-connected devices
- Use this tool only for testing and legitimate purposes
- Consider airgapping generation device for critical wallets

## Testing

```bash
# Run tests
python -m pytest test_generator.py -v
```

## Troubleshooting

### Module not found error
```bash
pip install --upgrade -r requirements.txt
```

### Permission denied
```bash
chmod +x cli.py
```

### Termux-specific issues
```bash
# Install Python development files
pkg install python-dev

# Reinstall dependencies
pip install --upgrade --force-reinstall -r requirements.txt
```

## Architecture

```
Twt_seeds/
├── cli.py                 # Command-line interface
├── seed_generator.py      # Main generator logic
├── bip39_validator.py     # Validation module
├── config.py              # Configuration
├── bip39_wordlist.txt     # Official wordlist
├── test_generator.py      # Unit tests
├── requirements.txt       # Dependencies
├── README.md              # This file
└── output/                # Generated output files
```

## License

MIT License - Use responsibly

## Disclaimer

This tool is provided for educational and testing purposes. Users are responsible for secure storage and handling of seed phrases. The developers assume no liability for lost funds or misuse.