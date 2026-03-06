# 🌱 Twt_seeds — BIP39 Seed Phrase Tool + 📧 Email Monitor for Termux

A comprehensive Python toolset for Termux (Android) and desktop use, providing:
1. **BIP39 Seed Phrase Tool** — generate, validate, and analyze wallet seed phrases
2. **Email Monitor Tool** — monitor inboxes, verify email addresses, and analyze headers

---

## 📧 Email Monitor Tool

### Features

| Feature | Details |
|---|---|
| **Gmail Integration** | OAuth2 authentication, fetch last N emails, unread tracking |
| **Outlook/Microsoft 365** | OAuth2 via device code flow (Termux compatible), Graph API |
| **Generic IMAP** | Any IMAP provider, SSL/TLS, auto-server detection |
| **Email Verification** | RFC 5322 format, DNS/MX lookup, SMTP RCPT TO, disposable detection |
| **Header Analysis** | Parse SPF/DKIM/DMARC, routing hops, security risk scoring |
| **Phishing Detection** | Keyword matching, suspicious URL/TLD detection, spoofing analysis |
| **Multiple Exports** | Console, JSON, CSV, HTML reports |
| **Audit Logging** | Timestamped activity logs |
| **Secure Credentials** | OAuth2 tokens only — no plaintext passwords stored |
| **Termux Compatible** | Device code OAuth2 flow, mobile-optimized display |

### Quick Start

```bash
# Verify an email address
python email_cli.py verify user@example.com

# Monitor Gmail inbox (requires OAuth2 setup — see below)
python email_cli.py monitor gmail --credentials credentials.json --count 10

# Monitor Outlook inbox (requires Azure AD app — see below)
python email_cli.py monitor outlook --client-id YOUR_CLIENT_ID

# Monitor any IMAP inbox (auto-detects server from email domain)
python email_cli.py monitor imap --email user@yahoo.com

# Analyze a raw email for security issues
python email_cli.py analyze --file suspicious_email.eml
```

### Installation

#### Termux (Android)

```bash
pkg update && pkg upgrade
pkg install python git
pip install -r requirements.txt
```

#### Linux / macOS / Windows

```bash
git clone https://github.com/AKILO22/Twt_seeds.git
cd Twt_seeds
pip install -r requirements.txt
```

### Email Tool Commands

#### Monitor — Gmail

```bash
# Fetch last 10 emails from Gmail
python email_cli.py monitor gmail --credentials credentials.json

# Fetch only unread emails, show 20, save to storage
python email_cli.py monitor gmail --credentials credentials.json \
    --count 20 --unread --save

# Export to HTML report
python email_cli.py monitor gmail --credentials credentials.json \
    --format html --output inbox_report.html

# Multiple accounts
python email_cli.py monitor gmail --credentials creds_work.json --account work
python email_cli.py monitor gmail --credentials creds_personal.json --account personal
```

#### Monitor — Outlook

```bash
# Fetch last 10 emails from Outlook (device code flow)
python email_cli.py monitor outlook --client-id YOUR_AZURE_APP_ID

# Fetch unread, export to JSON
python email_cli.py monitor outlook --client-id YOUR_AZURE_APP_ID \
    --unread --format json --output outlook.json
```

#### Monitor — IMAP (Any Provider)

```bash
# Auto-detect server from email address (prompts for password)
python email_cli.py monitor imap --email user@yahoo.com

# Explicit server settings
python email_cli.py monitor imap --host imap.example.com --port 993 \
    --email user@example.com

# Fetch from a specific folder, unread only
python email_cli.py monitor imap --email user@icloud.com \
    --folder "Sent" --unread --count 5
```

#### Verify Email Addresses

```bash
# Verify a single address
python email_cli.py verify user@example.com

# Verify multiple addresses
python email_cli.py verify addr1@a.com addr2@b.com addr3@c.com

# Skip SMTP check (DNS only, faster)
python email_cli.py verify user@example.com --skip-smtp

# Export verification report as HTML
python email_cli.py verify user@example.com addr2@b.com \
    --format html --output verification_report.html

# Save results to local storage
python email_cli.py verify user@example.com --save
```

#### Analyze Email Headers

```bash
# Analyze a .eml file
python email_cli.py analyze --file suspicious_email.eml

# Read from stdin
cat suspicious_email.eml | python email_cli.py analyze --stdin

# Export HTML security report
python email_cli.py analyze --file email.eml --format html --output header_report.html

# Export JSON for further processing
python email_cli.py analyze --file email.eml --format json
```

#### Manage Stored Data

```bash
# Show statistics
python email_cli.py manage --action stats

# Export email history to JSON
python email_cli.py manage --action export-emails-json

# Export email history to CSV
python email_cli.py manage --action export-emails-csv

# Export verification results
python email_cli.py manage --action export-verifications

# Purge all stored data
python email_cli.py manage --action purge
```

### OAuth2 Setup

#### Gmail Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Gmail API**
4. Go to **Credentials → Create Credentials → OAuth 2.0 Client IDs**
5. Choose **Desktop App** as the application type
6. Download the credentials JSON file (save as `credentials.json`)
7. Run:

```bash
python email_cli.py monitor gmail --credentials credentials.json
```

A browser window will open for one-time authorization. Tokens are saved in `email_tokens/`.

#### Outlook / Microsoft 365 Setup

1. Go to [Azure Portal → App Registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps)
2. Click **New Registration**
3. Name: any name, Supported account types: **Personal Microsoft accounts**
4. Under **Authentication**, add a **Mobile and desktop application** platform with redirect URI `https://login.microsoftonline.com/common/oauth2/nativeclient`
5. Copy the **Application (client) ID**
6. Run:

```bash
python email_cli.py monitor outlook --client-id YOUR_CLIENT_ID
```

Follow the device code instructions printed to the terminal. No browser required — works in Termux.

### Email Tool — Project Structure

```
email_monitor.py       # Main monitoring orchestrator
email_verifier.py      # Email address verification (format, DNS, SMTP)
header_analyzer.py     # Email header + security analysis
gmail_auth.py          # Gmail OAuth2 authentication handler
outlook_auth.py        # Outlook OAuth2 (MSAL) authentication handler
imap_handler.py        # Generic IMAP handler (any provider)
domain_checker.py      # DNS/MX/SPF/DKIM/DMARC/SMTP verification
email_data_manager.py  # Data storage, export, audit logging
email_reporter.py      # Report generation (JSON, CSV, HTML)
email_cli.py           # CLI entry point for email tool
EMAIL_SECURITY.md      # Security documentation
```

---

## 🌱 Seed Phrase Tool (Original)

### Features

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

### Usage

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

