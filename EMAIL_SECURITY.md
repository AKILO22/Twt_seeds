# Email Monitor Tool — Security Documentation

## Overview

This document describes the security model, design decisions, and best practices for the Email Monitor Tool included in this repository.

---

## Credential Storage

### OAuth2 Tokens (Gmail / Outlook)

- Tokens are stored in the `email_tokens/` directory
- Gmail tokens: `email_tokens/gmail_token_<account>.json`
- Outlook tokens: `email_tokens/outlook_token_<account>.bin`
- **No plaintext passwords are ever stored**
- OAuth2 access tokens have limited scope (`readonly` for Gmail, `Mail.Read` for Outlook)
- Refresh tokens allow silent renewal without re-authentication

**Recommendation:** Set restrictive file system permissions on the `email_tokens/` directory:
```bash
chmod 700 email_tokens/
chmod 600 email_tokens/*.json email_tokens/*.bin
```

### IMAP Passwords

- IMAP passwords are **never stored** by default
- They are passed at connection time and held in memory only for the duration of the session
- Use app-specific passwords (not your main account password) for IMAP access
- Enable 2FA on your email accounts

---

## OAuth2 Security

### Gmail

1. Only `gmail.readonly` and `gmail.metadata` scopes are requested — **no write access**
2. OAuth2 credentials (client ID / secret) must be obtained from Google Cloud Console
3. Never commit `credentials.json` to version control — add it to `.gitignore`
4. Tokens are refreshed automatically and saved locally

### Outlook / Microsoft 365

1. Only `Mail.Read` and `User.Read` scopes are requested — **no write access**
2. Device code flow is used — no browser redirect required (Termux compatible)
3. Token caches are stored using MSAL's `SerializableTokenCache`
4. Client ID only (public client app) — no client secret stored

---

## Data at Rest

- Fetched emails are stored in `email_data/email_history.json` (plaintext JSON)
- Verification results are stored in `email_data/email_verifications.json`
- Audit logs are written to `email_data/email_audit.log`

**Recommendation:** If storing sensitive email content, consider encrypting the `email_data/` directory using OS-level encryption or a tool like `gpg`.

---

## Network Security

### SMTP Verification

- SMTP verification uses **read-only RCPT TO probing** — no emails are sent
- Connections time out after `SMTP_TIMEOUT` seconds (default: 10)
- Use `--skip-smtp` to avoid outbound SMTP connections if network access is restricted

### DNS Lookups

- DNS queries are made using `dnspython` for MX, SPF, DKIM, and DMARC records
- All DNS queries use the system resolver; consider a private DNS resolver for privacy

### IMAP Connections

- All IMAP connections use SSL/TLS by default (port 993)
- STARTTLS is supported as a fallback (`--no-ssl` is not recommended)
- Server certificates are verified using the default system CA bundle

---

## Phishing & Security Analysis

The `HeaderAnalyzer` performs best-effort heuristic analysis:

- **Phishing keywords** are matched against a static list — this is not exhaustive
- **Suspicious TLDs** are matched against a known list — new TLDs may be missed
- **SMTP spoofing detection** relies on `Authentication-Results` headers set by the receiving server — these can be absent or incorrect
- **This tool is for informational purposes only** — it does not replace a dedicated email security gateway

---

## Sensitive Data Masking

Use the `--mask` flag to mask sender email addresses in console output:
```bash
python email_cli.py monitor imap --mask ...
```

Masking is applied to local-part characters only (e.g., `jo***n@example.com`).

---

## Audit Logging

All data operations are logged to `email_data/email_audit.log` with timestamps:
- Email fetch operations
- Verification saves
- Export operations
- Data purges

The audit log does **not** contain email content, passwords, or access tokens.

---

## Secrets and Files to Keep Private

| File / Directory | Contents | Risk |
|---|---|---|
| `email_tokens/*.json` | Gmail OAuth2 tokens | High — treat like passwords |
| `email_tokens/*.bin` | Outlook MSAL token cache | High — treat like passwords |
| `credentials.json` | Google OAuth2 client credentials | High — never commit to git |
| `email_data/` | Email history, verification results | Medium — may contain personal data |

Add these to your `.gitignore`:
```
credentials.json
email_tokens/
email_data/
```

---

## Responsible Use

- Only monitor email accounts you own or have explicit permission to monitor
- Do not use SMTP verification in bulk without the receiving server's permission — this may be considered abuse
- Respect rate limits of email providers
- Do not use this tool to harvest or scrape email addresses from others

---

## Reporting Security Issues

If you discover a security vulnerability in this tool, please open a GitHub issue or contact the repository maintainer privately.
