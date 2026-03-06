# Security Documentation

## Overview

This tool handles extremely sensitive cryptographic material (BIP39 seed phrases). Seed phrases provide **complete, irrevocable access** to all funds in a cryptocurrency wallet. Loss or exposure of a seed phrase means permanent loss of all associated assets.

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Shoulder surfing | `--mask` flag hides phrases in console output |
| Clipboard sniffing | Clipboard is cleared automatically after paste |
| Unauthorized file access | Optional Fernet encryption for stored data |
| Brute-force password attack | PBKDF2-HMAC-SHA256 with 480,000 iterations |
| Memory forensics | Best-effort in-memory zeroing via `ctypes.memset` |
| Log leakage | Audit log records actions only — never phrase content |
| Accidental screen recording | `--mask` and `--source hidden` options |

---

## Encryption

When `--encrypt` is used or `ENABLE_ENCRYPTION = True` in `config.py`:

- A random 32-byte salt is generated using `secrets.token_bytes(32)`
- An encryption key is derived from the password using PBKDF2-HMAC-SHA256 with 480,000 iterations
- Data is encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256)
- The derived key is never stored; only the salt is persisted alongside the ciphertext
- Encrypting with a wrong password raises an exception, preventing silent data corruption

### Files written to disk (encrypted mode)

| File | Contents |
|---|---|
| `data/phrases.enc` | Fernet-encrypted JSON payload |
| `data/salt.bin` | Random 32-byte salt (not secret) |
| `data/audit.log` | Action log (no phrase content) |

---

## Password Security

- Passwords are never stored
- `getpass.getpass()` is used for all password prompts (no terminal echo)
- PBKDF2-HMAC-SHA256 with 480,000 iterations aligns with NIST SP 800-132 guidance
- Fernet authentication tag verification means a wrong password raises `cryptography.fernet.InvalidToken` before any data is returned

---

## Memory Handling

Python's garbage collector does not guarantee immediate object destruction. The `SecurityManager.secure_clear()` method overwrites a `bytearray` buffer with zeros using `ctypes.memset` before releasing the reference. This is a **best-effort** mitigation; Python string interning and garbage collection timing may still leave residual copies.

**Best practices:**
- Use `bytearray` instead of `str` when handling sensitive data in your own extensions
- Run the tool on a device with full-disk encryption enabled

---

## Clipboard Security

- After capturing a seed phrase from the clipboard, the tool optionally clears it
- On Termux: uses `termux-clipboard-set ""`
- On desktop Linux: uses `xclip` or `xsel`
- Cross-platform fallback: `pyperclip.copy("")`
- Auto-clear is enabled by default (`CLEAR_CLIPBOARD_AFTER_PASTE = True`)

---

## Audit Logging

All operations are logged to `data/audit.log`:

```
2026-03-06 10:00:00,000 [INFO] SAVE_ENCRYPTED | Saved 2 phrase(s) (encrypted)
2026-03-06 10:00:01,000 [INFO] LOAD_ENCRYPTED | Loaded encrypted phrases
2026-03-06 10:00:02,000 [INFO] EXPORT_JSON | Exported 2 phrase(s) to output/export.json
```

**Audit log entries never contain seed phrase content.**

---

## Operational Security Recommendations

1. **Use encrypted storage** — enable `--encrypt` for any saved data
2. **Use a strong, unique password** — at least 16 characters
3. **Run on an air-gapped device** when analysing real wallets
4. **Delete exports immediately** after use; prefer encrypted storage over plaintext exports
5. **Enable full-disk encryption** on your device (Android default since Android 6.0)
6. **Use `--mask`** when running in a shared environment
7. **Purge stored data** when no longer needed: `python cli.py manage --action purge`
8. **Never photograph or screenshot** phrases displayed in the terminal

---

## Dependency Security

| Package | Purpose | Advisory Check |
|---|---|---|
| `cryptography` | Fernet encryption, PBKDF2 | ✅ Well-maintained, FIPS-tested backends |
| `mnemonic` | BIP39 wordlist and derivation | ✅ Reference implementation by Trezor |
| `click` | CLI framework | ✅ Widely used, actively maintained |
| `colorama` | Terminal colours | ✅ Minimal, no crypto relevance |
| `pyperclip` | Clipboard access | ✅ No sensitive data persisted |

---

## Reporting Vulnerabilities

If you discover a security vulnerability in this tool, please open a GitHub Issue marked **[SECURITY]** or contact the repository owner directly. Do **not** include real seed phrases in any bug report.
