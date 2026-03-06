#!/usr/bin/env python3
"""
Configuration for Seed Phrase Tool and Email Monitor Tool
"""

# ---------------------------------------------------------------------------
# Email Monitor Configuration
# ---------------------------------------------------------------------------

# Default directories for email tool
EMAIL_DATA_DIR = 'email_data'
EMAIL_OUTPUT_DIR = 'output'
EMAIL_TOKEN_DIR = 'email_tokens'

# Fetch settings
EMAIL_DEFAULT_MAX_RESULTS = 10

# SMTP verification
SMTP_TIMEOUT = 10              # Seconds for SMTP connection timeout
SKIP_SMTP_VERIFICATION = False  # Set True to skip SMTP checks (faster, less accurate)

# Security / Privacy
EMAIL_MASK_SENDERS = False     # Mask sender addresses in console output

# ---------------------------------------------------------------------------
# Seed Phrase Tool Configuration (preserved)
# ---------------------------------------------------------------------------

# Entropy options (bits -> words)
ENTROPY_OPTIONS = {
    128: {
        'bits': 128,
        'words': 12,
        'description': 'Standard security (12 words)'
    },
    160: {
        'bits': 160,
        'words': 15,
        'description': 'High security (15 words)'
    },
    192: {
        'bits': 192,
        'words': 18,
        'description': 'Very high security (18 words)'
    },
    256: {
        'bits': 256,
        'words': 24,
        'description': 'Maximum security (24 words)'
    }
}

# Output settings
OUTPUT_DIR = 'output'
DEFAULT_FORMAT = 'text'

# Data storage
DATA_DIR = 'data'
ENABLE_ENCRYPTION = False  # Set True to encrypt stored phrases

# Logging
LOG_LEVEL = 'INFO'
LOG_FILE = 'seed_generator.log'

# Security
USE_SECURE_RANDOM = True
REQUIRE_VALIDATION = True
MASK_SENSITIVE_OUTPUT = False   # Set True to mask phrases in console output
CLEAR_CLIPBOARD_AFTER_PASTE = True  # Auto-clear clipboard after capture

# Analysis / Export
DEFAULT_EXPORT_DIR = 'output'
PBKDF2_ITERATIONS = 480000      # PBKDF2 iterations for key derivation
