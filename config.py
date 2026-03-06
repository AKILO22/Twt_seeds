#!/usr/bin/env python3
"""
Configuration for Seed Phrase Generator
"""

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

# Logging
LOG_LEVEL = 'INFO'
LOG_FILE = 'seed_generator.log'

# Security
USE_SECURE_RANDOM = True
REQUIRE_VALIDATION = True
