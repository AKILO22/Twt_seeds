#!/usr/bin/env python3
"""
Command Line Interface for Seed Phrase Tool
Provides generate, validate, capture, analyze, and manage commands
"""

import getpass
import json
import os
import sys
from datetime import datetime

import click
from colorama import init as colorama_init, Fore, Style

from seed_generator import SeedPhraseGenerator
from capture import SeedPhraseCapture
from analyzer import SeedPhraseAnalyzer
from wallet_detector import WalletDetector
from data_manager import DataManager
from security import SecurityManager
from config import (
    ENTROPY_OPTIONS, OUTPUT_DIR, DATA_DIR,
    ENABLE_ENCRYPTION, MASK_SENSITIVE_OUTPUT
)

colorama_init(autoreset=True)


@click.group()
def cli():
    """🌱 BIP39 Seed Phrase Tool for Termux — generate, validate, analyze"""
    pass


# ---------------------------------------------------------------------------
# generate command (existing, preserved)
# ---------------------------------------------------------------------------

@cli.command()
@click.option('--count', '-c', default=1, help='Number of phrases to generate', type=int)
@click.option('--entropy', '-e', default=128, help='Entropy bits (128, 160, 192, 256)', type=int)
@click.option('--format', '-f', default='text',
              type=click.Choice(['json', 'csv', 'text', 'console']),
              help='Output format')
@click.option('--output', '-o', default=None, help='Output filename')
@click.option('--save', '-s', is_flag=True, help='Save to file')
def generate(count, entropy, format, output, save):
    """Generate BIP39 seed phrases"""

    click.echo(f"\n🌱 Generating {count} seed phrase(s) with {entropy}-bit entropy...\n")

    try:
        generator = SeedPhraseGenerator()
        results = generator.generate_multiple(count, entropy)

        if format == 'console':
            _display_console(results)
        elif format == 'json':
            _display_json(results)

        if save:
            if format == 'json':
                filepath = generator.save_to_json(results, output)
                click.secho(f"✅ Saved to JSON: {filepath}", fg='green')
            elif format == 'csv':
                filepath = generator.save_to_csv(results, output)
                click.secho(f"✅ Saved to CSV: {filepath}", fg='green')
            else:
                filepath = generator.save_to_txt(results, output)
                click.secho(f"✅ Saved to TXT: {filepath}", fg='green')

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg='red')


# ---------------------------------------------------------------------------
# validate command (existing, preserved)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument('phrase')
def validate(phrase):
    """Validate a seed phrase"""

    click.echo("\n🔍 Validating seed phrase...\n")

    try:
        generator = SeedPhraseGenerator()
        is_valid, message = generator.validate_seed_phrase(phrase)

        if is_valid:
            click.secho(f"✅ {message}", fg='green')
        else:
            click.secho(f"❌ {message}", fg='red')

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg='red')


# ---------------------------------------------------------------------------
# capture command
# ---------------------------------------------------------------------------

@cli.command()
@click.option('--source', '-s',
              type=click.Choice(['interactive', 'clipboard', 'file', 'hidden']),
              default='interactive', help='Input source')
@click.option('--file', '-f', 'filepath', default=None,
              help='Input file path (required for --source=file)')
@click.option('--batch', '-b', is_flag=True,
              help='Capture multiple phrases interactively')
@click.option('--count', '-c', default=None, type=int,
              help='Number of phrases for batch capture')
@click.option('--analyze', '-a', is_flag=True,
              help='Run analysis after capture')
@click.option('--save', is_flag=True,
              help='Save captured phrases to storage')
@click.option('--encrypt', is_flag=True,
              help='Encrypt stored data with a password')
@click.option('--mask', '-m', is_flag=True, default=MASK_SENSITIVE_OUTPUT,
              help='Mask sensitive output')
@click.option('--clear-clipboard', is_flag=True, default=True,
              help='Clear clipboard after paste (default: true)')
def capture(source, filepath, batch, count, analyze, save, encrypt, mask,
            clear_clipboard):
    """Capture and validate existing seed phrases"""

    SecurityManager.print_security_warning()

    capturer = SeedPhraseCapture(mask_output=mask)
    generator = SeedPhraseGenerator()
    phrases = []

    try:
        if source == 'clipboard':
            click.echo("📋 Reading from clipboard...")
            content = capturer.capture_from_clipboard()
            if not content:
                click.secho("❌ Clipboard is empty or unavailable", fg='red')
                sys.exit(1)
            phrases = [content]
            if clear_clipboard:
                capturer.clear_clipboard()
                click.secho("🗑️  Clipboard cleared", fg='yellow')

        elif source == 'file':
            if not filepath:
                click.secho("❌ --file is required for --source=file", fg='red')
                sys.exit(1)
            click.echo(f"📂 Reading from file: {filepath}")
            phrases = capturer.capture_from_file(filepath)
            click.echo(f"   Found {len(phrases)} phrase(s)")

        elif source == 'hidden':
            if batch:
                click.echo("🔐 Hidden batch capture (type blank line to finish):")
                phrases = []
                index = 1
                while True:
                    p = getpass.getpass(f"Phrase #{index} (blank to finish): ").strip().lower()
                    if not p:
                        break
                    phrases.append(capturer.sanitize_phrase(p))
                    index += 1
            else:
                p = capturer.capture_hidden()
                phrases = [capturer.sanitize_phrase(p)]

        else:  # interactive
            if batch:
                phrases = capturer.capture_batch_interactive(count)
            else:
                p = capturer.capture_interactive("📝 Enter seed phrase: ")
                phrases = [capturer.sanitize_phrase(p)]

        if not phrases:
            click.secho("❌ No phrases captured", fg='red')
            sys.exit(1)

        # Validate each phrase
        records = []
        for i, phrase in enumerate(phrases, 1):
            is_valid, message = generator.validate_seed_phrase(phrase)
            record = {
                "index": i,
                "phrase": phrase,
                "word_count": len(phrase.split()),
                "is_valid": is_valid,
                "validation_message": message,
                "timestamp": datetime.now().isoformat(),
                "source": source,
            }
            records.append(record)

            status = click.style("✅ Valid", fg='green') if is_valid else click.style("❌ Invalid", fg='red')
            phrase_display = phrase if not mask else capturer.mask_phrase(phrase)
            click.echo(f"\nPhrase #{i}: {phrase_display}")
            click.echo(f"  Status : {status}")
            click.echo(f"  Words  : {record['word_count']}")
            click.echo(f"  Message: {message}")

        if analyze:
            click.echo("\n")
            _run_analysis(phrases, mask)

        if save:
            dm = DataManager(DATA_DIR, enable_encryption=encrypt)
            password = None
            if encrypt:
                sm = SecurityManager()
                password = sm.prompt_password("Set storage password: ", confirm=True)
            dm.save_phrases(records, password)
            click.secho(f"\n✅ {len(records)} phrase(s) saved to storage", fg='green')

    except (KeyboardInterrupt, EOFError):
        click.secho("\n⚠️  Capture cancelled", fg='yellow')
    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg='red')


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument('phrase', required=False)
@click.option('--file', '-f', 'filepath', default=None,
              help='Input file with seed phrases (one per line)')
@click.option('--format', '-o',
              type=click.Choice(['console', 'json', 'csv', 'html']),
              default='console', help='Output format')
@click.option('--output', default=None, help='Output file path')
@click.option('--mask', '-m', is_flag=True, default=MASK_SENSITIVE_OUTPUT,
              help='Mask sensitive data in output')
@click.option('--wallets', '-w', is_flag=True,
              help='Show compatible wallets')
def analyze(phrase, filepath, format, output, mask, wallets):
    """Analyze seed phrase(s): entropy, indices, checksums"""

    analyzer = SeedPhraseAnalyzer()
    detector = WalletDetector()
    phrases = []

    try:
        if filepath:
            capturer = SeedPhraseCapture()
            phrases = capturer.capture_from_file(filepath)
        elif phrase:
            phrases = [phrase.strip().lower()]
        else:
            click.secho("❌ Provide a phrase argument or --file", fg='red')
            sys.exit(1)

        results = [analyzer.analyze(p) for p in phrases]

        if format == 'console':
            for r in results:
                analyzer.display_analysis(r, mask=mask)
                if wallets and r["is_valid"]:
                    _show_wallets(r["phrase"], detector)
        elif format == 'json':
            out = output or os.path.join(OUTPUT_DIR, "analysis.json")
            path = analyzer.export_json(results, out)
            click.secho(f"✅ JSON report saved: {path}", fg='green')
        elif format == 'csv':
            out = output or os.path.join(OUTPUT_DIR, "analysis.csv")
            path = analyzer.export_csv(results, out)
            click.secho(f"✅ CSV report saved: {path}", fg='green')
        elif format == 'html':
            out = output or os.path.join(OUTPUT_DIR, "analysis.html")
            path = analyzer.export_html(results, out, mask=mask)
            click.secho(f"✅ HTML report saved: {path}", fg='green')

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg='red')


# ---------------------------------------------------------------------------
# manage command
# ---------------------------------------------------------------------------

@cli.command()
@click.option('--action',
              type=click.Choice(['list', 'export-json', 'export-csv', 'purge', 'stats']),
              default='list', help='Management action')
@click.option('--output', '-o', default=None, help='Output file for export')
@click.option('--encrypt', is_flag=True, help='Use encrypted storage')
def manage(action, output, encrypt):
    """Manage stored seed phrase data"""

    dm = DataManager(DATA_DIR, enable_encryption=encrypt)
    password = None

    try:
        if encrypt:
            sm = SecurityManager()
            password = sm.prompt_password("Storage password: ")

        if action == 'purge':
            click.confirm(
                "⚠️  This will permanently delete ALL stored phrases. Continue?",
                abort=True
            )
            dm.delete_all()
            click.secho("✅ All stored data purged", fg='green')
            return

        phrases = dm.load_phrases(password)

        if action == 'list':
            if not phrases:
                click.echo("No stored phrases found.")
                return
            for i, p in enumerate(phrases, 1):
                phrase_display = p.get("phrase", "")[:30] + "..."
                click.echo(
                    f"#{i} | Words: {p.get('word_count')} | "
                    f"Valid: {p.get('is_valid')} | {phrase_display}"
                )

        elif action == 'stats':
            stats = dm.get_stats(phrases)
            click.echo(json.dumps(stats, indent=2))

        elif action == 'export-json':
            out = output or os.path.join(OUTPUT_DIR, "export.json")
            path = dm.export_json(phrases, out)
            click.secho(f"✅ Exported to JSON: {path}", fg='green')

        elif action == 'export-csv':
            out = output or os.path.join(OUTPUT_DIR, "export.csv")
            path = dm.export_csv(phrases, out)
            click.secho(f"✅ Exported to CSV: {path}", fg='green')

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg='red')


# ---------------------------------------------------------------------------
# wallets command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument('phrase')
def wallets(phrase):
    """Show compatible wallets and derivation paths for a seed phrase"""

    generator = SeedPhraseGenerator()
    detector = WalletDetector()

    is_valid, msg = generator.validate_seed_phrase(phrase.strip().lower())
    if not is_valid:
        click.secho(f"❌ Invalid phrase: {msg}", fg='red')
        sys.exit(1)

    _show_wallets(phrase.strip().lower(), detector)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _display_console(results):
    for item in results:
        click.echo(f"Seed #{item['index']}")
        click.echo(f"Phrase: {item['phrase']}")
        click.echo(f"Words: {item['word_count']}")
        click.echo(f"Valid: {'✓' if item['valid'] else '✗'}")
        click.echo(f"Time: {item['timestamp']}")
        click.echo("-" * 80)


def _display_json(results):
    click.echo(json.dumps(results, indent=2))


def _run_analysis(phrases, mask=False):
    analyzer = SeedPhraseAnalyzer()
    for phrase in phrases:
        result = analyzer.analyze(phrase)
        analyzer.display_analysis(result, mask=mask)


def _show_wallets(phrase, detector: WalletDetector):
    word_count = len(phrase.split())
    sec = detector.get_security_level(word_count)
    compatible = detector.detect_compatible_wallets(phrase)

    click.echo(f"\n{'=' * 60}")
    click.echo(f"  Security Level : {sec['level']} (rating {sec['rating']}/5)")
    click.echo(f"  Entropy        : {sec['entropy_bits']} bits")
    click.echo(f"  Description    : {sec['description']}")
    click.echo(f"{'=' * 60}")
    click.echo(f"  Compatible Wallets ({len(compatible)} found):")
    click.echo(f"  {'-' * 55}")
    for w in compatible:
        click.echo(f"  • {w['wallet']:<35} {w['derivation_path']}")
    click.echo(f"{'=' * 60}\n")


if __name__ == '__main__':
    cli()
