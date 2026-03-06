#!/usr/bin/env python3
"""
Email Tool CLI
Command-line interface for email monitoring, verification, and header analysis.
Optimized for Termux (Android) and desktop use.
"""

import json
import sys
from pathlib import Path

import click
from colorama import Fore, Style, init as colorama_init

from email_monitor import EmailMonitor
from email_verifier import EmailVerifier
from header_analyzer import HeaderAnalyzer
from email_data_manager import EmailDataManager
from email_reporter import EmailReporter

colorama_init(autoreset=True)

# Default directories
DATA_DIR = "email_data"
OUTPUT_DIR = "output"


# ---------------------------------------------------------------------------
# CLI Group
# ---------------------------------------------------------------------------

@click.group()
def email_cli():
    """📧 Email Monitor & Verifier Tool for Termux

    \b
    Commands:
      monitor  - Monitor Gmail, Outlook, or IMAP accounts
      verify   - Verify email address deliverability
      analyze  - Analyze email headers for security
      manage   - Manage stored email data
    """


# ---------------------------------------------------------------------------
# monitor command
# ---------------------------------------------------------------------------

@email_cli.group()
def monitor():
    """Monitor email inboxes (Gmail, Outlook, IMAP)"""


@monitor.command('gmail')
@click.option('--credentials', '-c', required=True,
              help='Path to Google OAuth2 credentials JSON file')
@click.option('--account', '-a', default='default',
              help='Account name/identifier')
@click.option('--count', '-n', default=10, type=int,
              help='Number of emails to fetch (default: 10)')
@click.option('--unread', '-u', is_flag=True,
              help='Only show unread emails')
@click.option('--save', '-s', is_flag=True,
              help='Save emails to local storage')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['console', 'json', 'csv', 'html']),
              default='console', help='Output format')
@click.option('--output', '-o', default=None,
              help='Output file path (for non-console formats)')
@click.option('--mask', '-m', is_flag=True,
              help='Mask sender email addresses in output')
def monitor_gmail(credentials, account, count, unread, save, output_format, output, mask):
    """Fetch emails from a Gmail account via OAuth2"""
    click.secho("\n📧 Gmail Monitor", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    try:
        monitor_obj = EmailMonitor(data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
        click.echo(f"  Authenticating as '{account}'...")

        with click.progressbar(length=1, label='  Fetching emails') as bar:
            emails = monitor_obj.monitor_gmail(
                credentials_file=credentials,
                account_name=account,
                max_results=count,
                unread_only=unread,
                save=save,
            )
            bar.update(1)

        _output_emails(emails, output_format, output, account, mask)

        if save:
            click.secho(f"\n✅ {len(emails)} email(s) saved to local storage", fg='green')

    except Exception as e:
        click.secho(f"\n❌ Error: {e}", fg='red')
        sys.exit(1)


@monitor.command('outlook')
@click.option('--client-id', '-c', required=True,
              help='Azure AD application (client) ID')
@click.option('--account', '-a', default='default',
              help='Account name/identifier')
@click.option('--count', '-n', default=10, type=int,
              help='Number of emails to fetch (default: 10)')
@click.option('--unread', '-u', is_flag=True,
              help='Only show unread emails')
@click.option('--save', '-s', is_flag=True,
              help='Save emails to local storage')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['console', 'json', 'csv', 'html']),
              default='console', help='Output format')
@click.option('--output', '-o', default=None,
              help='Output file path (for non-console formats)')
@click.option('--mask', '-m', is_flag=True,
              help='Mask sender email addresses in output')
def monitor_outlook(client_id, account, count, unread, save, output_format, output, mask):
    """Fetch emails from an Outlook/Microsoft 365 account via OAuth2"""
    click.secho("\n📧 Outlook Monitor", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    try:
        monitor_obj = EmailMonitor(data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
        click.echo(f"  Authenticating as '{account}'...")

        emails = monitor_obj.monitor_outlook(
            client_id=client_id,
            account_name=account,
            max_results=count,
            unread_only=unread,
            save=save,
        )

        _output_emails(emails, output_format, output, account, mask)

        if save:
            click.secho(f"\n✅ {len(emails)} email(s) saved to local storage", fg='green')

    except Exception as e:
        click.secho(f"\n❌ Error: {e}", fg='red')
        sys.exit(1)


@monitor.command('imap')
@click.option('--host', '-H', default=None,
              help='IMAP server hostname (auto-detected if --email provided)')
@click.option('--port', '-p', default=993, type=int,
              help='IMAP server port (default: 993)')
@click.option('--email', '-e', default=None,
              help='Email address (used for auto-detection and login)')
@click.option('--username', '-u', default=None,
              help='IMAP username (defaults to --email if not provided)')
@click.option('--password', '-w', default=None,
              help='Password (prompted securely if not provided)')
@click.option('--folder', '-d', default='INBOX',
              help='Mailbox folder (default: INBOX)')
@click.option('--count', '-n', default=10, type=int,
              help='Number of emails to fetch (default: 10)')
@click.option('--unread', '-r', is_flag=True,
              help='Only show unread emails')
@click.option('--no-ssl', is_flag=True,
              help='Disable SSL (not recommended)')
@click.option('--save', '-s', is_flag=True,
              help='Save emails to local storage')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['console', 'json', 'csv', 'html']),
              default='console', help='Output format')
@click.option('--output', '-o', default=None,
              help='Output file path (for non-console formats)')
@click.option('--mask', '-m', is_flag=True,
              help='Mask sender email addresses in output')
def monitor_imap(host, port, email, username, password, folder, count, unread,
                 no_ssl, save, output_format, output, mask):
    """Fetch emails from a generic IMAP server"""
    click.secho("\n📧 IMAP Monitor", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    # Determine username
    login_user = username or email
    if not login_user:
        login_user = click.prompt("  Email/Username")

    # Prompt for password securely if not provided
    if not password:
        password = click.prompt("  Password", hide_input=True)

    try:
        monitor_obj = EmailMonitor(data_dir=DATA_DIR, output_dir=OUTPUT_DIR)

        if host:
            emails = monitor_obj.monitor_imap(
                host=host,
                username=login_user,
                password=password,
                port=port,
                folder=folder,
                max_results=count,
                unread_only=unread,
                use_ssl=not no_ssl,
                save=save,
            )
        else:
            if not email:
                email = login_user
            click.echo(f"  Auto-detecting IMAP server for '{email}'...")
            emails = monitor_obj.monitor_imap_auto(
                email_address=email,
                password=password,
                folder=folder,
                max_results=count,
                unread_only=unread,
                save=save,
            )

        _output_emails(emails, output_format, output, login_user, mask)

        if save:
            click.secho(f"\n✅ {len(emails)} email(s) saved to local storage", fg='green')

    except Exception as e:
        click.secho(f"\n❌ Error: {e}", fg='red')
        sys.exit(1)


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------

@email_cli.command()
@click.argument('email_address', nargs=-1, required=True)
@click.option('--skip-smtp', is_flag=True,
              help='Skip SMTP verification (faster, less accurate)')
@click.option('--timeout', '-t', default=10, type=int,
              help='SMTP connection timeout in seconds (default: 10)')
@click.option('--save', '-s', is_flag=True,
              help='Save verification results to local storage')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['console', 'json', 'html']),
              default='console', help='Output format')
@click.option('--output', '-o', default=None,
              help='Output file path (for non-console formats)')
def verify(email_address, skip_smtp, timeout, save, output_format, output):
    """Verify one or more email addresses

    \b
    Examples:
      python email_cli.py verify user@example.com
      python email_cli.py verify addr1@a.com addr2@b.com --format json
      python email_cli.py verify user@gmail.com --skip-smtp --save
    """
    click.secho("\n🔍 Email Verifier", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    verifier = EmailVerifier(smtp_timeout=timeout, skip_smtp=skip_smtp)
    dm = EmailDataManager(data_dir=DATA_DIR)
    reporter = EmailReporter(output_dir=OUTPUT_DIR)

    results = []
    for addr in email_address:
        click.echo(f"\n  Verifying: {addr}")
        result = verifier.verify(addr)
        results.append(result)

        if output_format == 'console':
            _display_verification(result)

        if save:
            dm.save_verification(result)

    if output_format == 'json':
        fp = reporter.report_verification_json(results, output)
        click.secho(f"\n✅ JSON report saved: {fp}", fg='green')
    elif output_format == 'html':
        fp = reporter.report_verification_html(results, output)
        click.secho(f"\n✅ HTML report saved: {fp}", fg='green')

    if save and output_format == 'console':
        click.secho(f"\n✅ {len(results)} result(s) saved to local storage", fg='green')


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@email_cli.command()
@click.option('--file', '-f', 'filepath', default=None,
              help='Path to raw email file (.eml or .txt)')
@click.option('--stdin', is_flag=True,
              help='Read raw email from stdin')
@click.option('--format', '-o', 'output_format',
              type=click.Choice(['console', 'json', 'html']),
              default='console', help='Output format')
@click.option('--output', default=None,
              help='Output file path (for non-console formats)')
def analyze(filepath, stdin, output_format, output):
    """Analyze email headers and metadata for security issues

    \b
    Examples:
      python email_cli.py analyze --file email.eml
      cat email.eml | python email_cli.py analyze --stdin
      python email_cli.py analyze --file email.eml --format html --output report.html
    """
    click.secho("\n🔎 Email Header Analyzer", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    if not filepath and not stdin:
        click.secho("❌ Provide --file or --stdin", fg='red')
        sys.exit(1)

    try:
        if stdin:
            raw_email = sys.stdin.read()
        else:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                raw_email = f.read()
    except Exception as e:
        click.secho(f"❌ Failed to read email: {e}", fg='red')
        sys.exit(1)

    analyzer = HeaderAnalyzer()
    reporter = EmailReporter(output_dir=OUTPUT_DIR)

    analysis = analyzer.analyze_raw(raw_email)

    if output_format == 'console':
        _display_analysis(analysis)
    elif output_format == 'json':
        fp = reporter.report_header_analysis_json(analysis, output)
        click.secho(f"\n✅ JSON report saved: {fp}", fg='green')
    elif output_format == 'html':
        fp = reporter.report_header_analysis_html(analysis, output)
        click.secho(f"\n✅ HTML report saved: {fp}", fg='green')


# ---------------------------------------------------------------------------
# manage command
# ---------------------------------------------------------------------------

@email_cli.command()
@click.option('--action', '-a',
              type=click.Choice(['stats', 'export-emails-json', 'export-emails-csv',
                                 'export-verifications', 'purge']),
              default='stats', help='Management action')
@click.option('--output', '-o', default=None, help='Output file path')
def manage(action, output):
    """Manage stored email data and verification history

    \b
    Examples:
      python email_cli.py manage --action stats
      python email_cli.py manage --action export-emails-json
      python email_cli.py manage --action purge
    """
    click.secho("\n📂 Email Data Manager", fg='cyan', bold=True)
    click.secho("=" * 50, fg='cyan')

    dm = EmailDataManager(data_dir=DATA_DIR)
    reporter = EmailReporter(output_dir=OUTPUT_DIR)

    try:
        if action == 'stats':
            email_stats = dm.get_email_stats()
            ver_stats = dm.get_verification_stats()
            click.echo("\n  Email Statistics:")
            click.echo(json.dumps(email_stats, indent=4))
            click.echo("\n  Verification Statistics:")
            click.echo(json.dumps(ver_stats, indent=4))

        elif action == 'export-emails-json':
            emails = dm.load_emails()
            fp = reporter.report_emails_json(emails, output)
            click.secho(f"\n✅ Emails exported to JSON: {fp}", fg='green')

        elif action == 'export-emails-csv':
            emails = dm.load_emails()
            fp = reporter.report_emails_csv(emails, output)
            click.secho(f"\n✅ Emails exported to CSV: {fp}", fg='green')

        elif action == 'export-verifications':
            fp = dm.export_verifications_json(output)
            click.secho(f"\n✅ Verifications exported to JSON: {fp}", fg='green')

        elif action == 'purge':
            click.confirm(
                "  ⚠️  This will permanently delete ALL stored email data. Continue?",
                abort=True
            )
            dm.purge_history()
            click.secho("\n✅ All email data purged", fg='green')

    except Exception as e:
        click.secho(f"\n❌ Error: {e}", fg='red')
        sys.exit(1)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _output_emails(emails, output_format, output, account, mask):
    """Output emails in the requested format."""
    reporter = EmailReporter(output_dir=OUTPUT_DIR)

    if output_format == 'console':
        monitor_obj = EmailMonitor(data_dir=DATA_DIR, output_dir=OUTPUT_DIR)
        monitor_obj.display_emails(emails, mask=mask)
    elif output_format == 'json':
        fp = reporter.report_emails_json(emails, output)
        click.secho(f"\n✅ JSON report saved: {fp}", fg='green')
    elif output_format == 'csv':
        fp = reporter.report_emails_csv(emails, output)
        click.secho(f"\n✅ CSV report saved: {fp}", fg='green')
    elif output_format == 'html':
        fp = reporter.report_emails_html(emails, output, account=account)
        click.secho(f"\n✅ HTML report saved: {fp}", fg='green')


def _display_verification(result: dict):
    """Display a single verification result in the console."""
    email = result.get('email', '')
    fmt_ok = result.get('format_valid', False)
    mx_ok = result.get('mx_found', False)
    smtp = result.get('smtp_valid')
    disposable = result.get('is_disposable', False)
    deliverable = result.get('is_deliverable', False)
    confidence = result.get('confidence', 'unknown')
    risk = result.get('risk_level', 'unknown')

    def tick(v):
        return click.style("✅", fg='green') if v else click.style("❌", fg='red')

    def smtp_str(v):
        if v is True:
            return click.style("Pass", fg='green')
        elif v is False:
            return click.style("Fail", fg='red')
        return click.style("N/A", fg='yellow')

    def risk_color(r):
        colors = {'low': 'green', 'medium': 'yellow', 'high': 'red', 'critical': 'red'}
        return colors.get(r, 'white')

    click.echo(f"\n  Email      : {click.style(email, fg='white', bold=True)}")
    click.echo(f"  Format     : {tick(fmt_ok)}")
    click.echo(f"  MX Records : {tick(mx_ok)}")
    click.echo(f"  SMTP       : {smtp_str(smtp)}")
    click.echo(f"  Disposable : {tick(not disposable)}")
    click.echo(f"  Deliverable: {click.style(str(deliverable), fg='green' if deliverable else 'red')}")
    click.echo(f"  Confidence : {confidence}")
    click.echo(f"  Risk Level : {click.style(risk, fg=risk_color(risk))}")

    for detail in result.get('details', []):
        click.echo(f"  • {detail}")


def _display_analysis(analysis: dict):
    """Display header analysis in the console."""
    meta = analysis.get('metadata', {})
    auth = analysis.get('authentication', {})
    sender = analysis.get('sender', {})
    security = analysis.get('security', {})
    routing = analysis.get('routing', [])
    attachments = analysis.get('attachments', [])

    click.secho("\n  📋 Metadata", fg='cyan', bold=True)
    click.echo(f"  Subject  : {meta.get('subject', '')}")
    click.echo(f"  Date     : {meta.get('date_iso', '') or meta.get('date', '')}")
    click.echo(f"  Msg-ID   : {meta.get('message_id', '')}")
    click.echo(f"  Content  : {meta.get('content_type', '')}")

    click.secho("\n  📬 Sender", fg='cyan', bold=True)
    click.echo(f"  From     : {sender.get('from', '')}")
    click.echo(f"  Reply-To : {sender.get('reply_to', '')}")
    click.echo(f"  Return-Path: {sender.get('return_path', '')}")
    if sender.get('domain_mismatch'):
        click.secho("  ⚠️  Domain mismatch detected!", fg='yellow')
    for inc in sender.get('inconsistencies', []):
        click.secho(f"  ⚠️  {inc}", fg='yellow')

    click.secho("\n  🔐 Authentication", fg='cyan', bold=True)
    for proto in ('spf', 'dkim', 'dmarc'):
        val = auth.get(proto)
        if val == 'pass':
            status = click.style("pass", fg='green')
        elif val in ('fail', 'hardfail'):
            status = click.style(val, fg='red')
        elif val:
            status = click.style(val, fg='yellow')
        else:
            status = click.style("N/A", fg='white')
        click.echo(f"  {proto.upper():<8}: {status}")

    click.secho("\n  🛡️  Security Analysis", fg='cyan', bold=True)
    risk_score = security.get('risk_score', 0)
    risk_level = security.get('risk_level', 'unknown')
    risk_colors = {'low': 'green', 'medium': 'yellow', 'high': 'red', 'critical': 'red'}
    risk_color = risk_colors.get(risk_level, 'white')
    click.echo(f"  Risk Score : {click.style(f'{risk_score}/10', fg=risk_color)}")
    click.echo(f"  Risk Level : {click.style(risk_level.upper(), fg=risk_color)}")
    click.echo(f"  Phishing KW: {security.get('phishing_keyword_count', 0)}")
    click.echo(f"  URLs Found : {security.get('url_count', 0)}")
    click.echo(f"  Suspicious : {security.get('suspicious_url_count', 0)}")
    if security.get('spoofing_risk'):
        click.secho("  ⚠️  Spoofing risk detected!", fg='red')
        for reason in security.get('spoofing_reasons', []):
            click.secho(f"    • {reason}", fg='red')
    if security.get('reply_to_mismatch'):
        click.secho("  ⚠️  Reply-To mismatch!", fg='yellow')

    click.secho(f"\n  🛤️  Routing ({len(routing)} hops)", fg='cyan', bold=True)
    for i, hop in enumerate(routing, 1):
        tls = click.style("TLS", fg='green') if hop.get('tls') else click.style("NO TLS", fg='yellow')
        click.echo(f"  {i}. {hop.get('from_host', '?')} → {hop.get('by_server', '?')} [{tls}]")

    if attachments:
        click.secho(f"\n  📎 Attachments ({len(attachments)})", fg='cyan', bold=True)
        for att in attachments:
            click.echo(f"  • {att.get('filename', 'unnamed')} ({att.get('content_type', '')},"
                       f" {att.get('size', 0)} bytes)")


if __name__ == '__main__':
    email_cli()
