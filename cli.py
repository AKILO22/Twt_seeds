#!/usr/bin/env python3
"""
Command Line Interface for Seed Phrase Generator
"""

import click
from seed_generator import SeedPhraseGenerator
from config import ENTROPY_OPTIONS

@click.group()
def cli():
    """BIP39 Seed Phrase Generator for Termux"""
    pass

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
        
        # Display results
        if format == 'console':
            display_console(results)
        elif format == 'json':
            display_json(results)
        
        # Save if requested
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

def display_console(results):
    """Display results in console format"""
    for item in results:
        click.echo(f"Seed #{item['index']}")
        click.echo(f"Phrase: {item['phrase']}")
        click.echo(f"Words: {item['word_count']}")
        click.echo(f"Valid: {'✓' if item['valid'] else '✗'}")
        click.echo(f"Time: {item['timestamp']}")
        click.echo("-" * 80)

def display_json(results):
    """Display results in JSON format"""
    import json
    click.echo(json.dumps(results, indent=2))

if __name__ == '__main__':
    cli()