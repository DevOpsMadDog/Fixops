#!/usr/bin/env python3
"""FixOps CLI - Developer-friendly command-line interface.

Usage:
    fixops scan <path>
    fixops test <path>
    fixops monitor
    fixops auth login
    fixops auth logout
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import click
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="1.0.0")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--api-url", default="https://api.fixops.com", help="FixOps API URL")
@click.pass_context
def cli(ctx, verbose: bool, api_url: str):
    """FixOps CLI - Unified vulnerability management platform."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["api_url"] = api_url
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", default="sarif", type=click.Choice(["sarif", "json", "table"]))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--severity", "-s", multiple=True, type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--exclude", multiple=True, help="Paths to exclude")
@click.pass_context
def scan(ctx, path: str, format: str, output: Optional[str], severity: tuple, exclude: tuple):
    """Scan codebase for vulnerabilities."""
    from cli.scanner import CodeScanner
    
    click.echo(f"🔍 Scanning {path}...")
    
    scanner = CodeScanner(ctx.obj["api_url"])
    results = scanner.scan(
        path=path,
        format=format,
        severity_filter=list(severity) if severity else None,
        exclude_paths=list(exclude) if exclude else None,
    )
    
    if output:
        with open(output, "w") as f:
            f.write(results)
        click.echo(f"✅ Results saved to {output}")
    else:
        click.echo(results)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--test-type", "-t", default="all", type=click.Choice(["all", "unit", "integration", "security"]))
@click.pass_context
def test(ctx, path: str, test_type: str):
    """Run security tests."""
    from cli.tester import SecurityTester
    
    click.echo(f"🧪 Running {test_type} tests in {path}...")
    
    tester = SecurityTester(ctx.obj["api_url"])
    results = tester.run_tests(path=path, test_type=test_type)
    
    click.echo(results)


@cli.command()
@click.option("--watch", "-w", is_flag=True, help="Watch for changes")
@click.pass_context
def monitor(ctx, watch: bool):
    """Monitor application runtime for security issues."""
    from cli.monitor import RuntimeMonitor
    
    click.echo("🛡️  Starting runtime monitoring...")
    
    monitor = RuntimeMonitor(ctx.obj["api_url"])
    if watch:
        monitor.watch()
    else:
        results = monitor.analyze()
        click.echo(results)


@cli.group()
def auth():
    """Authentication commands."""
    pass


@auth.command()
@click.option("--api-key", prompt=True, hide_input=True, help="FixOps API key")
@click.pass_context
def login(ctx, api_key: str):
    """Login to FixOps."""
    from cli.auth import AuthManager
    
    click.echo("🔐 Logging in...")
    
    auth_manager = AuthManager(ctx.obj["api_url"])
    success = auth_manager.login(api_key)
    
    if success:
        click.echo("✅ Login successful!")
    else:
        click.echo("❌ Login failed!", err=True)
        sys.exit(1)


@auth.command()
@click.pass_context
def logout(ctx):
    """Logout from FixOps."""
    from cli.auth import AuthManager
    
    click.echo("🔐 Logging out...")
    
    auth_manager = AuthManager(ctx.obj["api_url"])
    auth_manager.logout()
    
    click.echo("✅ Logged out!")


@cli.group()
def config():
    """Configuration commands."""
    pass


@config.command()
@click.option("--api-url", prompt=True, help="FixOps API URL")
@click.pass_context
def set_api_url(ctx, api_url: str):
    """Set FixOps API URL."""
    from cli.config import ConfigManager
    
    config_manager = ConfigManager()
    config_manager.set_api_url(api_url)
    
    click.echo(f"✅ API URL set to {api_url}")


@config.command()
@click.pass_context
def show(ctx):
    """Show current configuration."""
    from cli.config import ConfigManager
    
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    click.echo("📋 Current Configuration:")
    for key, value in config.items():
        click.echo(f"  {key}: {value}")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
