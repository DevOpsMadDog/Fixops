#!/usr/bin/env python3
"""ALdeci CLI - Security platform command-line interface.

This is a wrapper/overlay around the FixOps CLI that provides ALdeci-branded
commands and adds missing functionality.

Usage:
    aldeci scan <target>          # Security scan (wraps fixops scan)
    aldeci attack <target>        # Run micro-pentest / attack simulation
    aldeci findings               # List findings
    aldeci connect                # Manage connectors
    aldeci evidence               # Generate evidence bundles
    aldeci brain                  # AI chat interface
    aldeci mcp                    # MCP server management
    aldeci auth login             # Login (wraps fixops auth login)
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
import requests

# Default API URL
DEFAULT_API_URL = os.environ.get("FIXOPS_API_URL", "http://localhost:8000")
API_KEY = os.environ.get("FIXOPS_API_KEY", "")


def get_api_headers():
    """Get API headers with authentication."""
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers


def api_get(endpoint: str):
    """Make GET request to API."""
    url = f"{DEFAULT_API_URL}{endpoint}"
    try:
        resp = requests.get(url, headers=get_api_headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        click.echo(f"❌ API error: {e}", err=True)
        return None


def api_post(endpoint: str, data: dict):
    """Make POST request to API."""
    url = f"{DEFAULT_API_URL}{endpoint}"
    try:
        resp = requests.post(url, headers=get_api_headers(), json=data, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        click.echo(f"❌ API error: {e}", err=True)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Main CLI group
# ═══════════════════════════════════════════════════════════════════════════════


@click.group()
@click.version_option(version="3.0.0", prog_name="aldeci")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--api-url", default=DEFAULT_API_URL, help="ALdeci API URL")
@click.option("--api-key", envvar="FIXOPS_API_KEY", help="API key")
@click.pass_context
def cli(ctx, verbose: bool, api_url: str, api_key: str):
    """ALdeci CLI - AI-powered security platform."""
    global DEFAULT_API_URL, API_KEY

    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["api_url"] = api_url
    ctx.obj["api_key"] = api_key or API_KEY

    DEFAULT_API_URL = api_url
    if api_key:
        API_KEY = api_key


# ═══════════════════════════════════════════════════════════════════════════════
# Scan command - wraps fixops scan + adds attack capabilities
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("target")
@click.option(
    "--type",
    "-t",
    "scan_type",
    type=click.Choice(["vulnerability", "reachability", "attack", "full"]),
    default="vulnerability",
    help="Scan type",
)
@click.option(
    "--format", "-f", default="table", type=click.Choice(["table", "json", "sarif"])
)
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def scan(ctx, target: str, scan_type: str, format: str, output: Optional[str]):
    """Scan a target for vulnerabilities.

    TARGET can be:
    - CVE ID (e.g., CVE-2024-3094)
    - URL (e.g., https://api.example.com)
    - Container image (e.g., nginx:latest)
    - File path (e.g., ./src or /path/to/code)
    """
    click.echo(f"🔍 Scanning {target}...")

    # Determine if this is a path or other target
    if os.path.exists(target):
        # Use fixops scan for file paths
        from subprocess import run

        result = run(
            ["fixops", "scan", target, "--format", format],
            capture_output=True,
            text=True,
        )
        if output:
            with open(output, "w") as f:
                f.write(result.stdout)
            click.echo(f"✅ Results saved to {output}")
        else:
            click.echo(result.stdout)
    else:
        # Use API for CVE/URL/image scans
        data = {"target": target, "scan_type": scan_type}
        result = api_post("/api/v1/micro-pentest/scan", data)

        if result:
            if format == "json":
                output_text = json.dumps(result, indent=2)
            else:
                # Table format
                output_text = format_scan_results(result)

            if output:
                with open(output, "w") as f:
                    f.write(output_text)
                click.echo(f"✅ Results saved to {output}")
            else:
                click.echo(output_text)


def format_scan_results(result: dict) -> str:
    """Format scan results as table."""
    lines = ["", "┌─────────────────────────────────────────────────────────┐"]
    lines.append(f"│ Target: {result.get('target', 'Unknown'):<48}│")
    lines.append(f"│ Status: {result.get('status', 'Unknown'):<48}│")
    lines.append("├─────────────────────────────────────────────────────────┤")

    findings = result.get("findings", [])
    if findings:
        for f in findings[:10]:  # Limit to 10
            sev = f.get("severity", "unknown")[:8]
            title = f.get("title", "Unknown")[:40]
            lines.append(f"│ [{sev:>8}] {title:<45}│")
    else:
        lines.append("│ No findings                                             │")

    lines.append("└─────────────────────────────────────────────────────────┘")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Attack command - micro-pentest / attack simulation
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("target")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["passive", "active", "aggressive"]),
    default="passive",
    help="Attack mode",
)
@click.option("--timeout", "-t", default=300, help="Timeout in seconds")
@click.pass_context
def attack(ctx, target: str, mode: str, timeout: int):
    """Run micro-pentest / attack simulation.

    TARGET can be a CVE ID, URL, IP address, or container image.
    """
    click.echo(f"⚔️  Running {mode} attack on {target}...")

    data = {"target": target, "mode": mode, "timeout": timeout}
    result = api_post("/api/v1/micro-pentest/attack", data)

    if result:
        click.echo(format_attack_results(result))


def format_attack_results(result: dict) -> str:
    """Format attack results."""
    lines = ["", "═══════════════════════════════════════════════════════════"]
    lines.append(f"  Attack Results: {result.get('target', 'Unknown')}")
    lines.append("═══════════════════════════════════════════════════════════")

    verdict = result.get("verdict", "unknown")
    if verdict == "exploitable":
        lines.append("  ❌ VERDICT: EXPLOITABLE")
    elif verdict == "potentially_exploitable":
        lines.append("  ⚠️  VERDICT: POTENTIALLY EXPLOITABLE")
    else:
        lines.append("  ✅ VERDICT: NOT EXPLOITABLE")

    lines.append(f"  Confidence: {result.get('confidence', 0)}%")
    lines.append(f"  Risk Score: {result.get('risk_score', 0)}")
    lines.append("")

    evidence = result.get("evidence", [])
    if evidence:
        lines.append("  Evidence:")
        for e in evidence:
            lines.append(f"    • {e}")

    lines.append("═══════════════════════════════════════════════════════════")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Findings command - list/manage findings
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Filter by severity",
)
@click.option(
    "--status",
    type=click.Choice(["open", "in_progress", "resolved", "false_positive"]),
    help="Filter by status",
)
@click.option("--source", help="Filter by source connector")
@click.option("--limit", "-l", default=50, help="Maximum results")
@click.option("--format", "-f", default="table", type=click.Choice(["table", "json"]))
@click.pass_context
def findings(ctx, severity: str, status: str, source: str, limit: int, format: str):
    """List security findings."""
    click.echo("📋 Fetching findings...")

    params = []
    if severity:
        params.append(f"severity={severity}")
    if status:
        params.append(f"status={status}")
    if source:
        params.append(f"source={source}")
    params.append(f"limit={limit}")

    query = "&".join(params)
    result = api_get(f"/api/v1/analytics/findings?{query}")

    if result:
        if format == "json":
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo(format_findings_table(result))


def format_findings_table(result: dict) -> str:
    """Format findings as table."""
    items = result.get("items", result.get("findings", []))
    total = result.get("total", len(items))

    lines = ["", f"Found {total} findings:", ""]
    lines.append(
        "┌────────────┬────────────┬──────────────────────────────────────────┐"
    )
    lines.append(
        "│ Severity   │ Status     │ Title                                    │"
    )
    lines.append(
        "├────────────┼────────────┼──────────────────────────────────────────┤"
    )

    for f in items[:20]:  # Limit display to 20
        sev = f.get("severity", "unknown")[:10]
        stat = f.get("status", "open")[:10]
        title = f.get("title", f.get("name", "Unknown"))[:38]
        lines.append(f"│ {sev:<10} │ {stat:<10} │ {title:<40} │")

    lines.append(
        "└────────────┴────────────┴──────────────────────────────────────────┘"
    )
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Connect command - manage connectors
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def connect():
    """Manage integrations and connectors."""


@connect.command("list")
@click.option("--format", "-f", default="table", type=click.Choice(["table", "json"]))
@click.pass_context
def connect_list(ctx, format: str):
    """List configured connectors."""
    click.echo("🔗 Fetching connectors...")

    result = api_get("/api/v1/integrations")

    if result:
        if format == "json":
            click.echo(json.dumps(result, indent=2))
        else:
            items = result.get("items", [])
            click.echo(f"\n{len(items)} connectors configured:\n")
            for c in items:
                status = "✅" if c.get("status") == "active" else "❌"
                click.echo(
                    f"  {status} {c.get('name', 'Unknown')} ({c.get('integration_type', 'unknown')})"
                )


@connect.command("add")
@click.argument(
    "connector_type",
    type=click.Choice(
        [
            "github",
            "gitlab",
            "jira",
            "slack",
            "snyk",
            "sonarqube",
            "aws-security-hub",
            "azure-security-center",
            "dependabot",
        ]
    ),
)
@click.option("--name", "-n", required=True, help="Connector name")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file (JSON)")
@click.pass_context
def connect_add(ctx, connector_type: str, name: str, config: str):
    """Add a new connector."""
    click.echo(f"🔧 Adding {connector_type} connector...")

    config_data = {}
    if config:
        with open(config) as f:
            config_data = json.load(f)

    data = {"name": name, "integration_type": connector_type, "config": config_data}

    result = api_post("/api/v1/integrations", data)

    if result:
        click.echo(f"✅ Connector {name} added successfully!")


@connect.command("sync")
@click.argument("connector_name")
@click.pass_context
def connect_sync(ctx, connector_name: str):
    """Trigger sync for a connector."""
    click.echo(f"🔄 Syncing {connector_name}...")

    result = api_post(f"/api/v1/integrations/{connector_name}/sync", {})

    if result:
        click.echo(f"✅ Sync triggered for {connector_name}")


# ═══════════════════════════════════════════════════════════════════════════════
# Evidence command - compliance evidence bundles
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def evidence():
    """Manage compliance evidence."""


@evidence.command("list")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["SOC2", "ISO27001", "PCI-DSS", "SLSA"]),
    help="Filter by framework",
)
@click.pass_context
def evidence_list(ctx, framework: str):
    """List evidence bundles."""
    click.echo("📦 Fetching evidence bundles...")

    endpoint = "/api/v1/evidence/bundles"
    if framework:
        endpoint += f"?framework={framework}"

    result = api_get(endpoint)

    if result:
        bundles = result.get("bundles", [])
        click.echo(f"\n{len(bundles)} evidence bundles:\n")
        for b in bundles:
            signed = "🔐" if b.get("signed") else "  "
            click.echo(
                f"  {signed} {b.get('id')} | {b.get('type')} | {b.get('status')}"
            )


@evidence.command("generate")
@click.option(
    "--framework",
    "-f",
    required=True,
    type=click.Choice(["SOC2", "ISO27001", "PCI-DSS", "SLSA"]),
    help="Framework to generate evidence for",
)
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def evidence_generate(ctx, framework: str, output: str):
    """Generate compliance evidence bundle."""
    click.echo(f"📜 Generating {framework} evidence bundle...")

    result = api_post("/api/v1/evidence/generate", {"framework": framework})

    if result:
        bundle_id = result.get("bundle_id", "unknown")
        click.echo(f"✅ Evidence bundle generated: {bundle_id}")

        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            click.echo(f"📁 Saved to {output}")


# ═══════════════════════════════════════════════════════════════════════════════
# Brain command - AI chat interface
# ═══════════════════════════════════════════════════════════════════════════════


@cli.command()
@click.argument("query", required=False)
@click.option("--interactive", "-i", is_flag=True, help="Interactive chat mode")
@click.pass_context
def brain(ctx, query: str, interactive: bool):
    """Chat with The Brain AI assistant.

    Examples:
        aldeci brain "what are my critical findings?"
        aldeci brain "explain CVE-2024-3094"
        aldeci brain --interactive
    """
    if interactive:
        run_interactive_chat()
    elif query:
        ask_brain(query)
    else:
        click.echo("Usage: aldeci brain <query> or aldeci brain --interactive")


def ask_brain(query: str):
    """Send query to Brain."""
    click.echo(f"🧠 Asking The Brain: {query}\n")

    result = api_post("/api/v1/copilot/sessions/cli/message", {"content": query})

    if result:
        response = result.get("response", result.get("content", "No response"))
        click.echo(f"💡 {response}")


def run_interactive_chat():
    """Run interactive chat mode."""
    click.echo("🧠 The Brain - Interactive Mode")
    click.echo("Type 'exit' to quit\n")

    while True:
        try:
            query = click.prompt("You", prompt_suffix="> ")
            if query.lower() in ["exit", "quit", "q"]:
                break
            ask_brain(query)
            click.echo()
        except (KeyboardInterrupt, EOFError):
            break

    click.echo("\n👋 Goodbye!")


# ═══════════════════════════════════════════════════════════════════════════════
# MCP command - MCP server management
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def mcp():
    """MCP (Model Context Protocol) server management."""


@mcp.command("status")
@click.pass_context
def mcp_status(ctx):
    """Get MCP server status."""
    result = api_get("/api/v1/mcp/status")

    if result:
        enabled = "✅ Enabled" if result.get("enabled") else "❌ Disabled"
        click.echo("\n🔌 MCP Server Status")
        click.echo(f"   Status: {enabled}")
        click.echo(f"   Transport: {result.get('transport', 'unknown')}")
        click.echo(f"   Connected Clients: {result.get('connected_clients', 0)}")
        click.echo(f"   Available Tools: {result.get('available_tools', 0)}")
        click.echo(f"   Available Resources: {result.get('available_resources', 0)}")
        click.echo(f"   Version: {result.get('version', 'unknown')}")


@mcp.command("clients")
@click.pass_context
def mcp_clients(ctx):
    """List connected MCP clients."""
    result = api_get("/api/v1/mcp/clients")

    if result:
        click.echo(f"\n🖥️  Connected MCP Clients ({len(result)}):\n")
        for c in result:
            status = "🟢" if c.get("status") == "connected" else "🔴"
            click.echo(f"  {status} {c.get('name')} ({c.get('client_type')})")


@mcp.command("tools")
@click.pass_context
def mcp_tools(ctx):
    """List available MCP tools."""
    result = api_get("/api/v1/mcp/tools")

    if result:
        click.echo(f"\n🔧 Available MCP Tools ({len(result)}):\n")
        for t in result:
            click.echo(f"  • {t.get('name')}")
            click.echo(f"    {t.get('description')[:60]}...")


@mcp.command("manifest")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def mcp_manifest(ctx, output: str):
    """Get MCP server manifest for IDE configuration."""
    result = api_get("/api/v1/mcp/manifest")

    if result:
        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            click.echo(f"✅ Manifest saved to {output}")
        else:
            click.echo(json.dumps(result, indent=2))


# ═══════════════════════════════════════════════════════════════════════════════
# Auth commands - wraps fixops auth
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def auth():
    """Authentication commands."""


@auth.command("login")
@click.option("--api-key", prompt=True, hide_input=True, help="API key")
@click.pass_context
def auth_login(ctx, api_key: str):
    """Login to ALdeci."""
    click.echo("🔐 Logging in...")

    # Try to validate the key
    global API_KEY
    API_KEY = api_key
    result = api_get("/api/v1/health")

    if result:
        # Save to config file
        config_path = Path.home() / ".aldeci" / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = {"api_key": api_key, "api_url": DEFAULT_API_URL}
        with open(config_path, "w") as f:
            json.dump(config, f)
        os.chmod(config_path, 0o600)  # Secure permissions
        click.echo("✅ Login successful!")
    else:
        click.echo("❌ Login failed - invalid API key", err=True)
        sys.exit(1)


@auth.command("logout")
@click.pass_context
def auth_logout(ctx):
    """Logout from ALdeci."""
    click.echo("🔐 Logging out...")

    config_path = Path.home() / ".aldeci" / "config.json"
    if config_path.exists():
        config_path.unlink()

    click.echo("✅ Logged out!")


@auth.command("whoami")
@click.pass_context
def auth_whoami(ctx):
    """Show current authentication status."""
    result = api_get("/api/v1/auth/me")

    if result:
        click.echo(
            f"\n👤 Logged in as: {result.get('email', result.get('user_id', 'Unknown'))}"
        )
        click.echo(f"   Organization: {result.get('org_id', 'Unknown')}")
        click.echo(f"   Role: {result.get('role', 'Unknown')}")
    else:
        click.echo("❌ Not logged in")


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline command
# ═══════════════════════════════════════════════════════════════════════════════


@cli.group()
def pipeline():
    """Pipeline automation commands."""


@pipeline.command("run")
@click.option("--template", "-t", default="full-triage", help="Pipeline template")
@click.pass_context
def pipeline_run(ctx, template: str):
    """Run a pipeline."""
    click.echo(f"🚀 Running {template} pipeline...")

    result = api_post("/api/v1/brain-pipeline/runs", {"template": template})

    if result:
        run_id = result.get("run_id", result.get("id", "unknown"))
        click.echo(f"✅ Pipeline started: {run_id}")


@pipeline.command("status")
@click.argument("run_id", required=False)
@click.pass_context
def pipeline_status(ctx, run_id: str):
    """Check pipeline status."""
    if run_id:
        result = api_get(f"/api/v1/brain-pipeline/runs/{run_id}")
    else:
        result = api_get("/api/v1/brain-pipeline/runs?limit=5")

    if result:
        if isinstance(result, list):
            click.echo("\n📊 Recent Pipeline Runs:\n")
            for r in result:
                status = "✅" if r.get("status") == "completed" else "⏳"
                click.echo(
                    f"  {status} {r.get('id')} | {r.get('template')} | {r.get('status')}"
                )
        else:
            click.echo(f"\n📊 Pipeline: {result.get('id')}")
            click.echo(f"   Status: {result.get('status')}")
            click.echo(f"   Progress: {result.get('progress', 0)}%")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    """Main entry point."""
    # Load config if exists
    config_path = Path.home() / ".aldeci" / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
                global DEFAULT_API_URL, API_KEY
                DEFAULT_API_URL = config.get("api_url", DEFAULT_API_URL)
                API_KEY = config.get("api_key", API_KEY)
        except Exception:
            pass

    cli()


if __name__ == "__main__":
    main()
