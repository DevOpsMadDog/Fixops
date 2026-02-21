#!/usr/bin/env python3
"""
FixOps Real-Time Feed Sidecar - CVE/KEV Feed Ingestion.

A sidecar script that:
- Fetches real-time CVE data from NVD
- Fetches CISA KEV (Known Exploited Vulnerabilities) catalog
- Pushes data to FixOps API for analysis
- Provides animated, real-time output

Usage:
    python feed_sidecar.py fetch-kev
    python feed_sidecar.py fetch-nvd --days 7
    python feed_sidecar.py continuous --interval 3600
"""

import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import httpx
    import typer
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )
    from rich.table import Table
except ImportError:
    print("Installing required packages...")
    import subprocess

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "rich", "typer", "httpx"]
    )
    import httpx
    import typer
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
    )
    from rich.table import Table

# Configuration
BASE_URL = os.getenv("FIXOPS_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("FIXOPS_API_TOKEN", "")
TIMEOUT = 60.0

# External feed URLs
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Initialize
console = Console()
app = typer.Typer(help="FixOps Real-Time Feed Sidecar - CVE/KEV Ingestion")


def get_client() -> httpx.Client:
    """Create an authenticated HTTP client for FixOps API."""
    return httpx.Client(
        base_url=BASE_URL, headers={"X-API-Key": API_KEY}, timeout=TIMEOUT
    )


def wait_for_api(timeout: int = 120) -> bool:
    """Wait for the FixOps API to become healthy."""
    with console.status(
        "[bold cyan]Connecting to FixOps API...", spinner="dots"
    ) as status:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = httpx.get(f"{BASE_URL}/health", timeout=5.0)
                if r.status_code == 200:
                    console.print("[green]Connected to FixOps API[/green]")
                    return True
            except Exception as exc:
                logger.debug(f"Health check failed: {exc}")
            time.sleep(2)
            remaining = int(deadline - time.time())
            status.update(f"[bold cyan]Connecting... ({remaining}s remaining)")
    return False


def print_banner():
    """Print the feed sidecar banner."""
    banner = """
    ███████╗███████╗███████╗██████╗ ███████╗
    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝
    █████╗  █████╗  █████╗  ██║  ██║███████╗
    ██╔══╝  ██╔══╝  ██╔══╝  ██║  ██║╚════██║
    ██║     ███████╗███████╗██████╔╝███████║
    ╚═╝     ╚══════╝╚══════╝╚═════╝ ╚══════╝

    Real-Time CVE/KEV Feed Ingestion
    """
    console.print(Panel(banner, style="bold green", box=box.DOUBLE))


def fetch_cisa_kev() -> Optional[Dict[str, Any]]:
    """Fetch CISA KEV catalog."""
    with console.status("[bold cyan]Fetching CISA KEV catalog...", spinner="dots12"):
        try:
            r = httpx.get(CISA_KEV_URL, timeout=30.0)
            if r.status_code == 200:
                return r.json()
        except Exception as exc:
            console.print(f"[red]Error fetching KEV: {exc}[/red]")
    return None


def fetch_nvd_recent(days: int = 7) -> Optional[List[Dict[str, Any]]]:
    """Fetch recent CVEs from NVD."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
    }

    with console.status(
        f"[bold cyan]Fetching NVD CVEs from last {days} days...", spinner="dots12"
    ):
        try:
            r = httpx.get(NVD_API_URL, params=params, timeout=60.0)
            if r.status_code == 200:
                data = r.json()
                return data.get("vulnerabilities", [])
        except Exception as exc:
            console.print(f"[red]Error fetching NVD: {exc}[/red]")
    return None


def push_to_fixops(client: httpx.Client, cves: List[Dict[str, Any]]) -> Dict[str, int]:
    """Push CVE data to FixOps API."""
    results = {"success": 0, "failed": 0, "skipped": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Pushing CVEs to FixOps...", total=len(cves))

        for cve_data in cves:
            try:
                cve_id = cve_data.get("cve", {}).get("id", "unknown")
                progress.update(task, description=f"[cyan]Processing {cve_id}...")

                payload = {
                    "cve_id": cve_id,
                    "data": cve_data,
                }

                r = client.post("/api/v1/cve/ingest", json=payload)
                if r.status_code in (200, 201):
                    results["success"] += 1
                elif r.status_code == 409:
                    results["skipped"] += 1
                else:
                    results["failed"] += 1
            except Exception as exc:
                logger.warning(f"Failed to push CVE {cve_id}: {exc}")
                results["failed"] += 1

            progress.advance(task)
            time.sleep(0.1)

    return results


def display_kev_summary(kev_data: Dict[str, Any]):
    """Display KEV catalog summary."""
    vulnerabilities = kev_data.get("vulnerabilities", [])

    table = Table(title="CISA KEV Catalog Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Total KEV Entries", str(len(vulnerabilities)))
    table.add_row("Catalog Version", kev_data.get("catalogVersion", "N/A"))
    table.add_row("Last Updated", kev_data.get("dateReleased", "N/A"))

    vendors: Dict[str, int] = {}
    for vuln in vulnerabilities[:100]:
        vendor = vuln.get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]
    table.add_row("Top Vendors", ", ".join([f"{v[0]} ({v[1]})" for v in top_vendors]))

    console.print(table)

    recent_table = Table(title="Recent KEV Entries (Last 10)", box=box.ROUNDED)
    recent_table.add_column("CVE ID", style="cyan")
    recent_table.add_column("Vendor", style="white")
    recent_table.add_column("Product", style="white")
    recent_table.add_column("Due Date", style="red")

    for vuln in vulnerabilities[:10]:
        recent_table.add_row(
            vuln.get("cveID", "N/A"),
            vuln.get("vendorProject", "N/A"),
            vuln.get("product", "N/A")[:30],
            vuln.get("dueDate", "N/A"),
        )

    console.print(recent_table)


@app.command()
def fetch_kev(
    push: bool = typer.Option(False, "--push", "-p", help="Push to FixOps API"),
):
    """Fetch CISA KEV catalog and optionally push to FixOps."""
    print_banner()

    kev_data = fetch_cisa_kev()
    if not kev_data:
        console.print("[red]Failed to fetch KEV catalog[/red]")
        raise typer.Exit(1)

    display_kev_summary(kev_data)

    if push:
        if not wait_for_api():
            console.print("[red]FixOps API not available[/red]")
            raise typer.Exit(1)

        client = get_client()
        vulnerabilities = kev_data.get("vulnerabilities", [])

        cves = [
            {
                "cve": {
                    "id": v.get("cveID"),
                    "descriptions": [{"value": v.get("shortDescription", "")}],
                },
                "kev": True,
                "dueDate": v.get("dueDate"),
            }
            for v in vulnerabilities
        ]

        results = push_to_fixops(client, cves)
        console.print(
            f"\n[green]Pushed: {results['success']}[/green] | "
            f"[yellow]Skipped: {results['skipped']}[/yellow] | "
            f"[red]Failed: {results['failed']}[/red]"
        )


@app.command()
def fetch_nvd(
    days: int = typer.Option(7, "--days", "-d", help="Number of days to fetch"),
    push: bool = typer.Option(False, "--push", "-p", help="Push to FixOps API"),
):
    """Fetch recent CVEs from NVD and optionally push to FixOps."""
    print_banner()

    cves = fetch_nvd_recent(days)
    if not cves:
        console.print("[red]Failed to fetch NVD data[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Fetched {len(cves)} CVEs from last {days} days[/green]")

    table = Table(title=f"NVD CVEs (Last {days} Days)", box=box.ROUNDED)
    table.add_column("CVE ID", style="cyan")
    table.add_column("Published", style="white")
    table.add_column("Severity", style="white")

    for cve_item in cves[:20]:
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        published = cve.get("published", "N/A")[:10]

        metrics = cve.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", [])
        cvss_data = cvss_list[0] if cvss_list else {}
        severity = cvss_data.get("cvssData", {}).get("baseSeverity", "N/A")

        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity, "white")

        table.add_row(
            cve_id, published, f"[{severity_color}]{severity}[/{severity_color}]"
        )

    console.print(table)
    console.print(f"\n[dim]Showing first 20 of {len(cves)} CVEs[/dim]")

    if push:
        if not wait_for_api():
            console.print("[red]FixOps API not available[/red]")
            raise typer.Exit(1)

        client = get_client()
        results = push_to_fixops(client, cves)
        console.print(
            f"\n[green]Pushed: {results['success']}[/green] | "
            f"[yellow]Skipped: {results['skipped']}[/yellow] | "
            f"[red]Failed: {results['failed']}[/red]"
        )


@app.command()
def continuous(
    interval: int = typer.Option(
        3600, "--interval", "-i", help="Polling interval in seconds"
    ),
    kev: bool = typer.Option(True, "--kev/--no-kev", help="Fetch KEV catalog"),
    nvd: bool = typer.Option(True, "--nvd/--no-nvd", help="Fetch NVD data"),
    nvd_days: int = typer.Option(1, "--nvd-days", help="NVD lookback days"),
):
    """Run continuous feed ingestion."""
    print_banner()

    if not wait_for_api():
        console.print("[red]FixOps API not available[/red]")
        raise typer.Exit(1)

    client = get_client()
    iteration = 0

    console.print(
        Panel(
            f"[bold]Starting Continuous Feed Ingestion[/bold]\n\n"
            f"Interval: {interval} seconds\n"
            f"KEV: {'Enabled' if kev else 'Disabled'}\n"
            f"NVD: {'Enabled' if nvd else 'Disabled'} (last {nvd_days} days)",
            title="[bold cyan]Feed Configuration[/bold cyan]",
            border_style="cyan",
        )
    )

    while True:
        iteration += 1
        console.print(f"\n[bold cyan]--- Iteration {iteration} ---[/bold cyan]")
        console.print(f"[dim]Time: {datetime.utcnow().isoformat()}[/dim]")

        if kev:
            console.print("\n[bold]Fetching KEV catalog...[/bold]")
            kev_data = fetch_cisa_kev()
            if kev_data:
                vulnerabilities = kev_data.get("vulnerabilities", [])
                cves = [
                    {
                        "cve": {"id": v.get("cveID")},
                        "kev": True,
                    }
                    for v in vulnerabilities
                ]
                results = push_to_fixops(client, cves)
                console.print(
                    f"KEV: [green]{results['success']}[/green] pushed, "
                    f"[yellow]{results['skipped']}[/yellow] skipped"
                )

        if nvd:
            console.print("\n[bold]Fetching NVD data...[/bold]")
            nvd_cves = fetch_nvd_recent(nvd_days)
            if nvd_cves:
                results = push_to_fixops(client, nvd_cves)
                console.print(
                    f"NVD: [green]{results['success']}[/green] pushed, "
                    f"[yellow]{results['skipped']}[/yellow] skipped"
                )

        console.print(f"\n[dim]Sleeping for {interval} seconds...[/dim]")
        time.sleep(interval)


@app.command()
def health():
    """Check feed sources and FixOps API health."""
    print_banner()

    table = Table(title="Feed Sources Health", box=box.ROUNDED)
    table.add_column("Source", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Details", style="dim")

    try:
        r = httpx.get(CISA_KEV_URL, timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            count = len(data.get("vulnerabilities", []))
            table.add_row("CISA KEV", "[green]OK[/green]", f"{count} vulnerabilities")
        else:
            table.add_row("CISA KEV", f"[yellow]{r.status_code}[/yellow]", "")
    except Exception as exc:
        table.add_row("CISA KEV", "[red]ERROR[/red]", str(exc)[:40])

    try:
        r = httpx.get(NVD_API_URL, params={"resultsPerPage": 1}, timeout=10.0)
        if r.status_code == 200:
            table.add_row("NVD API", "[green]OK[/green]", "API accessible")
        else:
            table.add_row("NVD API", f"[yellow]{r.status_code}[/yellow]", "")
    except Exception as exc:
        table.add_row("NVD API", "[red]ERROR[/red]", str(exc)[:40])

    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=5.0)
        if r.status_code == 200:
            table.add_row("FixOps API", "[green]OK[/green]", BASE_URL)
        else:
            table.add_row("FixOps API", f"[yellow]{r.status_code}[/yellow]", BASE_URL)
    except Exception as exc:
        table.add_row("FixOps API", "[red]ERROR[/red]", str(exc)[:40])

    console.print(table)


if __name__ == "__main__":
    app()
