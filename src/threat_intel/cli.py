import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from pathlib import Path
from datetime import datetime

from threat_intel.feeds import (
    otx_get_subscribed_pulses,
    otx_extract_iocs,
    otx_lookup_ioc,
    abuseipdb_check_ip,
    abuseipdb_blacklist,
    urlhaus_recent_urls,
    urlhaus_lookup_host,
)
from threat_intel.correlator import correlate, top_iocs, summary_stats, enrich_with_abuseipdb
from threat_intel.summarizer import generate_report, format_report_for_terminal

app = typer.Typer()
console = Console()


@app.command()
def run(
    pulses: int = typer.Option(10, help="Number of OTX pulses to fetch"),
    blacklist: int = typer.Option(50, help="Number of IPs from AbuseIPDB blacklist"),
    no_llm: bool = typer.Option(False, help="Skip LLM summarization"),
):
    """Fetch threat intel feeds, correlate IOCs, and generate a report."""
    console.print(Panel("[bold cyan]Threat Intelligence Aggregator[/bold cyan]", box=box.ROUNDED))

    # Step 1 - Fetch OTX
    console.print("\n[cyan]Fetching OTX subscribed pulses...[/cyan]")
    try:
        pulse_data = otx_get_subscribed_pulses(limit=pulses)
        otx_iocs = otx_extract_iocs(pulse_data)
        console.print(f"  [green]OK[/green] {len(otx_iocs)} IOCs from {len(pulse_data)} pulses")
    except Exception as e:
        console.print(f"  [red]FAIL OTX failed: {e}[/red]")
        otx_iocs = []

    # Step 2 - Fetch AbuseIPDB blacklist
    console.print("[cyan]Fetching AbuseIPDB blacklist...[/cyan]")
    try:
        abuse_ips = abuseipdb_blacklist(limit=blacklist)
        abuse_iocs = [
            {
                "value": entry.get("ipAddress"),
                "type": "IPv4",
                "source": "AbuseIPDB",
                "abuse_score": entry.get("abuseConfidenceScore", 0),
                "country": entry.get("countryCode"),
                "total_reports": entry.get("totalReports", 0),
                "tags": [],
            }
            for entry in abuse_ips
        ]
    except (ValueError, RuntimeError) as e:
        console.print(f"  [bold red]FAIL AbuseIPDB error: {e}[/bold red]")
        raise typer.Exit()
    except Exception as e:
        console.print(f"  [bold red]FAIL AbuseIPDB unexpected error: {e}[/bold red]")
        raise typer.Exit()

    # Step 3 - Fetch URLhaus recent URLs
    console.print("[cyan]Fetching URLhaus recent malicious URLs...[/cyan]")
    try:
        recent_urls = urlhaus_recent_urls(limit=20)
        urlhaus_iocs = [
            {
                "value": u.get("url"),
                "type": "url",
                "source": "URLhaus",
                "tags": u.get("tags", []) or [],
                "country": None,
            }
            for u in recent_urls if u.get("url")
        ]
        console.print(f"  [green]OK[/green] {len(urlhaus_iocs)} URLs from URLhaus")
    except Exception as e:
        console.print(f"  [red]FAIL URLhaus failed: {e}[/red]")
        urlhaus_iocs = []

    # Step 4 - Correlate
    console.print("\n[cyan]Correlating IOCs...[/cyan]")
    all_iocs = otx_iocs + abuse_iocs + urlhaus_iocs
    if not all_iocs:
        console.print("[bold red]No IOCs collected. Check your API keys.[/bold red]")
        raise typer.Exit()

    correlated = correlate(all_iocs)
    stats = summary_stats(correlated)
    top = top_iocs(correlated, n=10)

    # Step 5 - Display stats table
    stats_table = Table(title="IOC Summary", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="white")

    stats_table.add_row("Total IOCs", str(stats["total_iocs"]))
    stats_table.add_row("Unique values", str(stats["unique_iocs"]))
    stats_table.add_row("Cross-source matches", str(stats["cross_source_matches"]))
    stats_table.add_row("High confidence (≥75)", str(stats["high_confidence_count"]))
    for source, count in stats["by_source"].items():
        stats_table.add_row(f"  From {source}", str(count))

    console.print(stats_table)

    # Step 6 - Display top IOCs
    ioc_table = Table(title="Top IOCs by Risk Score", box=box.ROUNDED)
    ioc_table.add_column("IOC", style="red")
    ioc_table.add_column("Type", style="yellow")
    ioc_table.add_column("Risk", style="magenta")
    ioc_table.add_column("Sources", style="cyan")
    ioc_table.add_column("Country", style="white")

    for ioc in top:
        ioc_table.add_row(
            str(ioc["value"]),
            str(ioc["type"]),
            str(ioc["risk_score"]),
            ", ".join(ioc["sources"]),
            str(ioc.get("country") or "-"),
        )

    console.print(ioc_table)

    # Step 7 - LLM report
    if not no_llm:
        console.print("\n[cyan]Generating executive report with LLM...[/cyan]")
        report = generate_report(correlated, top, stats)
        formatted = format_report_for_terminal(
            report, stats, correlated["generated_at"]
        )
        console.print(formatted)
    else:
        console.print("\n[yellow]LLM summarization skipped.[/yellow]")


@app.command()
def lookup(
    ioc: str = typer.Argument(..., help="IOC to look up (IP, domain, hash, URL)"),
    ioc_type: str = typer.Option("IPv4", help="Type: IPv4, domain, hostname, url, FileHash-MD5, FileHash-SHA256"),
):
    """Look up a single IOC across all available sources."""

    console.print(f"\n[cyan]Looking up:[/cyan] {ioc} ({ioc_type})\n")

    # OTX
    console.print("[cyan]OTX...[/cyan]")
    try:
        otx_result = otx_lookup_ioc(ioc_type, ioc)
        pulse_count = otx_result.get("pulse_info", {}).get("count", 0)
        console.print(f"  Pulse count: [bold]{pulse_count}[/bold]")
    except Exception as e:
        console.print(f"  [red]Failed: {e}[/red]")

    # AbuseIPDB (only for IPs)
    if ioc_type == "IPv4":
        console.print("[cyan]AbuseIPDB...[/cyan]")
        try:
            abuse = abuseipdb_check_ip(ioc)
            console.print(f"  Abuse score: [bold]{abuse.get('abuse_score')}[/bold]")
            console.print(f"  Total reports: {abuse.get('total_reports')}")
            console.print(f"  Country: {abuse.get('country')}")
            console.print(f"  ISP: {abuse.get('isp')}")
            console.print(f"  Is Tor: {abuse.get('is_tor')}")
        except Exception as e:
            console.print(f"  [red]Failed: {e}[/red]")

    # URLhaus (for domains and URLs)
    if ioc_type in ["domain", "hostname"]:
        console.print("[cyan]URLhaus...[/cyan]")
        try:
            urlhaus = urlhaus_lookup_host(ioc)
            status = urlhaus.get("query_status")
            urls_found = urlhaus.get("urls", [])
            console.print(f"  Status: [bold]{status}[/bold]")
            console.print(f"  Malicious URLs found: {len(urls_found)}")
        except Exception as e:
            console.print(f"  [red]Failed: {e}[/red]")

    if ioc_type == "url":
        console.print("[cyan]URLhaus...[/cyan]")
        try:
            from threat_intel.feeds import urlhaus_lookup_url
            urlhaus = urlhaus_lookup_url(ioc)
            console.print(f"  Status: [bold]{urlhaus.get('query_status')}[/bold]")
            console.print(f"  Threat: {urlhaus.get('threat', 'unknown')}")
        except Exception as e:
            console.print(f"  [red]Failed: {e}[/red]")