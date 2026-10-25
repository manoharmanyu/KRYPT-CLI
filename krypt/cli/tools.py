"""
CLI Commands for Integrated Upstream Tools (theHarvester, Photon, TorBot, ARES).
Provides discovery, health diagnostics, and execution for all third-party adapters.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from krypt.integrations.registry import registry

tools_app = typer.Typer(
    name="tools",
    help="Manage, diagnose, and execute integrated upstream reconnaissance & assessment tools.",
    no_args_is_help=True
)

console = Console()


@tools_app.command("list")
def tools_list_command(
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format.")
):
    """List all integrated upstream security tools, upstream commit SHAs, licenses, and readiness."""
    tools = registry.list_tools()

    if json_output:
        console.print_json(json.dumps([t.model_dump() for t in tools], indent=2))
        return

    table = Table(
        title="[bold red]KRYPT CLI[/] [bold white]— Integrated Upstream Tool Catalog[/]",
        border_style="cyan"
    )
    table.add_column("Tool", style="bold white")
    table.add_column("Upstream Repository", style="cyan")
    table.add_column("Commit SHA", style="dim")
    table.add_column("License", style="green")
    table.add_column("Runtime", style="yellow")
    table.add_column("Status", justify="center")

    for t in tools:
        status_badge = "[bold green]READY[/]" if t.installed else "[bold red]MISSING[/]"
        table.add_row(
            t.name,
            f"{t.upstream_repo} ({t.upstream_branch})",
            t.commit_sha[:10],
            t.license,
            f"Python {t.runtime_python}",
            status_badge
        )

    console.print(table)
    console.print("\n[dim]Use 'krypt tools doctor' to verify runtime environments, virtualenvs, and dependencies.[/]\n")


@tools_app.command("doctor")
def tools_doctor_command(
    json_output: bool = typer.Option(False, "--json", help="Output diagnostic results in JSON format.")
):
    """Perform diagnostic health check for all upstream tool virtual environments and executables."""
    with console.status("[bold cyan]Running diagnostics across all integrated tool adapters..."):
        diag = asyncio.run(registry.doctor())

    if json_output:
        console.print_json(json.dumps(diag, indent=2))
        return

    table = Table(
        title="[bold red]KRYPT CLI[/] [bold white]— Upstream Tools Doctor & Environment Diagnostics[/]",
        border_style="cyan"
    )
    table.add_column("Tool Name", style="bold white")
    table.add_column("Runtime Path", style="dim")
    table.add_column("Health Status", justify="center")
    table.add_column("Smoke Test", justify="center")
    table.add_column("Details", style="yellow")

    all_healthy = True
    for tool_name, data in diag.items():
        st = data.get("status", "UNKNOWN")
        smoke = data.get("smoke_test", "N/A")
        
        if st == "HEALTHY":
            status_style = "[bold green]HEALTHY[/]"
        elif st == "WARNING":
            status_style = "[bold yellow]WARNING[/]"
            all_healthy = False
        else:
            status_style = "[bold red]FAILED[/]"
            all_healthy = False

        smoke_style = "[bold green]PASSED[/]" if smoke == "PASSED" else f"[dim]{smoke}[/]"
        table.add_row(
            data.get("display_name", tool_name),
            data.get("venv_path", "N/A"),
            status_style,
            smoke_style,
            data.get("message", "Ready")
        )

    console.print(table)

    if all_healthy:
        console.print(Panel(
            "[bold green]✓ ALL 4 INTEGRATED UPSTREAM TOOLS ARE HEALTHY AND READY FOR USE.[/]\n"
            "[dim]theHarvester (Py 3.14), Photon (Py 3.11), TorBot (Py 3.12), ARES (Py 3.11).[/]",
            border_style="green"
        ))
    else:
        console.print(Panel(
            "[bold yellow]! ONE OR MORE TOOLS REQUIRE SETUP OR ARE MISSING VIRTUAL ENVIRONMENTS.[/]\n"
            "[dim]Review the paths above or check docs/INTEGRATIONS.md for installation instructions.[/]",
            border_style="yellow"
        ))


@tools_app.command("harvester")
def harvester_command(
    domain: str = typer.Argument(..., help="Domain name to harvest OSINT intelligence for."),
    sources: str = typer.Option("crtsh,duckduckgo,hackertarget", "--sources", "-s", help="Comma-separated OSINT sources."),
    limit: int = typer.Option(100, "--limit", "-l", help="Query limit per source."),
    active: bool = typer.Option(False, "--active", "-a", help="Perform active DNS brute-forcing (strictly requires registered target)."),
    timeout: int = typer.Option(90, "--timeout", "-t", help="Timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File to write result JSON.")
):
    """Run theHarvester OSINT engine to discover subdomains, IPs, emails, and hostnames."""
    adapter = registry.get_adapter("theHarvester")
    if not adapter:
        console.print("[bold red]Error: theHarvester adapter is not registered.[/]")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Running theHarvester against [white]{domain}[/] (sources: {sources})..."):
        result = asyncio.run(adapter.run(
            target=domain,
            sources=sources,
            limit=limit,
            active=active,
            timeout=timeout
        ))

    if json_output or output:
        json_data = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(json_data, encoding="utf-8")
            console.print(f"[bold green]✓ theHarvester results written to {output}[/]")
        else:
            console.print_json(json_data)
        return

    if result.status == "BLOCKED":
        console.print(Panel(
            f"[bold red]SCOPE VIOLATION BLOCKED BY KRYPT SAFETY ENGINE[/]\n\n"
            f"{result.errors[0] if result.errors else 'Target not authorized in registered scope.'}",
            border_style="red"
        ))
        raise typer.Exit(code=2)

    if result.status == "FAILED":
        console.print(Panel(
            f"[bold red]theHarvester execution failed:[/]\n\n"
            f"{result.errors[0] if result.errors else 'Unknown execution error.'}",
            border_style="red"
        ))
        raise typer.Exit(code=1)

    table = Table(
        title=f"[bold cyan]theHarvester Findings for [white]{domain}[/] (Status: {result.status})[/]",
        border_style="cyan"
    )
    table.add_column("Category", style="bold")
    table.add_column("Discovered Item", style="white")
    table.add_column("Details", style="dim")

    for f in result.findings[:100]:
        table.add_row(f["category"].upper(), f["item"], f["details"])

    console.print(table)
    console.print(
        f"\n[bold green]✓ Total findings discovered:[/] {len(result.findings)} "
        f"[dim]| Run ID: {result.run_id} | Output files: {len(result.output_files)}[/]\n"
    )


@tools_app.command("photon")
def photon_command(
    target: str = typer.Argument(..., help="Target URL or hostname to crawl."),
    level: int = typer.Option(2, "--level", "-l", help="Crawl depth level (1-5)."),
    threads: int = typer.Option(4, "--threads", "-t", help="Concurrent crawler threads."),
    timeout: int = typer.Option(60, "--timeout", help="HTTP timeout in seconds."),
    no_keys: bool = typer.Option(False, "--no-keys", help="Disable regex secret key scanning."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File to write result JSON.")
):
    """Run Photon crawler to extract endpoints, query parameters, JS assets, and secret keys."""
    adapter = registry.get_adapter("Photon")
    if not adapter:
        console.print("[bold red]Error: Photon adapter is not registered.[/]")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Crawling [white]{target}[/] with Photon (level: {level}, threads: {threads})..."):
        result = asyncio.run(adapter.run(
            target=target,
            level=level,
            threads=threads,
            timeout=timeout,
            keys=not no_keys
        ))

    if json_output or output:
        json_data = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(json_data, encoding="utf-8")
            console.print(f"[bold green]✓ Photon results written to {output}[/]")
        else:
            console.print_json(json_data)
        return

    if result.status == "BLOCKED":
        console.print(Panel(
            f"[bold red]SCOPE VIOLATION BLOCKED BY KRYPT SAFETY ENGINE[/]\n\n"
            f"{result.errors[0] if result.errors else 'Target not authorized in registered scope.'}",
            border_style="red"
        ))
        raise typer.Exit(code=2)

    if result.status == "FAILED":
        console.print(Panel(
            f"[bold red]Photon execution failed:[/]\n\n"
            f"{result.errors[0] if result.errors else 'Unknown execution error.'}",
            border_style="red"
        ))
        raise typer.Exit(code=1)

    table = Table(
        title=f"[bold cyan]Photon Crawl Findings for [white]{target}[/] (Status: {result.status})[/]",
        border_style="cyan"
    )
    table.add_column("Category", style="bold")
    table.add_column("Discovered Asset", style="white")
    table.add_column("Severity", justify="center")

    for f in result.findings[:100]:
        sev = f.get("severity", "info")
        sev_style = "[bold red]HIGH[/]" if sev in ("high", "critical") else (
            "[bold yellow]MEDIUM[/]" if sev == "medium" else "[dim]INFO[/]"
        )
        table.add_row(f["category"].upper(), f["item"][:80], sev_style)

    console.print(table)
    console.print(
        f"\n[bold green]✓ Discovered assets:[/] {len(result.findings)} "
        f"[dim]| Output files saved: {len(result.output_files)}[/]\n"
    )


@tools_app.command("torbot")
def torbot_command(
    target: str = typer.Argument(..., help="Target .onion URL or service to inspect."),
    depth: int = typer.Option(1, "--depth", "-d", help="Crawl depth (1-3)."),
    proxy_host: str = typer.Option("127.0.0.1", "--proxy-host", help="Tor SOCKS5 proxy IP."),
    proxy_port: int = typer.Option(9050, "--proxy-port", help="Tor SOCKS5 proxy port (default 9050 or 9150)."),
    disable_socks5: bool = typer.Option(False, "--disable-socks5", help="Bypass Tor proxy (for clearnet targets only)."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate execution without sending live network traffic."),
    timeout: int = typer.Option(60, "--timeout", help="Execution timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File to write result JSON.")
):
    """Run TorBot dark web OSINT crawler to map hidden services and link relationships."""
    adapter = registry.get_adapter("TorBot")
    if not adapter:
        console.print("[bold red]Error: TorBot adapter is not registered.[/]")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Executing TorBot against [white]{target}[/] (proxy: {proxy_host}:{proxy_port})..."):
        result = asyncio.run(adapter.run(
            target=target,
            depth=depth,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            disable_socks5=disable_socks5,
            dry_run=dry_run,
            timeout=timeout
        ))

    if json_output or output:
        json_data = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(json_data, encoding="utf-8")
            console.print(f"[bold green]✓ TorBot results written to {output}[/]")
        else:
            console.print_json(json_data)
        return

    if result.status == "BLOCKED":
        console.print(Panel(
            f"[bold red]SCOPE VIOLATION BLOCKED BY KRYPT SAFETY ENGINE[/]\n\n"
            f"{result.errors[0] if result.errors else 'Target not authorized in registered scope.'}",
            border_style="red"
        ))
        raise typer.Exit(code=2)

    if result.status == "FAILED":
        console.print(Panel(
            f"[bold red]TorBot execution failed:[/]\n\n"
            f"{result.errors[0] if result.errors else 'Execution error.'}",
            border_style="red"
        ))
        raise typer.Exit(code=1)

    table = Table(
        title=f"[bold cyan]TorBot OSINT Results for [white]{target}[/] (Status: {result.status})[/]",
        border_style="cyan"
    )
    table.add_column("Category", style="bold")
    table.add_column("Discovered Element", style="white")
    table.add_column("Details", style="dim")

    for f in result.findings[:100]:
        table.add_row(f["category"].upper(), f["item"][:80], f.get("details", ""))

    console.print(table)
    console.print(
        f"\n[bold green]✓ Discovered hidden items:[/] {len(result.findings)} "
        f"[dim]| Output files: {len(result.output_files)}[/]\n"
    )


@tools_app.command("ares")
def ares_command(
    target: str = typer.Argument("local_audit", help="Target or engagement scope identifier."),
    action: str = typer.Option("doctor", "--action", "-a", help="Safe audit action: doctor, modules, info, targets, campaigns."),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Specific module to inspect."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File to write result JSON.")
):
    """Safe audit & capability inspection via ARES Automated Red Team Engagement System."""
    adapter = registry.get_adapter("ARES")
    if not adapter:
        console.print("[bold red]Error: ARES adapter is not registered.[/]")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Executing ARES safe audit (action: [white]{action}[/])..."):
        result = asyncio.run(adapter.run(
            target=target,
            action=action,
            module_name=module
        ))

    if json_output or output:
        json_data = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(json_data, encoding="utf-8")
            console.print(f"[bold green]✓ ARES results written to {output}[/]")
        else:
            console.print_json(json_data)
        return

    if result.status == "BLOCKED":
        console.print(Panel(
            f"[bold red]SCOPE VIOLATION BLOCKED BY KRYPT SAFETY ENGINE[/]\n\n"
            f"{result.errors[0] if result.errors else 'Target not authorized in registered scope.'}",
            border_style="red"
        ))
        raise typer.Exit(code=2)

    if result.status == "FAILED":
        console.print(Panel(
            f"[bold red]ARES command failed:[/]\n\n"
            f"{result.errors[0] if result.errors else 'Execution error.'}",
            border_style="red"
        ))
        raise typer.Exit(code=1)

    table = Table(
        title=f"[bold cyan]ARES Audit Findings: action={action} (Status: {result.status})[/]",
        border_style="cyan"
    )
    table.add_column("Category", style="bold")
    table.add_column("Element / Check", style="white")
    table.add_column("Details", style="dim")

    for f in result.findings[:100]:
        table.add_row(f["category"].upper(), f["item"][:70], f.get("details", ""))

    console.print(table)
    console.print(f"\n[bold green]✓ ARES audit items:[/] {len(result.findings)} [dim]| Run ID: {result.run_id}[/]\n")
