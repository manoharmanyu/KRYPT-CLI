"""
Target Scope Management CLI commands for KRYPT CLI.
"""

from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from krypt.core.logger import audit_log
from krypt.database.db import db
from krypt.safety.scope import ScopeEngine

target_app = typer.Typer(help="Manage authorized target scope boundaries.")
console = Console()


@target_app.command("add")
def add_target(
    target: str = typer.Argument(..., help="Target URL, hostname, or IP address to authorize."),
    notes: str = typer.Option("", "--notes", "-n", help="Authorization notes or engagement context.")
):
    """Register and authorize a new target for security assessment."""
    try:
        t = db.add_target(target, notes=notes)
        audit_log("TARGET_REGISTER", t.url, "AUTHORIZED", notes)
        console.print(Panel(
            f"[bold green]✓ Target successfully registered in authorized scope:[/]\n\n"
            f"[bold cyan]URL:[/]      {t.url}\n"
            f"[bold cyan]Host:[/]     {t.host}\n"
            f"[bold cyan]Port:[/]     {t.port}\n"
            f"[bold cyan]Scheme:[/]   {t.scheme}\n"
            f"[bold cyan]Status:[/]   [bold green]{t.scope_status}[/]\n"
            f"[bold cyan]Notes:[/]    {t.notes or 'None'}",
            title="Target Authorization Granted",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[bold red]Error adding target:[/] {e}")
        raise typer.Exit(code=1)


@target_app.command("list")
def list_targets():
    """List all registered and authorized targets."""
    targets = db.list_targets()
    if not targets:
        console.print(Panel("[bold yellow]No authorized targets registered.[/]\nRegister a target using: `krypt target add <target>`", title="Target Scope", border_style="yellow"))
        return

    table = Table(title=f"[bold]Authorized Target Scope Inventory[/] ({len(targets)} targets)", border_style="cyan")
    table.add_column("ID", style="dim", justify="center")
    table.add_column("Canonical URL", style="bold cyan")
    table.add_column("Host", style="white")
    table.add_column("Port", justify="center")
    table.add_column("Scope Status", justify="center")
    table.add_column("Created", style="dim")

    for t in targets:
        table.add_row(
            str(t.id),
            t.url,
            t.host,
            str(t.port),
            f"[bold green]{t.scope_status}[/]" if t.is_active else "[dim red]INACTIVE[/]",
            t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else "-"
        )

    console.print(table)


@target_app.command("remove")
def remove_target(
    target: str = typer.Argument(..., help="Target URL or hostname to remove from scope.")
):
    """Remove target authorization from scope."""
    removed = db.remove_target(target)
    if removed:
        audit_log("TARGET_DEAUTHORIZE", target, "REMOVED", "Target deauthorized from scope")
        console.print(f"[bold green]✓ Target '{target}' removed from authorized scope.[/]")
    else:
        console.print(f"[bold yellow]Target '{target}' was not found in registered scope.[/]")


@target_app.command("info")
def target_info(
    target: str = typer.Argument(..., help="Target URL or hostname to inspect.")
):
    """View deep-dive telemetry and findings for an authorized target."""
    t = db.get_target(target)
    if not t:
        console.print(f"[bold red]Target '{target}' is not registered.[/] Use `krypt target add {target}` first.")
        raise typer.Exit(code=1)

    endpoints = db.get_endpoints(t.url)
    findings = db.get_findings(target=t.host)
    techs = db.get_technologies(t.url)

    content = f"""
[bold cyan]URL:[/]               {t.url}
[bold cyan]Host:[/]              {t.host}
[bold cyan]Port:[/]              {t.port}
[bold cyan]Status:[/]            [bold green]{t.scope_status}[/]
[bold cyan]Discovered Endpoints:[/] {len(endpoints)}
[bold cyan]Security Findings:[/]    {len(findings)}
[bold cyan]Technologies:[/]        {', '.join([x.name for x in techs]) or 'None identified'}
[bold cyan]Notes:[/]               {t.notes or 'N/A'}
"""
    console.print(Panel(content.strip(), title=f"Target Profile: {t.host}", border_style="cyan"))
