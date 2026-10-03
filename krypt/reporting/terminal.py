"""
Terminal Reporting Engine for KRYPT CLI.
Renders rich tables, summary scorecards, and formatted finding cards.
"""

from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from krypt.database.models import FindingModel

SEVERITY_COLORS = {
    "CRITICAL": "bold red on dark_red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "bold blue",
}

SEVERITY_BADGES = {
    "CRITICAL": "[bold white on red] CRITICAL [/]",
    "HIGH": "[bold white on dark_orange] HIGH [/]",
    "MEDIUM": "[bold black on yellow] MEDIUM [/]",
    "LOW": "[bold white on blue] LOW [/]",
    "INFO": "[bold white on dim] INFO [/]",
}


class TerminalReporter:
    """Renders findings and intelligence reports to terminal using Rich."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_findings_table(self, findings: List[FindingModel], title: str = "Security Assessment Findings") -> None:
        """Display summary table of findings."""
        if not findings:
            self.console.print(Panel("[bold green]✓ No security findings identified in registered scope.[/]", title="Assessment Status", border_style="green"))
            return

        table = Table(title=f"[bold]{title}[/] ({len(findings)} total)", border_style="dim")
        table.add_column("ID", style="dim", no_wrap=True)
        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Vulnerability", style="bold")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Param", style="magenta")
        table.add_column("Confidence", justify="center")

        for f in findings:
            badge = SEVERITY_BADGES.get(f.severity, f.severity)
            table.add_row(
                f.id,
                badge,
                f.vulnerability,
                f.endpoint or "/",
                f.parameter or "-",
                f.confidence
            )

        self.console.print(table)

    def render_finding_detail(self, f: FindingModel) -> None:
        """Render single finding deep-dive card with evidence and remediation."""
        badge = SEVERITY_BADGES.get(f.severity, f.severity)
        content = f"""
[bold cyan]Target:[/]       {f.target_url}
[bold cyan]Endpoint:[/]     {f.endpoint}
[bold cyan]Parameter:[/]    {f.parameter or 'N/A'}
[bold cyan]Severity:[/]     {badge}
[bold cyan]Confidence:[/]   {f.confidence}
[bold cyan]Module:[/]       {f.module}
[bold cyan]Timestamp:[/]    {f.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

[bold underline red]Vulnerability Description & Evidence:[/]
{f.evidence or 'No detailed evidence recorded.'}

[bold underline yellow]Potential Impact:[/]
{f.impact or 'Security risk to confidentiality, integrity, or availability.'}

[bold underline green]Remediation Guidance:[/]
{f.remediation or 'Review application logic and apply secure coding principles.'}
"""
        refs = f.get_references()
        if refs:
            content += "\n[bold underline blue]References:[/]\n" + "\n".join(f"  • {r}" for r in refs)

        panel = Panel(
            content.strip(),
            title=f"[bold white on red] FINDING {f.id} [/] [bold]{f.vulnerability}[/]",
            border_style="red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
        )
        self.console.print(panel)
