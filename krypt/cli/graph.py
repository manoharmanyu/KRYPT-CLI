"""
Interactive Terminal Visualization (Tree/Graph) for KRYPT CLI.
Renders structured hierarchy of targets, subdomains, endpoints, and security findings.
"""

from typing import Optional
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from krypt.database.db import db
from krypt.safety.scope import ScopeEngine


def render_target_graph(target_input: str, console: Optional[Console] = None) -> None:
    """Render terminal visual tree of the target infrastructure and endpoints."""
    c = console or Console()
    canonical_url, host, port, scheme = ScopeEngine.normalize_target(target_input)

    # 1. Fetch data from DB
    subdomains = db.get_intelligence(target_host=host, category="Subdomain")
    endpoints = db.get_endpoints(target_url=canonical_url) or db.get_endpoints(target_url=host)
    technologies = db.get_technologies(target_url=canonical_url) or db.get_technologies(target_url=host)
    findings = db.get_findings(target=host)

    # Root Node
    root = Tree(f"[bold cyan]{host}[/]", guide_style="bold bright_blue")

    # Technologies subtree
    if technologies:
        tech_branch = root.add("[bold yellow]⚡ Technologies Identified[/]")
        for t in technologies:
            ver_str = f" ({t.version})" if t.version else ""
            tech_branch.add(f"[green]{t.name}[/]{ver_str} [dim]({t.category})[/]")

    # Subdomains and Endpoints
    subdomain_hosts = {s.key: s.value for s in subdomains}
    if not subdomain_hosts:
        subdomain_hosts[host] = "active"

    # Group endpoints by host / path
    endpoints_by_path = {}
    for ep in endpoints:
        p = ep.path or urlparse(ep.url).path or "/"
        endpoints_by_path[p] = ep

    for sub_host, status in sorted(subdomain_hosts.items()):
        sub_branch = root.add(f"[bold white]{sub_host}[/] [dim]({status})[/]")
        
        # Add paths if this is the main host
        if sub_host in (host, f"www.{host}"):
            if endpoints_by_path:
                paths_added = 0
                for path, ep in sorted(endpoints_by_path.items()):
                    if paths_added < 15:
                        param_str = f" [magenta]?{ep.parameters}[/]" if ep.parameters else ""
                        sub_branch.add(f"[cyan]{ep.method}[/] {path}{param_str}")
                        paths_added += 1
                if len(endpoints_by_path) > 15:
                    sub_branch.add(f"[dim]... and {len(endpoints_by_path) - 15} more endpoints[/]")
            else:
                sub_branch.add("[dim]/ (Root)[/]")

    # Findings subtree
    if findings:
        findings_branch = root.add(f"[bold red]⚠ Security Findings ({len(findings)})[/]")
        for f in findings:
            sev_color = "red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
            findings_branch.add(f"[{sev_color}][{f.severity}] {f.vulnerability}[/] at [cyan]{f.endpoint}[/]")

    c.print(Panel(root, title=f"[bold]Target Architecture & Attack Surface: {host}[/]", border_style="cyan"))
