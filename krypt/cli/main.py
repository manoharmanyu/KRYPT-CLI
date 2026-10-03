"""
Main CLI Application for KRYPT CLI.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from krypt import __author__, __github__, __tagline__, __version__
from krypt.cli.banner import show_banner
from krypt.cli.doctor import run_doctor
from krypt.cli.graph import render_target_graph
from krypt.cli.target import target_app
from krypt.core.config import config
from krypt.core.integrity import IntegrityGuard
from krypt.crawler.crawler import Crawler
from krypt.crawler.endpoints import EndpointManager
from krypt.crawler.scripts import ScriptAnalyzer
from krypt.database.db import db
from krypt.evidence.store import EvidenceStore
from lab.server import LabManager
from krypt.osint.engine import OSINTEngine
from krypt.osint.sources.dns_source import DNSSource
from krypt.osint.sources.emails import EmailSource
from krypt.osint.sources.subdomains import SubdomainSource
from krypt.plugins.registry import PluginRegistry
from krypt.recon.engine import ReconEngine
from krypt.recon.headers import HeaderAnalyzer
from krypt.recon.seo import SEOAnalyzer
from krypt.recon.tech import TechFingerprinter
from krypt.reporting.generator import ReportGenerator
from krypt.reporting.terminal import TerminalReporter
from krypt.safety.scope import ScopeEngine, ScopeViolationException

app = typer.Typer(
    name="krypt",
    help="KRYPT CLI: 100% Terminal-Driven Cybersecurity Intelligence and Authorized Web-Security Assessment Framework",
    no_args_is_help=True
)

app.add_typer(target_app, name="target")

console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"[bold red]KRYPT CLI[/] version [bold white]{__version__}[/] by {__author__} ({__github__})")
        console.print(f"[dim]{__tagline__}[/]")
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show KRYPT version and exit.", callback=version_callback, is_eager=True
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Suppress the startup ASCII banner."
    ),
):
    """KRYPT CLI entrypoint."""
    if not no_banner and ctx.invoked_subcommand != "version":
        show_banner(console)


# ----------------------------------------------------
# OSINT & Domain Intelligence Commands
# ----------------------------------------------------
@app.command("osint")
def osint_command(
    domain: str = typer.Argument(..., help="Domain name or host to gather intelligence for."),
    json_output: bool = typer.Option(False, "--json", help="Output results in structured JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save JSON output.")
):
    """Aggregate multi-source OSINT intelligence (DNS, Subdomains, Emails, Certificates, RDAP)."""
    with console.status(f"[bold cyan]Harvesting OSINT intelligence for [white]{domain}[/]..."):
        engine = OSINTEngine()
        report = asyncio.run(engine.run(domain))

    if json_output or output:
        json_data = report.model_dump_json(indent=2)
        if output:
            Path(output).write_text(json_data, encoding="utf-8")
            console.print(f"[bold green]✓ OSINT report saved to {output}[/]")
        else:
            console.print_json(json_data)
        return

    # Render Terminal OSINT summary
    table_summary = Table(title=f"[bold]OSINT Intelligence Summary: {domain}[/]", border_style="cyan")
    table_summary.add_column("Category", style="bold")
    table_summary.add_column("Count", justify="center")
    table_summary.add_column("Key Highlights", style="dim")

    dns_preview = ", ".join(sorted({r.record_type for r in report.dns_records})) or "None"
    sub_preview = ", ".join([s.hostname for s in report.subdomains[:3]]) or "None"
    email_preview = ", ".join([e.email for e in report.emails[:3]]) or "None"
    cert_status = report.certificate.issuer if report.certificate else "None"

    table_summary.add_row("DNS Records", str(len(report.dns_records)), f"Types: {dns_preview}")
    table_summary.add_row("Subdomains", str(len(report.subdomains)), f"Sample: {sub_preview}")
    table_summary.add_row("Email Indicators", str(len(report.emails)), f"Sample: {email_preview}")
    table_summary.add_row("TLS Certificate", "1" if report.certificate else "0", f"Issuer: {cert_status}")

    console.print(table_summary)


@app.command("dns")
def dns_command(
    domain: str = typer.Argument(..., help="Domain name to query DNS records for.")
):
    """Query all standard DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)."""
    with console.status(f"[bold cyan]Resolving DNS records for [white]{domain}[/]..."):
        source = DNSSource()
        data = asyncio.run(source.collect(domain))

    records_dict = data.get("records", {})
    table = Table(title=f"[bold]DNS Records: {domain}[/]", border_style="cyan")
    table.add_column("Type", style="bold yellow", justify="center")
    table.add_column("Name", style="white")
    table.add_column("Value", style="cyan")
    table.add_column("TTL", style="dim", justify="center")

    found_any = False
    for rtype, items in records_dict.items():
        for rec in items:
            table.add_row(rec["type"], rec["name"], rec["value"], str(rec.get("ttl", "-")))
            found_any = True

    if found_any:
        console.print(table)
    else:
        console.print(f"[bold yellow]No DNS records resolved for {domain}[/]")


@app.command("subdomains")
def subdomains_command(
    domain: str = typer.Argument(..., help="Domain name to discover subdomains for.")
):
    """Discover subdomains and resolve IP addresses through passive OSINT and DNS."""
    with console.status(f"[bold cyan]Enumerating subdomains for [white]{domain}[/]..."):
        source = SubdomainSource()
        data = asyncio.run(source.collect(domain))

    resolved = data.get("resolved_subdomains", [])
    if not resolved:
        console.print(f"[bold yellow]No active subdomains resolved for {domain}[/]")
        return

    table = Table(title=f"[bold]Discovered Subdomains: {domain}[/] ({len(resolved)} total)", border_style="cyan")
    table.add_column("Hostname", style="bold white")
    table.add_column("Resolved IP", style="cyan")
    table.add_column("Status", justify="center")

    for item in resolved:
        table.add_row(item["hostname"], item.get("resolved_ip", "unresolved"), "[bold green]ACTIVE[/]")

    console.print(table)


@app.command("emails")
def emails_command(
    domain: str = typer.Argument(..., help="Domain name to search for public email indicators.")
):
    """Harvest public email indicators from authorized and passive indicators."""
    with console.status(f"[bold cyan]Searching public email indicators for [white]{domain}[/]..."):
        source = EmailSource()
        data = asyncio.run(source.collect(domain))

    emails = data.get("emails", [])
    if not emails:
        console.print(f"[bold yellow]No public email indicators discovered for {domain}[/]")
        return

    table = Table(title=f"[bold]Public Email Indicators: {domain}[/] ({len(emails)} total)", border_style="cyan")
    table.add_column("Email Address", style="bold green")
    table.add_column("Source", style="dim")
    table.add_column("Confidence", justify="center")

    for e in emails:
        table.add_row(e, "Public Recon / DNS", "HIGH" if domain in e else "MEDIUM")

    console.print(table)


# ----------------------------------------------------
# Web Recon & Fingerprinting Commands
# ----------------------------------------------------
@app.command("recon")
def recon_command(
    target: str = typer.Argument(..., help="Target URL to perform web reconnaissance against.")
):
    """Comprehensive web reconnaissance (HTTP/TLS, redirects, headers, robots, sitemaps, tech)."""
    with console.status(f"[bold cyan]Performing web reconnaissance on [white]{target}[/]..."):
        engine = ReconEngine()
        report = asyncio.run(engine.run(target))

    content = f"""
[bold cyan]Target URL:[/]         {report.target_url}
[bold cyan]HTTP Status:[/]        {report.status_code or 'Failed'}
[bold cyan]HTTPS Enabled:[/]      {'Yes' if report.is_https else 'No'}
[bold cyan]Server Banner:[/]      {report.server_banner or 'Hidden'}
[bold cyan]Page Title:[/]         {report.page_title or 'N/A'}
[bold cyan]Meta Description:[/]   {report.meta_description or 'N/A'}
[bold cyan]Robots.txt Rules:[/]   {len(report.robots_rules)} rules found
[bold cyan]Sitemaps Found:[/]     {len(report.sitemap_urls)} sitemaps found
[bold cyan]Security Grade:[/]     [bold yellow]{report.headers_report.grade if report.headers_report else 'N/A'}[/]
"""
    console.print(Panel(content.strip(), title=f"Reconnaissance Profile: {report.host}", border_style="cyan"))

    if report.technologies:
        tech_table = Table(title="[bold]Identified Technologies[/]", border_style="dim")
        tech_table.add_column("Technology", style="bold green")
        tech_table.add_column("Category", style="cyan")
        tech_table.add_column("Version", style="yellow")
        tech_table.add_column("Confidence", justify="center")
        for t in report.technologies:
            tech_table.add_row(t.name, t.category, t.version or "-", t.confidence)
        console.print(tech_table)


@app.command("tech")
def tech_command(
    target: str = typer.Argument(..., help="Target URL to fingerprint.")
):
    """Detect web servers, backend runtimes, frameworks, CMS, and CDN/WAF indicators."""
    with console.status(f"[bold cyan]Fingerprinting technology stack for [white]{target}[/]..."):
        from krypt.core.http import http_client
        resp = asyncio.run(http_client.get(target))
        matches = TechFingerprinter.fingerprint(target, response=resp)

    if not matches:
        console.print(f"[bold yellow]No known technology signatures matched for {target}[/]")
        return

    table = Table(title=f"[bold]Technology Fingerprint: {target}[/] ({len(matches)} identified)", border_style="cyan")
    table.add_column("Technology", style="bold green")
    table.add_column("Category", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Evidence", style="dim")

    for m in matches:
        table.add_row(m.name, m.category, m.version or "-", m.evidence[:60])

    console.print(table)


@app.command("headers")
def headers_command(
    target: str = typer.Argument(..., help="Target URL to audit security headers for.")
):
    """Audit HTTP response security headers (CSP, HSTS, XFO, XCTO) and cookie security flags."""
    with console.status(f"[bold cyan]Auditing security headers for [white]{target}[/]..."):
        from krypt.core.http import http_client
        resp = asyncio.run(http_client.get(target))
        report = HeaderAnalyzer.analyze(target, response=resp)

    # Headers table
    table = Table(title=f"[bold]Security Headers Audit: {target}[/] (Grade: [bold]{report.grade}[/] - {report.score_percentage}%)", border_style="cyan")
    table.add_column("Header Directive", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Current Value / Recommendation", style="dim")

    for h in report.header_results:
        status_str = "[bold green]PASS[/]" if h.status == "PASS" else "[bold red]FAIL[/]"
        val_str = h.value if h.status == "PASS" else f"Missing. Rec: {h.recommendation}"
        table.add_row(h.header_name, status_str, val_str)

    console.print(table)

    # Cookies table if any
    if report.cookie_results:
        c_table = Table(title="[bold]Cookie Security Flags[/]", border_style="dim")
        c_table.add_column("Cookie Name", style="bold cyan")
        c_table.add_column("HttpOnly", justify="center")
        c_table.add_column("Secure", justify="center")
        c_table.add_column("SameSite", justify="center")
        c_table.add_column("Issues", style="bold red")

        for c in report.cookie_results:
            c_table.add_row(
                c.cookie_name,
                "[green]Yes[/]" if c.has_httponly else "[red]No[/]",
                "[green]Yes[/]" if c.has_secure else "[red]No[/]",
                c.samesite or "[yellow]None[/]",
                ", ".join(c.issues) if c.issues else "[green]None[/]"
            )
        console.print(c_table)


@app.command("seo")
def seo_command(
    target: str = typer.Argument(..., help="Target URL to audit for SEO compliance, metadata, and search readiness."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format.")
):
    """Audit Search Engine Optimization (SEO) structure, metadata, social tags, and crawlability."""
    with console.status(f"[bold cyan]Auditing SEO structure for [white]{target}[/]..."):
        report = asyncio.run(SEOAnalyzer.analyze(target))

    if json_output:
        items_list = [
            {
                "category": i.category,
                "item": i.item,
                "status": i.status,
                "value": i.value,
                "details": i.details,
                "recommendation": i.recommendation,
            }
            for i in report.items
        ]
        console.print_json(json.dumps({
            "target": report.target_url,
            "score_percentage": report.score_percentage,
            "grade": report.grade,
            "title": report.title,
            "meta_description": report.meta_description,
            "canonical_url": report.canonical_url,
            "sitemap_found": report.sitemap_found,
            "has_structured_data": report.has_structured_data,
            "checks": items_list
        }, indent=2))
        return

    grade_color = "green" if report.grade in ("A+", "A") else ("yellow" if report.grade == "B" else "red")
    console.print(Panel(
        f"[bold cyan]Target URL:[/]         {report.target_url}\n"
        f"[bold cyan]SEO Score:[/]          [{grade_color} bold]{report.score_percentage}% (Grade: {report.grade})[/]\n"
        f"[bold cyan]Page Title:[/]         {report.title or 'Missing'}\n"
        f"[bold cyan]Meta Description:[/]   {report.meta_description or 'Missing'}\n"
        f"[bold cyan]Canonical URL:[/]      {report.canonical_url or 'Missing'}\n"
        f"[bold cyan]Robots Rules:[/]       {len(report.robots_rules)} active\n"
        f"[bold cyan]Sitemap Detected:[/]   {'Yes' if report.sitemap_found else 'No'}\n"
        f"[bold cyan]Structured Data:[/]    {'Yes (JSON-LD)' if report.has_structured_data else 'No'}",
        title="SEO Technical Audit Summary",
        border_style=grade_color
    ))

    table = Table(title="[bold]SEO Technical Directives & Best Practices[/]", border_style="cyan")
    table.add_column("Category", style="cyan")
    table.add_column("Audit Directive", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Observation & Recommendation", style="dim")

    for item in report.items:
        status_str = "[bold green]PASS[/]" if item.status == "PASS" else ("[bold yellow]WARN[/]" if item.status == "WARN" else "[bold red]FAIL[/]")
        detail_str = item.details
        if item.recommendation:
            detail_str += f" | Rec: {item.recommendation}"
        table.add_row(item.category, item.item, status_str, detail_str)

    console.print(table)


# ----------------------------------------------------
# Crawler, Endpoints & JavaScript Commands
# ----------------------------------------------------
@app.command("crawl")
def crawl_command(
    target: str = typer.Argument(..., help="Target URL to crawl."),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum crawl depth limit."),
    max_pages: int = typer.Option(50, "--max-pages", "-m", help="Maximum pages to process."),
    rate: float = typer.Option(10.0, "--rate", "-r", help="Maximum requests per second rate limit."),
    threads: int = typer.Option(5, "--threads", "-t", help="Concurrent worker tasks."),
    timeout: float = typer.Option(10.0, "--timeout", help="HTTP timeout per page."),
    same_origin: bool = typer.Option(True, "--same-origin/--any-origin", help="Enforce same-origin boundaries."),
    json_output: bool = typer.Option(False, "--json", help="Output crawler results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save JSON results.")
):
    """Execute controlled, asynchronous queue-based (BFS) crawl within scope."""
    with console.status(f"[bold cyan]Crawling target [white]{target}[/] (Depth={depth}, MaxPages={max_pages})..."):
        crawler = Crawler(
            max_depth=depth,
            max_pages=max_pages,
            rate_limit=rate,
            threads=threads,
            timeout=timeout,
            same_origin_only=same_origin
        )
        res = asyncio.run(crawler.crawl(target))

    if json_output or output:
        json_obj = {
            "target": res.target_url,
            "total_processed": res.total_processed,
            "internal_urls": list(res.internal_urls),
            "external_urls": list(res.external_urls),
            "endpoints": list(res.endpoints),
            "scripts": list(res.scripts),
            "parameters": list(res.parameters),
            "forms_count": res.forms_count
        }
        json_str = json.dumps(json_obj, indent=2)
        if output:
            Path(output).write_text(json_str, encoding="utf-8")
            console.print(f"[bold green]✓ Crawl dataset saved to {output}[/]")
        else:
            console.print_json(json_str)
        return

    # Terminal summary
    content = f"""
[bold cyan]Target URL:[/]         {res.target_url}
[bold cyan]Pages Processed:[/]    {res.total_processed}
[bold cyan]Internal URLs:[/]      {len(res.internal_urls)}
[bold cyan]External Links:[/]     {len(res.external_urls)}
[bold cyan]Endpoints Discovered:[/] {len(res.endpoints)}
[bold cyan]Script Files:[/]       {len(res.scripts)}
[bold cyan]Form Elements:[/]      {res.forms_count}
[bold cyan]Parameters Found:[/]   {len(res.parameters)}
"""
    console.print(Panel(content.strip(), title="Crawl Execution Summary", border_style="cyan"))


@app.command("endpoints")
def endpoints_command(
    target: str = typer.Argument(..., help="Target URL or hostname to list endpoints for.")
):
    """List normalized inventory of discovered endpoints, methods, and parameters."""
    endpoints = EndpointManager.get_target_endpoints(target)
    if not endpoints:
        console.print(f"[bold yellow]No endpoints recorded for {target}.[/] Run `krypt crawl {target}` or `krypt recon {target}` first.")
        return

    table = Table(title=f"[bold]Discovered Endpoints Inventory: {target}[/] ({len(endpoints)} total)", border_style="cyan")
    table.add_column("Method", style="bold yellow", justify="center")
    table.add_column("Path / URL", style="cyan")
    table.add_column("Parameters", style="magenta")
    table.add_column("Source", style="dim")

    for ep in endpoints:
        param_str = ", ".join(ep.parameters) if ep.parameters else "-"
        table.add_row(ep.method, ep.path, param_str, ep.discovered_from)

    console.print(table)


@app.command("scripts")
def scripts_command(
    target: str = typer.Argument(..., help="Target URL to extract and analyze JavaScript files for.")
):
    """Download in-scope JavaScript files and analyze for API routes, endpoints, and configs."""
    with console.status(f"[bold cyan]Analyzing JavaScript files on [white]{target}[/]..."):
        results = asyncio.run(ScriptAnalyzer.analyze_target_scripts(target))

    if not results:
        console.print(f"[bold yellow]No in-scope JavaScript files found on {target}[/]")
        return

    for res in results:
        table = Table(title=f"[bold]Script Analysis: {res.script_url}[/]", border_style="dim")
        table.add_column("Discovered Endpoints", style="cyan")
        table.add_column("Parameters", style="magenta")
        table.add_column("Config / Envs", style="yellow")

        eps = "\n".join(res.endpoints) or "None"
        params = "\n".join(res.parameters) or "None"
        cfgs = "\n".join(res.configurations) or "None"

        table.add_row(eps, params, cfgs)
        console.print(table)


# ----------------------------------------------------
# Security Assessment / Scanning Commands
# ----------------------------------------------------
@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="Target URL to assess for vulnerabilities."),
    all_modules: bool = typer.Option(False, "--all", "-a", help="Run all available security modules."),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Specific module to run (sqli, xss, auth, authz, idor, exposure, headers).")
):
    """Execute defensive security assessment modules against authorized target."""
    try:
        # Check fail-closed scope
        ScopeEngine.check_scope(target, is_active_assessment=True)
    except ScopeViolationException as e:
        console.print(Panel(f"[bold red]{e}[/]", title="Scope Violation", border_style="red"))
        raise typer.Exit(code=1)

    modules_to_run = []
    if all_modules or not module:
        modules_to_run = list(PluginRegistry.SECURITY_MODULES.keys())
    else:
        mod_name = module.lower()
        if mod_name not in PluginRegistry.SECURITY_MODULES:
            console.print(f"[bold red]Unknown module '{module}'.[/] Available: {', '.join(PluginRegistry.SECURITY_MODULES.keys())}")
            raise typer.Exit(code=1)
        modules_to_run = [mod_name]

    console.print(Panel(
        f"[bold cyan]Target:[/]   {target}\n"
        f"[bold cyan]Modules:[/]  {', '.join(modules_to_run)}\n"
        f"[bold cyan]Safety:[/]   [bold green]Fail-Closed Boundary Active[/]",
        title="Starting Security Assessment",
        border_style="cyan"
    ))

    scan = db.create_scan(target_url=target, module=",".join(modules_to_run))
    all_findings = []

    for mod_name in modules_to_run:
        mod_instance = PluginRegistry.get_security_module(mod_name)
        if mod_instance:
            with console.status(f"[bold cyan]Executing assessment module: [yellow]{mod_instance.name}[/]..."):
                findings = asyncio.run(mod_instance.run(target, scan_id=scan.id))
                all_findings.extend(findings)

    db.complete_scan(scan.id, len(all_findings))

    console.print()
    reporter = TerminalReporter(console=console)
    reporter.render_findings_table(all_findings, title=f"Scan Findings for {target}")


@app.command("findings")
def findings_command(
    action: Optional[str] = typer.Argument(None, help="Action: 'show' to view finding details."),
    finding_id: Optional[str] = typer.Argument(None, help="Finding ID when using 'show' action."),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (critical, high, medium, low, info)."),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target hostname or URL.")
):
    """View and query recorded security assessment findings."""
    reporter = TerminalReporter(console=console)

    if action == "show" or (finding_id and not action):
        target_id = finding_id or action
        finding = db.get_finding_by_id(target_id)
        if not finding:
            console.print(f"[bold red]Finding '{target_id}' not found.[/]")
            raise typer.Exit(code=1)
        reporter.render_finding_detail(finding)
        return

    findings = db.get_findings(severity=severity, target=target)
    reporter.render_findings_table(findings, title="Recorded Security Findings Catalog")


@app.command("evidence")
def evidence_command(
    finding_id: str = typer.Argument(..., help="Finding ID to inspect evidence records for.")
):
    """Inspect verifiable, redacted HTTP evidence attached to a finding."""
    finding = db.get_finding_by_id(finding_id)
    if not finding:
        console.print(f"[bold red]Finding '{finding_id}' not found.[/]")
        raise typer.Exit(code=1)

    evidence_records = EvidenceStore.get_evidence(finding_id)
    console.print(Panel(
        f"[bold cyan]Finding ID:[/]      {finding.id}\n"
        f"[bold cyan]Vulnerability:[/]   {finding.vulnerability}\n"
        f"[bold cyan]Endpoint:[/]        {finding.endpoint}\n"
        f"[bold cyan]Evidence Records:[/] {len(evidence_records)}",
        title="Evidence Trail Inspection",
        border_style="cyan"
    ))

    for idx, ev in enumerate(evidence_records, 1):
        content = f"""
[bold yellow]Evidence Record #{idx}[/] &bull; [dim]{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}[/]
[bold cyan]Type:[/] {ev.evidence_type}

[bold underline]Summary Observation:[/]
{ev.redacted_data}

[bold underline]Raw Transaction Metadata (Redacted):[/]
{ev.raw_data}
"""
        console.print(Panel(content.strip(), border_style="dim"))


# ----------------------------------------------------
# Reporting Commands
# ----------------------------------------------------
@app.command("report")
def report_command(
    format_type: str = typer.Option("terminal", "--format", "-f", help="Report format: terminal, json, html, pdf, md, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Custom output file destination path."),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity level."),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Filter by target URL or host.")
):
    """Generate comprehensive security assessment reports in multiple formats."""
    try:
        dest = ReportGenerator.generate(
            target_url=target,
            severity=severity,
            format_type=format_type,
            output_path=output,
            console=console
        )
        if dest:
            console.print(f"[bold green]✓ Security assessment report generated successfully:[/] [white underline]{dest}[/]")
    except Exception as e:
        console.print(f"[bold red]Report generation failed:[/] {e}")
        raise typer.Exit(code=1)


# ----------------------------------------------------
# Laboratory Lifecycle Commands
# ----------------------------------------------------
lab_app = typer.Typer(help="Manage the local intentionally vulnerable training laboratory.")
app.add_typer(lab_app, name="lab")


@lab_app.command("start")
def lab_start(
    port: int = typer.Option(8888, "--port", "-p", help="Port for the test laboratory."),
    mode: str = typer.Option("vulnerable", "--mode", "-m", help="Laboratory mode: 'vulnerable' (training) or 'hardened' (zero-vulnerability / crackproof).")
):
    """Start the training laboratory on localhost (vulnerable or hardened)."""
    success, msg = LabManager.start(port=port, mode=mode)
    if success:
        mode_label = "[bold red]VULNERABLE (TRAINING)[/]" if mode.lower() == "vulnerable" else "[bold green]HARDENED (ZERO-VULNERABILITY / SECURE)[/]"
        console.print(Panel(
            f"[bold green]{msg}[/]\n"
            f"[bold cyan]Security Profile:[/] {mode_label}\n\n"
            f"Add to scope to test:\n`krypt target add http://127.0.0.1:{port}`",
            title="Training Laboratory",
            border_style="green"
        ))
    else:
        console.print(f"[bold red]{msg}[/]")


@lab_app.command("stop")
def lab_stop():
    """Stop the running training laboratory process."""
    success, msg = LabManager.stop()
    if success:
        console.print(f"[bold green]✓ {msg}[/]")
    else:
        console.print(f"[bold red]{msg}[/]")


@lab_app.command("status")
def lab_status(
    port: int = typer.Option(8888, "--port", "-p", help="Port to check.")
):
    """Check if the training laboratory is running and responsive."""
    stat = LabManager.status(port=port)
    status_str = "[bold green]RUNNING & RESPONSIVE[/]" if stat["responsive"] else ("[bold yellow]PROCESS ALIVE (NOT RESPONSIVE)[/]" if stat["running"] else "[bold red]STOPPED[/]")
    console.print(Panel(
        f"[bold cyan]Status:[/]   {status_str}\n"
        f"[bold cyan]PID:[/]      {stat['pid'] or 'N/A'}\n"
        f"[bold cyan]URL:[/]      {stat['url']}\n"
        f"[bold cyan]Message:[/]  {stat['message']}",
        title="Laboratory Lifecycle Status",
        border_style="cyan"
    ))


@lab_app.command("verify")
def lab_verify(
    port: int = typer.Option(8888, "--port", "-p", help="Port to verify.")
):
    """Run automated health-check smoke tests against all laboratory vulnerability endpoints."""
    with console.status(f"[bold cyan]Verifying laboratory endpoints on port {port}..."):
        res = LabManager.verify(port=port)

    table = Table(title=f"[bold]Laboratory Health & Route Verification ({res['base_url']})[/]", border_style="cyan")
    table.add_column("Vulnerable Route / Feature", style="bold")
    table.add_column("Path", style="cyan")
    table.add_column("Expected Status", justify="center")
    table.add_column("Actual Status", justify="center")
    table.add_column("Result", justify="center")

    for t in res["results"]:
        status_badge = "[bold green]PASS[/]" if t["status"] == "PASS" else "[bold red]FAIL[/]"
        table.add_row(t["test"], t["path"], str(t["expected"]), str(t["actual"] or "ERR"), status_badge)

    console.print(table)
    if res["all_passed"]:
        console.print("[bold green]✓ All laboratory test cases verified and operational.[/]")
    else:
        console.print("[bold yellow]⚠ Some laboratory test endpoints did not respond as expected. Ensure `krypt lab start` is running.[/]")


# ----------------------------------------------------
# Plugins, Config, Doctor & Graph Commands
# ----------------------------------------------------
plugins_app = typer.Typer(help="Inspect extensible KRYPT plugin architecture.")
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def list_plugins():
    """List all available OSINT, Web Recon, and Security assessment plugins."""
    all_p = PluginRegistry.list_all()
    for cat, items in all_p.items():
        table = Table(title=f"[bold]{cat} Modules[/]", border_style="cyan")
        table.add_column("Plugin / Module", style="bold green", no_wrap=True)
        table.add_column("Description", style="white")
        for it in items:
            table.add_row(it["name"], it["description"])
        console.print(table)


@plugins_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Module name to inspect.")
):
    """Inspect detailed capabilities and parameters of a security module."""
    mod = PluginRegistry.get_security_module(name)
    if not mod:
        console.print(f"[bold red]Plugin '{name}' not found in registry.[/]")
        raise typer.Exit(code=1)

    content = f"""
[bold cyan]Module Name:[/]   {mod.name}
[bold cyan]Category:[/]      SECURITY
[bold cyan]Description:[/]   {mod.description}
[bold cyan]Scope Check:[/]   Fail-Closed Target Scope Enforcement
"""
    console.print(Panel(content.strip(), title=f"Plugin Info: {mod.name}", border_style="cyan"))


config_app = typer.Typer(help="Manage runtime configuration (~/.krypt/config.yaml).")
app.add_typer(config_app, name="config")


@config_app.callback(invoke_without_command=True)
def config_root(ctx: typer.Context):
    """Show current configuration if no subcommand given."""
    if ctx.invoked_subcommand is None:
        console.print(Panel(json.dumps(config.data, indent=2), title="KRYPT Active Configuration", border_style="cyan"))


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key path (e.g. 'socks5.enabled').")
):
    """Get configuration value."""
    val = config.get(key)
    console.print(f"[bold cyan]{key}:[/] {val}")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key path (e.g. 'socks5.enabled')."),
    value: str = typer.Argument(..., help="New value.")
):
    """Set configuration value and save to disk."""
    config.set(key, value)
    console.print(f"[bold green]✓ Updated configuration:[/] [bold cyan]{key}[/] = [white]{config.get(key)}[/]")


@app.command("doctor")
def doctor_command():
    """Run comprehensive environment diagnostics and health checks."""
    run_doctor(console=console)


@app.command("graph")
def graph_command(
    target: str = typer.Argument(..., help="Target URL or domain to visualize in terminal graph.")
):
    """Render terminal tree and attack surface graph for target."""
    render_target_graph(target, console=console)


@app.command("integrity")
def integrity_command(
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate or update cryptographic SHA-256 integrity baseline manifest."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format.")
):
    """Cryptographic code integrity & anti-tamper verification (hackproof & crackproof check)."""
    if generate:
        manifest = IntegrityGuard.generate_manifest()
        if json_output:
            console.print_json(data=manifest)
        else:
            console.print(Panel(
                f"[bold green]✓ Cryptographic integrity baseline generated successfully![/]\n\n"
                f"[bold cyan]Algorithm:[/]        {manifest['algorithm']}\n"
                f"[bold cyan]Files Tracked:[/]    {manifest['file_count']} source files\n"
                f"[bold cyan]Master Signature:[/] [white]{manifest['master_signature']}[/]\n"
                f"[bold cyan]Generated At:[/]     {manifest['generated_at']}",
                title="Integrity Manifest Generator",
                border_style="green"
            ))
        return

    stat = IntegrityGuard.verify_integrity()
    if json_output:
        console.print_json(data=stat)
        return

    if stat["is_intact"]:
        console.print(Panel(
            f"[bold green]✓ FRAMEWORK INTEGRITY VERIFIED (CRACKPROOF & TAMPER-FREE)[/]\n\n"
            f"[bold cyan]Status:[/]            [bold green]SECURE & AUTHENTIC[/]\n"
            f"[bold cyan]Algorithm:[/]         {stat['algorithm']}\n"
            f"[bold cyan]Total Modules:[/]     {stat['total_files']} files verified intact (0 tampered)\n"
            f"[bold cyan]Master Signature:[/]  [white]{stat['master_signature']}[/]\n"
            f"[bold cyan]Baseline Date:[/]     {stat['manifest_date']}\n\n"
            f"[dim]All core safety scope guards, validators, scanners, and redactors match official cryptographic signatures.[/]",
            title="KRYPT Anti-Tamper & Code Integrity Guard",
            border_style="green"
        ))
    else:
        table = Table(title="[bold red]TAMPER OR CRACK ATTEMPT DETECTED[/]", border_style="red")
        table.add_column("Anomaly Type", style="bold red")
        table.add_column("File Path", style="cyan")
        table.add_column("Details", style="yellow")

        for item in stat.get("tampered", []):
            table.add_row("MODIFIED / CRACKED", item["file"], f"Hash mismatch! Expected {item['expected']} vs Actual {item['actual']}")
        for f in stat.get("missing", []):
            table.add_row("MISSING FILE", f, "Required security module has been removed")
        for f in stat.get("added", []):
            table.add_row("UNAUTHORIZED FILE", f, "Untracked or injected payload script detected")

        console.print(table)
        console.print("[bold red]CRITICAL: Framework code integrity check failed! Code may be tampered with.[/]")
        raise typer.Exit(code=1)


@app.command("verify-integrity", hidden=True)
def verify_integrity_alias(
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate or update cryptographic SHA-256 integrity baseline manifest."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format.")
):
    """Alias for krypt integrity."""
    integrity_command(generate=generate, json_output=json_output)


def main():
    """CLI Entrypoint wrapper."""
    app()


if __name__ == "__main__":
    main()
