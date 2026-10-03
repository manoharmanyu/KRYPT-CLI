"""
ASCII Banner and Styling for KRYPT CLI.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from krypt import __author__, __github__, __tagline__, __version__
from krypt.core.config import config

BANNER_ART = r"""
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
██║  ██╗██║  ██║   ██║   ██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
"""


def show_banner(console: Console, verbose: bool = True) -> None:
    """Print the official KRYPT CLI banner and runtime environment badges."""
    is_socks5 = config.get("socks5.enabled", False)
    socks5_badge = "[bold green]SOCKS5: ENABLED[/]" if is_socks5 else "[dim]SOCKS5: DISABLED[/]"
    safety_badge = "[bold cyan]FAIL-CLOSED SAFETY: ACTIVE[/]"

    banner_text = f"""[bold red]{BANNER_ART}[/]
             [bold white]KRYPT CLI v{__version__}[/]
   [bold cyan]{__tagline__}[/]

[dim]Created by {__author__} ({__github__})[/]
{safety_badge}  •  {socks5_badge}
"""
    console.print(banner_text)
