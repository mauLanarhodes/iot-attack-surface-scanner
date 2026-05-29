"""Rich console helpers for styled terminal output."""

from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.table import Table

console = Console()

# Palette (mirrors shell.py)
C_ACCENT = "bright_cyan"
C_DIM    = "grey50"
C_OK     = "bright_green"
C_ERR    = "bright_red"
C_WARN   = "yellow"
C_SUBTLE = "grey37"


def _format_last_seen(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now  = datetime.now(timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{int(diff // 60)}m ago"
    if diff < 86400:
        return f"{int(diff // 3600)}h ago"
    return dt.strftime("%Y-%m-%d %H:%M")


def _svc_summary(services: list | None, cap: int = 6) -> str:
    """Render a services list, capped, with a +N overflow indicator."""
    svcs = services or []
    if not svcs:
        return f"[{C_DIM}]—[/{C_DIM}]"
    if len(svcs) <= cap:
        return ", ".join(svcs)
    shown = ", ".join(svcs[:cap])
    return f"{shown} [{C_DIM}]+{len(svcs) - cap}[/{C_DIM}]"


def _port_count(dev) -> str:
    """Number of open ports as a styled string."""
    if isinstance(dev, dict):
        ports = dev.get("open_ports") or []
    else:
        ports = getattr(dev, "open_ports", None) or []
    n = len(ports)
    if n == 0:
        return f"[{C_DIM}]0[/{C_DIM}]"
    return f"[bold]{n}[/bold]"


def make_device_table(devices: list) -> Table:
    """Build a Rich Table from a list of device dicts or ORM objects."""
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {C_ACCENT}",
        border_style=C_SUBTLE,
        padding=(0, 2),
        row_styles=["", f"on grey7"],      # alternating row shading
    )
    table.add_column("IP",        style=f"bold {C_ACCENT}", no_wrap=True)
    table.add_column("MAC",       style=C_DIM,   no_wrap=True)
    table.add_column("Vendor",    style=C_OK)
    table.add_column("Hostname",  style="white")
    table.add_column("Ports",     style="white", justify="right", no_wrap=True)
    table.add_column("Services",  style=C_WARN)
    table.add_column("Last Seen", style=C_DIM,   justify="right")

    for dev in devices:
        if isinstance(dev, dict):
            ip        = dev.get("ip", "")
            mac       = dev.get("mac", "")
            vendor    = dev.get("vendor")    or f"[{C_DIM}]—[/{C_DIM}]"
            hostname  = dev.get("hostname")  or f"[{C_DIM}]—[/{C_DIM}]"
            services  = _svc_summary(dev.get("services"))
            last_seen = _format_last_seen(dev.get("last_seen"))
        else:
            ip        = dev.ip
            mac       = dev.mac
            vendor    = dev.vendor    or f"[{C_DIM}]—[/{C_DIM}]"
            hostname  = dev.hostname  or f"[{C_DIM}]—[/{C_DIM}]"
            services  = _svc_summary(dev.services)
            last_seen = _format_last_seen(dev.last_seen)

        table.add_row(ip, mac, vendor, hostname, _port_count(dev), services, last_seen)

    return table


def print_error(message: str) -> None:
    console.print(f"  [{C_ERR}]✗[/{C_ERR}]  {message}")


def print_success(message: str) -> None:
    console.print(f"  [{C_OK}]✓[/{C_OK}]  {message}")


def print_info(message: str) -> None:
    console.print(f"  [{C_ACCENT}]ℹ[/{C_ACCENT}]  {message}")