"""Rich console helpers for styled terminal output."""

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _format_last_seen(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    now = datetime.now(timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{int(diff // 60)}m ago"
    if diff < 86400:
        return f"{int(diff // 3600)}h ago"
    return dt.strftime("%Y-%m-%d %H:%M")


def make_device_table(devices: list) -> Table:
    """Build a Rich Table from a list of device dicts or ORM objects."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="dim")
    table.add_column("Vendor", style="green")
    table.add_column("Hostname", style="white")
    table.add_column("Services", style="yellow")
    table.add_column("Last Seen", style="dim")

    for dev in devices:
        if isinstance(dev, dict):
            ip = dev.get("ip", "")
            mac = dev.get("mac", "")
            vendor = dev.get("vendor") or "[dim]Unknown[/dim]"
            hostname = dev.get("hostname") or "[dim]-[/dim]"
            services = ", ".join(dev.get("services") or [])
            last_seen = _format_last_seen(dev.get("last_seen"))
        else:
            ip = dev.ip
            mac = dev.mac
            vendor = dev.vendor or "[dim]Unknown[/dim]"
            hostname = dev.hostname or "[dim]-[/dim]"
            services = ", ".join(dev.services or [])
            last_seen = _format_last_seen(dev.last_seen)

        table.add_row(ip, mac, vendor, hostname, services, last_seen)

    return table


def print_scan_summary(device_count: int, duration_seconds: float, new_count: int):
    """Print a styled summary panel after scan completes."""
    msg = (
        f"[bold green]Scan complete[/bold green] — "
        f"{device_count} devices found ({new_count} new) in {duration_seconds:.1f}s"
    )
    console.print(Panel(msg, expand=False))


def print_error(message: str):
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_success(message: str):
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str):
    console.print(f"[bold blue]ℹ[/bold blue] {message}")
