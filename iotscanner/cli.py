"""CLI entry point for the installed `iotscanner` command."""

import argparse
import sys

from iotscanner import __version__
from iotscanner.scanner.discovery import get_local_subnet
from iotscanner.shell import ScannerShell
from iotscanner.utils.console import console


def main() -> None:
    """Parse arguments and launch the scanner."""
    parser = argparse.ArgumentParser(
        prog="iotscanner",
        description="IoT Attack Surface Scanner — discover and fingerprint devices on your network",
    )
    parser.add_argument(
        "subnet",
        nargs="?",
        default=None,
        help="Target subnet (e.g., 192.168.1.0/24). If omitted, auto-detect local subnet.",
    )
    parser.add_argument(
        "-c",
        "--command",
        type=str,
        default=None,
        help="Run a single command and exit (e.g., 'scan', 'devices')",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"iotscanner v{__version__}",
    )

    args = parser.parse_args()

    if args.subnet is None and len(sys.argv) == 1:
        console.print("[bold cyan]IoT Attack Surface Scanner[/bold cyan]")
        console.print("Usage: iotscanner <subnet> [-c COMMAND]")
        console.print("Example: iotscanner 192.168.1.0/24")
        console.print("Run 'iotscanner --help' for more options.")
        sys.exit(0)

    subnet = args.subnet if args.subnet else get_local_subnet()

    shell = ScannerShell(subnet)
    if args.command:
        shell.run_command(args.command)
    else:
        shell.run()


app = main
