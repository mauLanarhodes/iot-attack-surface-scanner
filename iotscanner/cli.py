"""CLI entry point for the installed `iotscanner` command."""

import argparse
import sys

from iotscanner import __version__
from iotscanner.scanner.discovery import get_local_subnet
from iotscanner.utils.console import console


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="iotscanner",
        description=(
            "IoT Attack Surface Scanner — discover, fingerprint, and assess\n"
            "IoT devices on your local network.\n\n"
            "QUICK START:\n"
            "  iotscanner --launch                   # Auto-detect subnet and launch\n"
            "  iotscanner --launch 192.168.1.0/24    # Launch with specific subnet\n"
            "  iotscanner --launch --passive          # Launch without active UPnP probes\n\n"
            "SHELL COMMANDS (once launched):\n"
            "  scan                 Run full network scan\n"
            "  scan --passive       Scan without active UPnP probes\n"
            "  scan --timeout=5     Scan with custom timeout (seconds)\n"
            "  devices              List all discovered devices\n"
            "  devices --json       Export devices as JSON\n"
            "  devices --filter <x> Filter by vendor or IP prefix\n"
            "  report               Save scan report to ~/.iotscanner/\n"
            "  clear                Clear the screen\n"
            "  help                 Show command reference\n"
            "  exit                 Exit the scanner"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--launch",
        nargs="?",
        const="auto",         # --launch with no argument → auto-detect
        metavar="SUBNET",
        help=(
            "Launch the interactive shell. Optionally pass a subnet "
            "(e.g. --launch 192.168.1.0/24). Omit to auto-detect."
        ),
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        default=False,
        help="Suppress active UPnP/SSDP probes during launch (passive mode).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"iotscanner v{__version__}",
    )

    return parser


def main() -> None:
    """Parse arguments and launch the scanner."""
    parser = build_parser()
    args = parser.parse_args()

    # No arguments → print concise usage hint, not the full help wall
    if len(sys.argv) == 1:
        console.print(
            "[bold cyan]iotscanner[/bold cyan] [dim]v{v}[/dim]".format(v=__version__)
        )
        console.print(
            "  [green]iotscanner --launch[/green]               "
            "[dim]Auto-detect subnet and launch[/dim]"
        )
        console.print(
            "  [green]iotscanner --launch 192.168.1.0/24[/green]  "
            "[dim]Launch with specific subnet[/dim]"
        )
        console.print(
            "  [green]iotscanner --help[/green]                 "
            "[dim]Full usage and command reference[/dim]"
        )
        console.print(
            "  [green]iotscanner --version[/green]              "
            "[dim]Print version[/dim]"
        )
        sys.exit(0)

    if args.launch is not None:
        # Resolve subnet: explicit value or auto-detect
        if args.launch == "auto":
            subnet = get_local_subnet()
            console.print(
                f"[dim]Auto-detected subnet:[/dim] [bold cyan]{subnet}[/bold cyan]"
            )
        else:
            subnet = args.launch

        # Import here to avoid slow startup on --version / --help
        from iotscanner.shell import ScannerShell
        shell = ScannerShell(subnet, passive=args.passive)
        shell.run()
    else:
        # Ran with unrecognised args or forgot --launch
        parser.print_help()
        sys.exit(1)


app = main