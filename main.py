#!/usr/bin/env python3
"""
IoT Attack Surface Scanner — Main entry point.

Usage:
    python3 main.py 192.168.1.0/24              # Interactive shell
    python3 main.py 192.168.1.0/24 -c scan      # Run one command and exit
    python3 main.py 192.168.1.0/24 --command devices
"""

import argparse
import sys

from iotscanner import __version__
from iotscanner.scanner.discovery import get_local_subnet
from iotscanner.shell import ScannerShell
from iotscanner.utils.console import console


def main():
    """Parse arguments and launch scanner."""
    parser = argparse.ArgumentParser(
        prog="python3 main.py",
        description="IoT Attack Surface Scanner — discover and fingerprint devices on your network",
        add_help=True,
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

    # If no subnet, show usage
    if args.subnet is None:
        console.print("[bold cyan]IoT Attack Surface Scanner[/bold cyan]")
        console.print(__doc__)
        parser.print_help()
        sys.exit(0)

    subnet = args.subnet

    # Launch shell
    shell = ScannerShell(subnet)

    if args.command:
        # One-shot mode: run command and exit
        shell.run_command(args.command)
    else:
        # Interactive mode
        shell.run()


if __name__ == "__main__":
    main()
