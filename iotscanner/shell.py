"""Interactive REPL shell for iotscanner — Osintgram-style pattern."""

import asyncio
import json
import readline
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from sqlalchemy import select

from iotscanner.db.models import Device
from iotscanner.db.session import get_session
from iotscanner.scanner.discovery import DiscoveredDevice, run_discovery
from iotscanner.scanner.fingerprint import fingerprint_all
from iotscanner.utils.console import (
    console,
    make_device_table,
    print_error,
    print_info,
    print_success,
)


# ASCII Banner
BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          IoT Attack Surface Scanner — Interactive Shell                      ║
║                                                                              ║
║     Discover, fingerprint, and assess IoT devices on your network            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class ScannerShell:
    """Interactive REPL shell for network scanning and device management."""

    def __init__(self, subnet: str):
        """Initialize shell with target subnet."""
        self.subnet = subnet
        self.discovered_devices: list[DiscoveredDevice] = []
        self.scan_results: list[dict] = []
        self._in_interactive_mode = False
        self.command_map = {
            "scan": self.cmd_scan,
            "devices": self.cmd_devices,
            "ports": self.cmd_ports,
            "vuln": self.cmd_vuln,
            "report": self.cmd_report,
            "clear": self.cmd_clear,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
        }

    def run(self):
        """Main REPL loop."""
        self._in_interactive_mode = True
        console.print(BANNER)
        console.print(f"[bold cyan]Target:[/bold cyan] {self.subnet}\n")

        # Set up tab completion
        self._setup_completion()

        while True:
            try:
                prompt = f"[{self.subnet}] > "
                user_input = input(prompt).strip()
            except KeyboardInterrupt:
                console.print()  # New line after ^C
                continue
            except EOFError:
                # Ctrl+D
                self.cmd_exit()
                break

            if not user_input:
                continue

            self._dispatch_command(user_input)

    def run_command(self, command_str: str):
        """Run a single command and exit (for --command/-c mode)."""
        self._dispatch_command(command_str)

    def _setup_completion(self):
        """Set up readline tab completion for command names."""
        commands = list(self.command_map.keys())

        def completer(text, state):
            options = [cmd for cmd in commands if cmd.startswith(text)]
            if state < len(options):
                return options[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    def _dispatch_command(self, user_input: str):
        """Parse and dispatch a command to its handler."""
        try:
            parts = shlex.split(user_input)
        except ValueError as e:
            print_error(f"Parse error: {e}")
            return

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        if cmd in self.command_map:
            try:
                self.command_map[cmd](*args)
            except Exception as e:
                print_error(f"Command failed: {e}")
        else:
            print_error(f"Unknown command: '{cmd}'. Type 'help' for a list.")

    # Command handlers
    def cmd_scan(self, *args):
        """Scan the network for IoT devices."""
        timeout = 2
        passive = False

        # Parse optional arguments
        for arg in args:
            if arg.startswith("--timeout="):
                try:
                    timeout = int(arg.split("=")[1])
                except ValueError:
                    print_error("Invalid timeout value")
                    return
            elif arg == "--passive":
                passive = True

        print_info(f"Scanning {self.subnet}...")
        start = time.time()

        try:
            # Run discovery
            with console.status(f"[bold blue]Scanning {self.subnet}...", spinner="dots"):
                self.discovered_devices = asyncio.run(
                    run_discovery(self.subnet, timeout=timeout, passive=passive)
                )

            if not self.discovered_devices:
                print_info("No devices found.")
                return

            # Run fingerprinting
            with console.status("[bold blue]Fingerprinting devices...", spinner="dots"):
                device_dicts = asyncio.run(fingerprint_all(self.discovered_devices))

            # Filter out devices with empty MAC
            device_dicts = [d for d in device_dicts if d.get("mac")]
            self.scan_results = device_dicts

            duration = time.time() - start

            # Display results
            table = make_device_table(device_dicts)
            console.print(table)

            # Save to database
            new_count = self._upsert_devices(device_dicts)
            console.print(
                f"\n[bold green]✓[/bold green] Scan complete — "
                f"{len(device_dicts)} devices found ({new_count} new) in {duration:.1f}s\n"
            )
        except Exception as e:
            print_error(f"Scan failed: {e}")

    def cmd_devices(self, *args):
        """List all known devices from the database."""
        as_json = "--json" in args
        filter_text = None

        for i, arg in enumerate(args):
            if arg == "--filter" and i + 1 < len(args):
                filter_text = args[i + 1]

        try:
            with get_session() as session:
                query = select(Device).order_by(Device.last_seen.desc())
                results = session.execute(query).scalars().all()

                if filter_text:
                    filter_lower = filter_text.lower()
                    results = [
                        d for d in results
                        if (d.vendor and filter_lower in d.vendor.lower())
                        or (d.ip and d.ip.startswith(filter_text))
                    ]

                if not results:
                    print_info("No devices found in database.")
                    return

                if as_json:
                    json_data = []
                    for d in results:
                        json_data.append({
                            "ip": d.ip,
                            "mac": d.mac,
                            "hostname": d.hostname,
                            "vendor": d.vendor,
                            "friendly_name": d.friendly_name,
                            "model_name": d.model_name,
                            "manufacturer": d.manufacturer,
                            "services": d.services,
                            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
                            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                        })
                    console.print_json(json.dumps(json_data, default=str))
                else:
                    table = make_device_table(results)
                    console.print(table)
        except Exception as e:
            print_error(f"Failed to list devices: {e}")

    def cmd_ports(self, *args):
        """Show open ports for a specific device (placeholder for Stage 2)."""
        if not args:
            print_error("Usage: ports <ip>")
            return

        ip = args[0]
        print_info(f"Port scanning for {ip} — coming in Stage 2 (port probing)")

    def cmd_vuln(self, *args):
        """Run vulnerability assessment on a device (placeholder for Stage 3)."""
        if not args:
            print_error("Usage: vuln <ip>")
            return

        ip = args[0]
        print_info(f"Vulnerability assessment for {ip} — coming in Stage 3 (CVE correlation)")

    def cmd_report(self, *args):
        """Generate and export the full scan report."""
        if not self.scan_results:
            print_info("No scan results to report. Run 'scan' first.")
            return

        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = Path.home() / ".iotscanner" / f"report_{timestamp}.json"
            output_path.parent.mkdir(exist_ok=True)

            json_data = []
            for d in self.scan_results:
                entry = dict(d)
                json_data.append(entry)

            output_path.write_text(json.dumps(json_data, indent=2, default=str))
            print_success(f"Report saved to {output_path}")
        except Exception as e:
            print_error(f"Failed to generate report: {e}")

    def cmd_clear(self, *args):
        """Clear the terminal screen."""
        console.clear()

    def cmd_help(self, *args):
        """Show all available commands."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Command", style="green")
        table.add_column("Description", style="white")

        commands_help = [
            ("scan", "Run full network scan on the loaded subnet"),
            ("devices", "List all discovered devices from database"),
            ("ports <ip>", "Show open ports for a specific device"),
            ("vuln <ip>", "Run vulnerability assessment on a device"),
            ("report", "Generate and export the full scan report"),
            ("clear", "Clear the terminal screen"),
            ("help", "Show this command table"),
            ("exit", "Exit the scanner"),
        ]

        for cmd, desc in commands_help:
            table.add_row(cmd, desc)

        console.print(table)
        console.print()

    def cmd_exit(self, *args):
        """Exit the scanner gracefully."""
        if self._in_interactive_mode:
            console.print("[bold cyan]Goodbye![/bold cyan]")
        sys.exit(0)

    # Database helper
    def _upsert_devices(self, device_dicts: list[dict]) -> int:
        """Upsert devices into the database. Returns count of newly inserted devices."""
        from iotscanner.db.models import Device

        new_count = 0
        now = datetime.now(timezone.utc)

        with get_session() as session:
            for d in device_dicts:
                existing = session.execute(
                    select(Device).where(Device.mac == d["mac"])
                ).scalar_one_or_none()

                if existing:
                    for key, value in d.items():
                        if key not in ("mac",) and value is not None:
                            setattr(existing, key, value)
                    existing.last_seen = now
                else:
                    device = Device(
                        **d,
                        first_seen=now,
                        last_seen=now,
                    )
                    session.add(device)
                    new_count += 1

        return new_count
