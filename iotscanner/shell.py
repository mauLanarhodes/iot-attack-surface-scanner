"""Interactive REPL shell — IoT Attack Surface Scanner."""

import asyncio
import json
import os
import readline
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from sqlalchemy import select

from iotscanner import __version__
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


# ── Palette ────────────────────────────────────────────────────────────────────
C_ACCENT   = "bright_cyan"
C_DIM      = "grey50"
C_WARN     = "yellow"
C_OK       = "bright_green"
C_ERR      = "bright_red"
C_SUBTLE   = "grey37"
C_TITLE    = "bold bright_white"


# ── Banner ─────────────────────────────────────────────────────────────────────
_LOGO = """\
 ██╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗
 ██║██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
 ██║██║   ██║   ██║       ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝
 ██║██║   ██║   ██║       ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗
 ██║╚██████╔╝   ██║       ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
 ╚═╝ ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝"""


def _render_banner(subnet: str, passive: bool) -> None:
    """Print the full startup banner."""
    console.print()

    # Logo in accent colour
    console.print(Text(_LOGO, style=f"bold {C_ACCENT}"))

    # Tagline + version strip
    console.print()
    tagline = Text()
    tagline.append("  Attack Surface Scanner", style=f"bold {C_TITLE}")
    tagline.append(f"  v{__version__}", style=C_DIM)
    tagline.append("  ·  ", style=C_SUBTLE)
    tagline.append("IoT Security Research Tool", style=C_DIM)
    console.print(tagline)

    console.print(Rule(style=C_SUBTLE))

    # Status row
    mode_label = "[yellow]PASSIVE[/yellow]" if passive else f"[{C_OK}]ACTIVE[/{C_OK}]"
    console.print(
        f"  [{C_DIM}]Target[/{C_DIM}]  [{C_ACCENT}]{subnet}[/{C_ACCENT}]"
        f"   [{C_DIM}]Mode[/{C_DIM}]  {mode_label}"
        f"   [{C_DIM}]DB[/{C_DIM}]  [{C_DIM}]~/.iotscanner/scanner.db[/{C_DIM}]"
    )

    console.print(Rule(style=C_SUBTLE))

    # Quick-start hint
    hint = Text("  Type ", style=C_DIM)
    hint.append("scan", style=f"bold {C_OK}")
    hint.append(" to start  ·  ", style=C_DIM)
    hint.append("help", style=f"bold {C_OK}")
    hint.append(" for all commands  ·  ", style=C_DIM)
    hint.append("exit", style=f"bold {C_OK}")
    hint.append(" to quit", style=C_DIM)
    console.print(hint)
    console.print()


# ── Help table ─────────────────────────────────────────────────────────────────
_HELP_ROWS = [
    ("scan",                 "Default scan — ~55 consumer IoT ports (~10s)",     ""),
    ("scan --fast",          "Quick scan — ~25 ports (~5s)",                     ""),
    ("scan --deep",          "Deep scan — 169 ports incl. OT/industrial (~35s)", ""),
    ("scan --full",          "Exhaustive — all 65,535 ports (minutes)",          ""),
    ("scan --ports=<spec>",  "Custom ports, e.g. 22,80,443 or 1-1024",           ""),
    ("scan --passive",       "Skip active ICMP/SYN/SSDP probes",                 ""),
    ("scan --timeout=<sec>", "Override per-probe timeout",                       ""),
    ("devices",              "List all discovered devices from database",         ""),
    ("devices --json",       "Export devices as JSON (incl. open ports)",        ""),
    ("devices --filter <x>", "Filter by vendor name or IP prefix",               ""),
    ("report",               "Save last scan to ~/.iotscanner/report_*.json",    ""),
    ("clear",                "Clear the terminal screen",                         ""),
    ("help",                 "Show this reference",                               ""),
    ("exit / quit",          "Exit the scanner",                                  ""),
    # Stubs
    ("ports <ip>",           "Per-device port detail view",                      "Stage 2"),
    ("vuln  <ip>",           "CVE assessment for a device",                      "Stage 3"),
]


def _render_help() -> None:
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {C_ACCENT}",
        border_style=C_SUBTLE,
        padding=(0, 2),
    )
    table.add_column("Command",     style=f"bold {C_OK}", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Status",      style=C_WARN, justify="right")

    for cmd, desc, status in _HELP_ROWS:
        table.add_row(cmd, desc, status)

    console.print()
    console.print(
        Panel(table, title="[bold]Command Reference[/bold]",
              border_style=C_SUBTLE, padding=(0, 1))
    )
    console.print()


# ── Shell ──────────────────────────────────────────────────────────────────────
class ScannerShell:
    """Interactive REPL shell for network scanning and device management."""

    def __init__(self, subnet: str, passive: bool = False):
        self.subnet  = subnet
        self.passive = passive
        self.discovered_devices: list[DiscoveredDevice] = []
        self.scan_results: list[dict] = []
        self._in_interactive_mode = False

        self.command_map = {
            "scan":    self.cmd_scan,
            "devices": self.cmd_devices,
            "ports":   self.cmd_ports,
            "vuln":    self.cmd_vuln,
            "report":  self.cmd_report,
            "clear":   self.cmd_clear,
            "help":    self.cmd_help,
            "exit":    self.cmd_exit,
            "quit":    self.cmd_exit,
        }

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Main REPL loop."""
        self._in_interactive_mode = True
        _render_banner(self.subnet, self.passive)
        self._setup_completion()

        while True:
            try:
                user_input = input(self._prompt()).strip()
            except KeyboardInterrupt:
                console.print()
                continue
            except EOFError:
                self.cmd_exit()
                break

            if not user_input:
                continue

            self._dispatch(user_input)

    def run_command(self, command_str: str) -> None:
        """Run a single command non-interactively."""
        self._dispatch(command_str)

    # ── Prompt ────────────────────────────────────────────────────────────────

    def _prompt(self) -> str:
        # ANSI-escaped so readline accounts for non-printing chars
        subnet  = self.subnet
        reset   = "\001\033[0m\002"
        cyan    = "\001\033[96m\002"
        grey    = "\001\033[90m\002"
        bold    = "\001\033[1m\002"
        green   = "\001\033[92m\002"
        return f"{grey}[{reset}{cyan}{bold}{subnet}{reset}{grey}]{reset} {green}›{reset} "

    # ── Completion ────────────────────────────────────────────────────────────

    def _setup_completion(self) -> None:
        commands = list(self.command_map.keys())

        def completer(text, state):
            options = [c for c in commands if c.startswith(text)]
            return options[state] if state < len(options) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, user_input: str) -> None:
        try:
            parts = shlex.split(user_input)
        except ValueError as e:
            print_error(f"Parse error: {e}")
            return

        if not parts:
            return

        cmd  = parts[0].lower()
        args = parts[1:]

        if cmd in self.command_map:
            try:
                self.command_map[cmd](*args)
            except SystemExit:
                raise
            except Exception as e:
                print_error(f"Command failed: {e}")
        else:
            print_error(
                f"Unknown command [bold]{cmd!r}[/bold]. "
                f"Type [bold {C_OK}]help[/bold {C_OK}] for a list."
            )

    # ── Commands ──────────────────────────────────────────────────────────────

    def _parse_ports(self, spec: str) -> list[int] | None:
        """Parse a --ports spec like '22,80,443' or '1-1024' or '80,8000-8100'.

        Returns a sorted unique list of ints, or None on error (after printing).
        """
        ports: set[int] = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    lo, hi = int(lo), int(hi)
                    if lo < 1 or hi > 65535 or lo > hi:
                        raise ValueError
                    ports.update(range(lo, hi + 1))
                else:
                    p = int(part)
                    if p < 1 or p > 65535:
                        raise ValueError
                    ports.add(p)
            except ValueError:
                print_error(f"Invalid port spec: {part!r} (use e.g. 22,80,443 or 1-1024)")
                return None
        if not ports:
            print_error("No valid ports in --ports spec")
            return None
        return sorted(ports)

    def cmd_scan(self, *args) -> None:
        """Run network discovery + fingerprinting."""
        timeout      = 2
        passive      = self.passive
        profile      = "default"
        custom_ports: list[int] | None = None

        for arg in args:
            if arg.startswith("--timeout="):
                try:
                    timeout = int(arg.split("=", 1)[1])
                except ValueError:
                    print_error("--timeout value must be an integer")
                    return
            elif arg == "--passive":
                passive = True
            elif arg == "--fast":
                profile = "fast"
            elif arg == "--deep":
                profile = "deep"
            elif arg == "--full":
                profile = "full"
            elif arg.startswith("--ports="):
                custom_ports = self._parse_ports(arg.split("=", 1)[1])
                if custom_ports is None:
                    return
            else:
                print_error(f"Unknown scan option: {arg!r}")
                return

        # Port count for messaging
        from iotscanner.scanner.fingerprint import _ports_for
        n_ports = len(list(_ports_for(profile, custom_ports)))

        if profile == "full":
            console.print(
                f"  [{C_WARN}]⚠[/{C_WARN}]  Full 65,535-port scan — this will take "
                f"several minutes per host. Press Ctrl+C to abort.\n"
            )

        start = time.time()

        # ── Discovery phase ───────────────────────────────────────────────────
        console.print()
        with console.status(
            f"[{C_ACCENT}]Discovering hosts on [bold]{self.subnet}[/bold]…[/{C_ACCENT}]",
            spinner="dots",
            spinner_style=C_ACCENT,
        ):
            try:
                self.discovered_devices = asyncio.run(
                    run_discovery(
                        self.subnet, timeout=timeout, passive=passive,
                        intensity="fast" if profile == "fast" else
                                  "deep" if profile in ("deep", "full") else "default",
                    )
                )
            except KeyboardInterrupt:
                print_error("Scan aborted.")
                return
            except Exception as e:
                print_error(f"Discovery failed: {e}")
                return

        if not self.discovered_devices:
            print_info("No devices responded on this subnet.")
            return

        found = len(self.discovered_devices)
        console.print(
            f"  [{C_OK}]✓[/{C_OK}]  [{C_DIM}]Discovery complete[/{C_DIM}]  "
            f"[bold]{found}[/bold] [{C_DIM}]host{'' if found == 1 else 's'} found[/{C_DIM}]"
        )

        # ── Fingerprint phase ─────────────────────────────────────────────────
        with console.status(
            f"[{C_ACCENT}]Fingerprinting {found} host{'' if found == 1 else 's'} "
            f"across {n_ports:,} ports…[/{C_ACCENT}]",
            spinner="dots",
            spinner_style=C_ACCENT,
        ):
            try:
                device_dicts = asyncio.run(
                    fingerprint_all(
                        self.discovered_devices,
                        profile=profile,
                        custom_ports=custom_ports,
                        timeout=float(timeout) if timeout < 2 else 1.0,
                    )
                )
            except KeyboardInterrupt:
                print_error("Scan aborted.")
                return
            except Exception as e:
                print_error(f"Fingerprinting failed: {e}")
                return

        device_dicts = [d for d in device_dicts if d.get("mac")]
        self.scan_results = device_dicts
        duration = time.time() - start

        # ── Results table ─────────────────────────────────────────────────────
        console.print()
        console.print(make_device_table(device_dicts))

        # ── Persist ───────────────────────────────────────────────────────────
        try:
            new_count = self._upsert_devices(device_dicts)
        except Exception as e:
            print_error(f"Failed to save to database: {e}")
            new_count = 0

        # ── Summary strip ─────────────────────────────────────────────────────
        n          = len(device_dicts)
        devs       = "device" if n == 1 else "devices"
        total_open = sum(len(d.get("open_ports") or []) for d in device_dicts)
        console.print(Rule(style=C_SUBTLE))
        console.print(
            f"  [{C_OK}]✓[/{C_OK}]  [bold]{n}[/bold] [{C_DIM}]{devs}[/{C_DIM}]"
            f"  ·  [bold {C_OK}]{new_count}[/bold {C_OK}] [{C_DIM}]new[/{C_DIM}]"
            f"  ·  [bold]{total_open}[/bold] [{C_DIM}]open ports[/{C_DIM}]"
            f"  ·  [{C_DIM}]{n_ports:,} probed[/{C_DIM}]"
            f"  ·  [{C_DIM}]{duration:.1f}s[/{C_DIM}]"
            f"  ·  [{C_DIM}]Run[/{C_DIM}] [bold {C_OK}]report[/bold {C_OK}] [{C_DIM}]to export[/{C_DIM}]"
        )
        console.print()

    def cmd_devices(self, *args) -> None:
        """List known devices from the database."""
        as_json     = "--json" in args
        filter_text = None

        for i, arg in enumerate(args):
            if arg == "--filter" and i + 1 < len(args):
                filter_text = args[i + 1]

        try:
            with get_session() as session:
                results = session.execute(
                    select(Device).order_by(Device.last_seen.desc())
                ).scalars().all()

                if filter_text:
                    fl = filter_text.lower()
                    results = [
                        d for d in results
                        if (d.vendor and fl in d.vendor.lower())
                        or (d.ip and d.ip.startswith(filter_text))
                    ]

                if not results:
                    print_info("No devices in database — run [bold]scan[/bold] first.")
                    return

                if as_json:
                    data = [
                        {
                            "ip":           d.ip,
                            "mac":          d.mac,
                            "hostname":     d.hostname,
                            "vendor":       d.vendor,
                            "friendly_name":d.friendly_name,
                            "model_name":   d.model_name,
                            "manufacturer": d.manufacturer,
                            "http_banner":  d.http_banner,
                            "services":     d.services,
                            "open_ports":   d.open_ports,
                            "upnp_location":d.upnp_location,
                            "first_seen":   d.first_seen.isoformat() if d.first_seen else None,
                            "last_seen":    d.last_seen.isoformat()  if d.last_seen  else None,
                        }
                        for d in results
                    ]
                    console.print_json(json.dumps(data, default=str))
                else:
                    console.print()
                    console.print(make_device_table(results))
                    console.print(
                        f"  [{C_DIM}]{len(results)} device{'' if len(results)==1 else 's'} "
                        f"in database[/{C_DIM}]"
                    )
                    console.print()
        except Exception as e:
            print_error(f"Failed to list devices: {e}")

    def cmd_ports(self, *args) -> None:
        """Show open-port detail (port / service / banner) for a device."""
        if not args:
            print_error("Usage: ports <ip>")
            return

        ip = args[0]
        try:
            with get_session() as session:
                dev = session.execute(
                    select(Device).where(Device.ip == ip)
                ).scalars().first()

                if dev is None:
                    print_info(
                        f"No record for [bold]{ip}[/bold] — run [bold]scan[/bold] first."
                    )
                    return

                ports = dev.open_ports or []
                if not ports:
                    print_info(f"No open ports recorded for [bold]{ip}[/bold].")
                    return

                table = Table(
                    box=box.SIMPLE_HEAD, show_header=True,
                    header_style=f"bold {C_ACCENT}", border_style=C_SUBTLE,
                    padding=(0, 2),
                )
                table.add_column("Port",    style=f"bold {C_OK}", justify="right", no_wrap=True)
                table.add_column("Service", style=C_WARN, no_wrap=True)
                table.add_column("Banner",  style="white")

                for entry in ports:
                    p   = str(entry.get("port", ""))
                    svc = entry.get("service", "")
                    ban = entry.get("banner") or f"[{C_DIM}]—[/{C_DIM}]"
                    table.add_row(p, svc, ban)

                console.print()
                title = f"{ip}"
                if dev.vendor:
                    title += f"  ·  {dev.vendor}"
                if dev.hostname:
                    title += f"  ·  {dev.hostname}"
                console.print(f"  [bold {C_ACCENT}]{title}[/bold {C_ACCENT}]")
                console.print(table)
                console.print(
                    f"  [{C_DIM}]{len(ports)} open port"
                    f"{'' if len(ports)==1 else 's'}[/{C_DIM}]"
                )
                console.print()
        except Exception as e:
            print_error(f"Failed to read port detail: {e}")

    def cmd_vuln(self, *args) -> None:
        """CVE assessment stub — Stage 3."""
        if not args:
            print_error("Usage: vuln <ip>")
            return
        console.print(
            f"  [{C_WARN}]⚠[/{C_WARN}]  Vulnerability assessment for [bold]{args[0]}[/bold] — "
            f"[{C_DIM}]coming in Stage 3[/{C_DIM}]"
        )

    def cmd_report(self, *args) -> None:
        """Export last scan as JSON."""
        if not self.scan_results:
            print_info("No scan results — run [bold]scan[/bold] first.")
            return

        try:
            ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_path = Path.home() / ".iotscanner" / f"report_{ts}.json"
            output_path.parent.mkdir(exist_ok=True)
            output_path.write_text(
                json.dumps(self.scan_results, indent=2, default=str)
            )
            print_success(f"Report saved → {output_path}")
        except Exception as e:
            print_error(f"Failed to generate report: {e}")

    def cmd_clear(self, *args) -> None:
        console.clear()
        _render_banner(self.subnet, self.passive)

    def cmd_help(self, *args) -> None:
        _render_help()

    def cmd_exit(self, *args) -> None:
        if self._in_interactive_mode:
            console.print(
                f"\n  [{C_DIM}]Session ended.[/{C_DIM}]  "
                f"[bold {C_ACCENT}]Stay curious.[/bold {C_ACCENT}]\n"
            )
        sys.exit(0)

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _upsert_devices(self, device_dicts: list[dict]) -> int:
        """Upsert devices; return count of newly inserted rows."""
        new_count = 0
        now       = datetime.now(timezone.utc)

        with get_session() as session:
            for d in device_dicts:
                existing = session.execute(
                    select(Device).where(Device.mac == d["mac"])
                ).scalar_one_or_none()

                if existing:
                    for key, value in d.items():
                        if key != "mac" and value is not None:
                            setattr(existing, key, value)
                    existing.last_seen = now
                else:
                    session.add(Device(**d, first_seen=now, last_seen=now))
                    new_count += 1

        return new_count