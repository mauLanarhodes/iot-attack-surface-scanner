"""CLI entry point for iotscanner — built with Typer and Rich."""

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from sqlalchemy import select

from iotscanner import __version__
from iotscanner.db.models import Device
from iotscanner.db.session import get_session
from iotscanner.scanner.discovery import DiscoveredDevice, get_local_subnet, run_discovery
from iotscanner.scanner.fingerprint import fingerprint_all
from iotscanner.utils.console import (
    console,
    make_device_table,
    print_error,
    print_info,
    print_scan_summary,
)

app = typer.Typer(
    name="iotscanner",
    help="IoT Attack Surface Scanner — discover and fingerprint devices on your network.",
    no_args_is_help=True,
)


def _upsert_devices(device_dicts: list[dict]) -> int:
    """Upsert devices into the database. Returns count of newly inserted devices."""
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


@app.command()
def scan(
    subnet: Optional[str] = typer.Option(None, help="Subnet to scan (e.g. 192.168.1.0/24)"),
    timeout: int = typer.Option(2, help="ARP timeout in seconds"),
    passive: bool = typer.Option(False, help="Skip active UPnP/SSDP, do ARP + mDNS only"),
    output: Optional[Path] = typer.Option(None, help="Save JSON results to file"),
):
    """Scan the network for IoT devices."""
    if subnet is None:
        subnet = get_local_subnet()

    print_info(f"Scanning {subnet}...")

    start = time.time()

    # Run discovery
    with console.status(f"[bold blue]Scanning {subnet}...", spinner="dots"):
        discovered = asyncio.run(run_discovery(subnet, timeout=timeout, passive=passive))

    if not discovered:
        print_info("No devices found.")
        return

    # Run fingerprinting
    with console.status("[bold blue]Fingerprinting devices...", spinner="dots"):
        device_dicts = asyncio.run(fingerprint_all(discovered))

    # Filter out devices with empty MAC (can happen from SSDP-only results)
    device_dicts = [d for d in device_dicts if d.get("mac")]

    duration = time.time() - start

    # Display results
    table = make_device_table(device_dicts)
    console.print(table)

    # Save to database
    new_count = _upsert_devices(device_dicts)
    print_scan_summary(len(device_dicts), duration, new_count)

    # Optional JSON output
    if output:
        json_data = []
        for d in device_dicts:
            entry = dict(d)
            # Remove non-serializable fields if any
            json_data.append(entry)
        output.write_text(json.dumps(json_data, indent=2, default=str))
        print_info(f"Results saved to {output}")


@app.command()
def devices(
    as_json: bool = typer.Option(False, "--json", help="Print output as JSON instead of table"),
    filter_text: Optional[str] = typer.Option(None, "--filter", help="Filter by vendor or IP prefix"),
):
    """List all known devices from the database."""
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
                    "http_banner": d.http_banner,
                    "services": d.services,
                    "upnp_location": d.upnp_location,
                    "first_seen": d.first_seen.isoformat() if d.first_seen else None,
                    "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                })
            console.print_json(json.dumps(json_data, default=str))
        else:
            table = make_device_table(results)
            console.print(table)


@app.command()
def version():
    """Print the iotscanner version."""
    console.print(f"iotscanner v{__version__}")


if __name__ == "__main__":
    app()
