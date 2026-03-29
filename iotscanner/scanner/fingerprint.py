"""Device fingerprinting: OUI lookup, UPnP XML parsing, HTTP banner grab."""

import csv
from pathlib import Path

import httpx
from lxml import etree

from iotscanner.scanner.discovery import DiscoveredDevice

# Path to the OUI database CSV
OUI_CSV_PATH = Path(__file__).parent.parent.parent / "data" / "oui_database.csv"

# Module-level OUI cache
_oui_cache: dict[str, str] | None = None


def _load_oui_database() -> dict[str, str]:
    """Load OUI CSV into a dict mapping uppercase OUI prefix → vendor name."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache

    _oui_cache = {}
    if not OUI_CSV_PATH.exists():
        return _oui_cache

    with open(OUI_CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            oui = row["oui"].strip().upper()
            vendor = row["vendor"].strip()
            _oui_cache[oui] = vendor

    return _oui_cache


def oui_lookup(mac: str) -> str | None:
    """Look up the vendor for a MAC address using the OUI database.

    Args:
        mac: MAC address in format "XX:XX:XX:XX:XX:XX"

    Returns:
        Vendor name or None if not found.
    """
    db = _load_oui_database()
    # Take first 3 octets: "DC:A6:32:xx:xx:xx" → "DC:A6:32"
    prefix = mac.upper()[:8]
    return db.get(prefix)


async def fetch_upnp_xml(location: str) -> dict:
    """Fetch and parse a UPnP device description XML.

    Returns a dict with keys: friendly_name, model_name, manufacturer,
    model_description, model_number. Missing fields are None.
    """
    result = {
        "friendly_name": None,
        "model_name": None,
        "manufacturer": None,
        "model_description": None,
        "model_number": None,
    }

    try:
        async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
            resp = await client.get(location)
            resp.raise_for_status()
    except Exception:
        return result

    try:
        root = etree.fromstring(resp.content)
        ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}

        device = root.find(".//upnp:device", ns)
        if device is None:
            # Try without namespace
            device = root.find(".//device")

        if device is not None:
            for tag, key in [
                ("friendlyName", "friendly_name"),
                ("modelName", "model_name"),
                ("manufacturer", "manufacturer"),
                ("modelDescription", "model_description"),
                ("modelNumber", "model_number"),
            ]:
                elem = device.find(f"upnp:{tag}", ns)
                if elem is None:
                    elem = device.find(tag)
                if elem is not None and elem.text:
                    result[key] = elem.text.strip()
    except Exception:
        pass

    return result


async def http_banner_grab(ip: str) -> str | None:
    """Attempt to grab the HTTP Server header from port 80 and 8080.

    TODO: Stage 2 — extend to grab banners from additional discovered ports.
    """
    for port in (80, 8080):
        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                resp = await client.get(f"http://{ip}:{port}/")
                server = resp.headers.get("server")
                if server:
                    return server
        except Exception:
            continue
    return None


async def fingerprint_device(device: DiscoveredDevice) -> dict:
    """Enrich a discovered device with fingerprint data.

    Returns a dict of all fields suitable for database upsert.

    TODO: Stage 2 — add port scan results to the fingerprint output.
    """
    # OUI vendor lookup
    vendor = oui_lookup(device.mac) if device.mac else None

    # UPnP XML fetch
    upnp_info = {}
    if device.upnp_location:
        upnp_info = await fetch_upnp_xml(device.upnp_location)

    # HTTP banner grab
    banner = await http_banner_grab(device.ip)

    # Check if http banner indicates an HTTP service
    services = list(device.services)
    if banner and "http" not in services:
        services.append("http")

    return {
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": vendor,
        "friendly_name": upnp_info.get("friendly_name"),
        "model_name": upnp_info.get("model_name"),
        "manufacturer": upnp_info.get("manufacturer"),
        "http_banner": banner,
        "services": services,
        "upnp_location": device.upnp_location,
    }


async def fingerprint_all(devices: list[DiscoveredDevice]) -> list[dict]:
    """Run fingerprinting on all discovered devices concurrently."""
    import asyncio

    tasks = [fingerprint_device(dev) for dev in devices]
    return await asyncio.gather(*tasks)
