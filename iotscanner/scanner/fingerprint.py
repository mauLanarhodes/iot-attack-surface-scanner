"""Device fingerprinting: OUI lookup, UPnP XML parsing, HTTP banner grab."""

import asyncio

import httpx
from lxml import etree
from mac_vendor_lookup import AsyncMacLookup

from iotscanner.scanner.discovery import DiscoveredDevice

# Pre-load the IEEE OUI database once at import (synchronously, before any
# event loop is running) so lookups during async scans are pure dict access.
# MacLookup.lookup() is a sync wrapper around an async call that breaks when
# invoked from inside another running event loop.
_async_lookup = AsyncMacLookup()
try:
    asyncio.run(_async_lookup.load_vendors())
except Exception:
    pass


def oui_lookup(mac: str) -> str | None:
    """Look up vendor for a MAC address using the full
    IEEE OUI database bundled with mac-vendor-lookup.

    Args:
        mac: MAC address in any standard format.
    Returns:
        Vendor name string or None if not found.
    """
    if not _async_lookup.prefixes:
        return None
    try:
        prefix = mac.replace(":", "").replace("-", "").replace(".", "").upper()[:6].encode("utf8")
        result = _async_lookup.prefixes.get(prefix)
        return result.decode("utf8") if result else None
    except Exception:
        return None


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
