"""Device fingerprinting.

Per-host enrichment:
  * OUI vendor lookup (full IEEE database)
  * UPnP device-description XML parse (friendly name / model / manufacturer)
  * Comprehensive TCP port scan (tiered profiles, semaphore-bounded)
  * Protocol-aware banner grabbing (HTTP, plus immediate-banner services)
  * Service-name resolution via a large built-in map + IANA fallback

The port scanner is built to be exhaustive without melting the network: every
probe acquires a global connection semaphore, and very large port ranges are
streamed host-by-host in chunks so coroutine count stays bounded even for a
full 1-65535 scan.
"""

import asyncio
import socket
import threading

import httpx
from lxml import etree
from mac_vendor_lookup import AsyncMacLookup

from iotscanner.scanner.discovery import DiscoveredDevice


# ── OUI vendor lookup ────────────────────────────────────────────────────────────

_async_lookup   = AsyncMacLookup()
_vendors_loaded = False
_vendor_lock    = threading.Lock()


def _ensure_vendors() -> None:
    """Load the OUI vendor DB once, in a dedicated thread with its own loop."""
    global _vendors_loaded
    if _vendors_loaded:
        return
    with _vendor_lock:
        if _vendors_loaded:
            return
        def _load():
            asyncio.run(_async_lookup.load_vendors())
        t = threading.Thread(target=_load, daemon=True)
        t.start()
        t.join(timeout=10)
        _vendors_loaded = True


try:
    _ensure_vendors()
except Exception:
    pass


def oui_lookup(mac: str) -> str | None:
    """Vendor name for a MAC address, or None if not found."""
    if not getattr(_async_lookup, "prefixes", None):
        return None
    try:
        prefix = mac.replace(":", "").replace("-", "").replace(".", "").upper()[:6].encode("utf8")
        result = _async_lookup.prefixes.get(prefix)
        return result.decode("utf8") if result else None
    except Exception:
        return None


# ── Service map & port profiles ──────────────────────────────────────────────────

# Curated port -> service-name map covering general + IoT/OT/smart-home services.
SERVICE_MAP: dict[int, str] = {
    # File transfer / sharing
    20: "ftp-data", 21: "ftp", 69: "tftp", 115: "sftp", 139: "netbios-ssn",
    445: "smb", 548: "afp", 873: "rsync", 990: "ftps", 2049: "nfs",
    # Remote access
    22: "ssh", 23: "telnet", 992: "telnets", 2323: "telnet-alt",
    3389: "rdp", 5985: "winrm", 5986: "winrm-tls",
    5900: "vnc", 5901: "vnc-1", 5902: "vnc-2", 5903: "vnc-3", 6000: "x11",
    # Mail
    25: "smtp", 110: "pop3", 143: "imap", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s",
    # Naming / directory / infra
    53: "dns", 67: "dhcp", 68: "dhcp-client", 88: "kerberos", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 389: "ldap",
    636: "ldaps", 514: "syslog", 515: "printer-lpd", 520: "rip",
    631: "ipp", 1812: "radius", 1813: "radius-acct", 111: "rpcbind",
    # Discovery / multicast / VoIP
    1900: "upnp", 3702: "ws-discovery", 5060: "sip", 5061: "sips",
    5353: "mdns", 5355: "llmnr",
    # IoT / OT / industrial
    102: "s7comm", 502: "modbus", 789: "redlion", 1883: "mqtt",
    1911: "niagara-fox", 1962: "pcworx", 2404: "iec-104", 4840: "opc-ua",
    5683: "coap", 5684: "coaps", 6052: "esphome", 8883: "mqtt-tls",
    9600: "omron-fins", 18245: "ge-srtp", 20000: "dnp3",
    44818: "ethernet-ip", 47808: "bacnet",
    # Web / HTTP family
    80: "http", 443: "https", 280: "http-mgmt", 591: "http-alt",
    981: "http-tls", 1311: "https-mgmt", 1880: "node-red", 2080: "http-alt",
    3000: "http-dev", 3128: "http-proxy", 4000: "http-alt", 4567: "http-alt",
    5000: "http-alt", 5800: "vnc-http", 6080: "http-alt", 7001: "http-alt",
    7070: "http-alt", 8000: "http-alt", 8001: "http-alt", 8008: "http-alt",
    8042: "http-alt", 8069: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8082: "http-alt", 8083: "http-alt", 8085: "http-alt", 8086: "influxdb",
    8088: "http-alt", 8089: "http-alt", 8090: "http-alt", 8123: "home-assistant",
    8181: "http-alt", 8243: "http-alt", 8280: "http-alt", 8443: "https-alt",
    8500: "consul", 8530: "wsus", 8581: "homebridge", 8765: "http-alt",
    8800: "http-alt", 8834: "nessus", 8880: "http-alt", 8888: "http-alt",
    8889: "http-alt", 8983: "solr", 9000: "http-alt", 9043: "websphere",
    9080: "http-alt", 9090: "http-alt", 9091: "transmission", 9200: "elasticsearch",
    9443: "https-alt", 9981: "tvheadend", 10000: "webmin", 32400: "plex",
    # Media / streaming / cast / cameras
    554: "rtsp", 1935: "rtmp", 5004: "rtp", 5005: "rtcp", 7000: "airplay",
    8009: "chromecast", 8060: "roku", 8200: "hikvision", 8554: "rtsp-alt",
    8899: "dvr-alt", 34567: "xmeye-dvr", 37777: "dahua-dvr",
    # Management / tunnels / debug
    179: "bgp", 512: "exec", 513: "login", 1099: "java-rmi", 1701: "l2tp",
    1723: "pptp", 2000: "cisco-sccp", 2375: "docker", 2376: "docker-tls",
    4444: "krb524", 4500: "ipsec-nat-t", 5222: "xmpp", 5269: "xmpp-server",
    5555: "adb", 5666: "nrpe", 6379: "redis", 6443: "kubernetes",
    6667: "irc", 7547: "tr-069", 9100: "jetdirect", 11211: "memcached",
    27017: "mongodb", 49152: "upnp-event", 49153: "upnp-event",
    62078: "apple-sync",
    # Databases
    1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql",
    5984: "couchdb", 7474: "neo4j", 9042: "cassandra",
}

# ── Port profiles ────────────────────────────────────────────────────────────────
#
# SERVICE_MAP is the source of truth for name resolution on ANY open port.
# Port profiles are SEPARATE — what the scanner actually probes per profile.
#
# default  (~55 ports)  — focused consumer IoT/smart-home; finishes in ~8-12s
# fast     (~25 ports)  — bare minimum; ~5s
# deep     (169 ports)  — full SERVICE_MAP including OT/industrial; ~25-40s
# full     (65535)      — exhaustive; several minutes

# fast — the 25 ports most likely to be open on any networked device
FAST_PORTS = sorted({
    21, 22, 23, 53, 80, 443, 445, 554, 631,
    1883, 1900, 3389, 5000, 5900, 7547,
    8000, 8008, 8009, 8080, 8081, 8443, 8883,
    9100, 9000, 32400,
})

# default — consumer IoT / smart-home focused; no industrial OT timeouts
DEFAULT_PORTS = sorted({
    # Remote access (always check — telnet on IoT is a critical finding)
    21, 22, 23, 2323,
    # Core web / HTTP variants seen on real consumer devices
    80, 443, 8000, 8001, 8008, 8009, 8080, 8081, 8083, 8086, 8088,
    8090, 8123, 8181, 8443, 8554, 8581, 8888, 8899,
    9000, 9090, 9091, 9443, 9981, 10000, 32400,
    # Smart-home platforms
    3000, 5000, 6052, 7000, 7547, 8060,
    # IoT protocols
    554, 1883, 5683, 8883,
    # Infra / printing
    53, 445, 515, 631, 9100,
    # Media / casting
    1935, 5004,
    # Sonos internal HTTP API
    1400, 1443,
    # Samsung SmartThings
    8001, 8002,
    # Debug / management (high-value security findings)
    4444, 4840, 5555, 6379, 7474,
    # Discovery protocols
    1900, 5353,
    # VNC / RDP
    3389, 5900,
    # UPnP event ports
    49152, 49153,
})

# deep — every port in SERVICE_MAP (covers OT/industrial too)
DEEP_PORTS = sorted(SERVICE_MAP.keys())

# FULL is generated on demand (range(1, 65536)) to avoid a 65k list in memory.

_CONNECT_TIMEOUT = 0.5          # per-port TCP connect timeout — LAN RTT is <5ms, 500ms is plenty
_CONN_LIMIT      = 600          # max concurrent socket connections
_CHUNK           = 2000         # ports per host-chunk for huge ranges

# Recreated fresh for each scan (asyncio.run uses a new loop each time)
_conn_sem: asyncio.Semaphore | None = None


def _service_name(port: int) -> str:
    """Resolve a port to a service label: map first, then IANA, then tcp/<port>."""
    name = SERVICE_MAP.get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return f"tcp/{port}"


def _ports_for(profile: str, custom: list[int] | None = None):
    """Return an iterable of ports for the requested profile.

    fast    ~25  — quickest meaningful check
    default ~55  — focused consumer IoT (the safe default)
    deep    169  — full SERVICE_MAP including OT/industrial
    full  65535  — every port
    """
    if custom:
        return custom
    if profile == "fast":
        return FAST_PORTS
    if profile == "deep":
        return DEEP_PORTS
    if profile == "full":
        return range(1, 65536)
    return DEFAULT_PORTS  # default


# ── TCP probing ──────────────────────────────────────────────────────────────────

async def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    """True if a TCP connect to ip:port succeeds within timeout."""
    assert _conn_sem is not None
    async with _conn_sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


async def _scan_host_ports(ip: str, ports, timeout: float) -> list[int]:
    """Return sorted list of open ports on a host, scanned in bounded chunks."""
    port_list = list(ports)
    open_ports: list[int] = []
    for i in range(0, len(port_list), _CHUNK):
        chunk = port_list[i:i + _CHUNK]
        flags = await asyncio.gather(*[_tcp_open(ip, p, timeout) for p in chunk])
        open_ports.extend(p for p, ok in zip(chunk, flags) if ok)
    return sorted(open_ports)


# ── Banner grabbing ──────────────────────────────────────────────────────────────

_HTTP_SERVICES = {"http", "https", "http-alt", "http-proxy", "http-dev",
                  "http-mgmt", "http-tls", "https-alt", "https-mgmt",
                  "home-assistant", "homebridge", "node-red"}


async def _http_banner(ip: str, port: int) -> str | None:
    """Server header from an HTTP(S) request on a given port."""
    scheme = "https" if port in (443, 8443, 9443, 981, 1311, 4443) else "http"
    for sch in (scheme, "http"):
        try:
            async with httpx.AsyncClient(timeout=1.5, verify=False) as client:
                resp = await client.get(f"{sch}://{ip}:{port}/")
                server = resp.headers.get("server")
                if server:
                    return f"{server}"
        except Exception:
            continue
    return None


async def _raw_banner(ip: str, port: int, timeout: float = 0.75) -> str | None:
    """Read an immediate service banner (SSH/FTP/SMTP/etc. announce on connect)."""
    assert _conn_sem is not None
    async with _conn_sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except Exception:
            return None
        try:
            data = await asyncio.wait_for(reader.read(160), timeout=timeout)
            text = data.decode(errors="ignore").strip()
            return text[:120] or None
        except Exception:
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def grab_banners(ip: str, open_ports: list[int]) -> tuple[str | None, dict[int, str]]:
    """Collect banners for open ports concurrently.

    Returns:
        http_banner — first HTTP Server header found (kept for the Device column)
        port_banners — {port: banner} for any port that yielded one
    """
    http_banner: str | None = None
    port_banners: dict[int, str] = {}

    http_ports  = [p for p in open_ports if _service_name(p) in _HTTP_SERVICES]
    other_ports = [p for p in open_ports if p not in set(http_ports)]

    # Run all banner grabs concurrently (was sequential for HTTP — fixed)
    http_results  = await asyncio.gather(*[_http_banner(ip, p) for p in http_ports])
    raw_results   = await asyncio.gather(*[_raw_banner(ip, p)  for p in other_ports])

    for p, b in zip(http_ports, http_results):
        if b:
            port_banners[p] = b
            if http_banner is None:
                http_banner = b

    for p, b in zip(other_ports, raw_results):
        if b:
            port_banners[p] = b

    return http_banner, port_banners


# ── UPnP description XML ──────────────────────────────────────────────────────────

async def fetch_upnp_xml(location: str) -> dict:
    """Fetch and parse a UPnP device description XML."""
    result = {
        "friendly_name":    None,
        "model_name":       None,
        "manufacturer":     None,
        "model_description":None,
        "model_number":     None,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
            resp = await client.get(location)
            resp.raise_for_status()
    except Exception:
        return result

    try:
        root = etree.fromstring(resp.content)
        ns   = {"upnp": "urn:schemas-upnp-org:device-1-0"}

        device = root.find(".//upnp:device", ns)
        if device is None:
            device = root.find(".//device")
        if device is not None:
            for tag, key in [
                ("friendlyName",    "friendly_name"),
                ("modelName",       "model_name"),
                ("manufacturer",    "manufacturer"),
                ("modelDescription","model_description"),
                ("modelNumber",     "model_number"),
            ]:
                elem = device.find(f"upnp:{tag}", ns)
                if elem is None:
                    elem = device.find(tag)
                if elem is not None and elem.text:
                    result[key] = elem.text.strip()
    except Exception:
        pass

    return result


# ── Per-device orchestration ──────────────────────────────────────────────────────

async def fingerprint_device(
    device: DiscoveredDevice,
    profile: str = "default",
    custom_ports: list[int] | None = None,
    timeout: float = _CONNECT_TIMEOUT,
) -> dict:
    """Enrich a single discovered device with full fingerprint data."""
    vendor    = oui_lookup(device.mac) if device.mac else None
    upnp_info = await fetch_upnp_xml(device.upnp_location) if device.upnp_location else {}

    ports     = _ports_for(profile, custom_ports)
    open_ports = await _scan_host_ports(device.ip, ports, timeout)

    http_banner, port_banners = await grab_banners(device.ip, open_ports)

    # Build the service list from open ports, then fold in discovery-tagged ones
    seen: set[str] = set()
    services: list[str] = []
    for p in open_ports:
        name = _service_name(p)
        if name not in seen:
            seen.add(name)
            services.append(name)
    for svc in device.services:
        if svc not in seen:
            seen.add(svc)
            services.append(svc)

    # Structured open-port detail (port, service, banner)
    open_detail = [
        {
            "port":    p,
            "service": _service_name(p),
            "banner":  port_banners.get(p),
        }
        for p in open_ports
    ]

    return {
        "ip":           device.ip,
        "mac":          device.mac,
        "hostname":     device.hostname,
        "vendor":       vendor,
        "friendly_name":upnp_info.get("friendly_name"),
        "model_name":   upnp_info.get("model_name"),
        "manufacturer": upnp_info.get("manufacturer"),
        "http_banner":  http_banner,
        "services":     services,
        "open_ports":   open_detail,
        "upnp_location":device.upnp_location,
    }


async def fingerprint_all(
    devices: list[DiscoveredDevice],
    profile: str = "default",
    custom_ports: list[int] | None = None,
    timeout: float = _CONNECT_TIMEOUT,
    host_concurrency: int = 24,
) -> list[dict]:
    """Fingerprint all devices.

    A fresh global connection semaphore is created per call (each asyncio.run
    uses a new event loop). Hosts are processed with bounded concurrency so a
    full-range scan across many hosts never explodes coroutine/socket counts.
    """
    global _conn_sem
    _conn_sem = asyncio.Semaphore(_CONN_LIMIT)

    host_sem = asyncio.Semaphore(host_concurrency)

    async def _one(dev: DiscoveredDevice) -> dict:
        async with host_sem:
            return await fingerprint_device(dev, profile, custom_ports, timeout)

    return await asyncio.gather(*[_one(d) for d in devices])