"""Multi-vector device discovery.

Finds live hosts on a subnet using every reliable technique at once:

  1. ARP sweep (with retransmission)   — definitive on a local L2 segment
  2. ICMP echo sweep                   — catches ICMP-only responders
  3. TCP-SYN ping to common ports      — catches hosts behind host firewalls
  4. Targeted ARP MAC resolution       — fills in MACs for any IP found by 2/3
  5. mDNS / DNS-SD service browse      — hostnames + advertised services
  6. SSDP / UPnP M-SEARCH (+ retries)  — UPnP devices + description URLs
  7. Reverse-DNS + NetBIOS name query  — hostname enrichment for every host

On a /24 LAN, ARP alone is near-definitive (any host with an IP on the segment
must answer ARP). Retransmission removes the run-to-run flakiness from dropped
packets; ICMP / SYN / NetBIOS add coverage and corroboration so the result set
is both complete and stable.
"""

import asyncio
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from iotscanner.utils.console import print_error


# Ports used for SYN-ping host discovery (a host need only answer on ONE).
_PING_PORTS = [80, 443, 22, 23, 8080, 445, 139, 53, 7547, 1900, 8443, 554, 8009]


@dataclass
class DiscoveredDevice:
    """Intermediate device representation used during discovery."""

    ip: str
    mac: str = ""
    hostname: str | None = None
    services: list[str] = field(default_factory=list)
    upnp_location: str | None = None

    def merge(self, other: "DiscoveredDevice"):
        """Merge fields from another discovery of the same device."""
        if other.mac and not self.mac:
            self.mac = other.mac
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.upnp_location and not self.upnp_location:
            self.upnp_location = other.upnp_location
        for svc in other.services:
            if svc not in self.services:
                self.services.append(svc)


def _check_root():
    """Exit with a clear error if not running as root."""
    if os.geteuid() != 0:
        print_error("Network scanning requires root / sudo privileges.")
        sys.exit(1)


def get_local_subnet() -> str:
    """Auto-detect the local subnet (best-effort, no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))  # route-only, no packets sent
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


# ── Layer-2 / Layer-3 sweeps (scapy, run in executor so they don't block) ────────

def _arp_sweep_blocking(subnet: str, timeout: int, retries: int) -> list[tuple[str, str]]:
    """Blocking ARP sweep. Returns list of (ip, mac)."""
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, srp

    network = IPv4Network(subnet, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(pkt, timeout=timeout, retry=retries, verbose=False)
    return [(rcv.psrc, rcv.hwsrc.upper()) for _, rcv in answered]


def _icmp_sweep_blocking(subnet: str, timeout: int) -> list[str]:
    """Blocking ICMP echo sweep. Returns list of responding IPs."""
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, ICMP, sr

    network = IPv4Network(subnet, strict=False)
    pkt = IP(dst=str(network)) / ICMP()
    answered, _ = sr(pkt, timeout=timeout, verbose=False)
    return [rcv.src for _, rcv in answered]


def _syn_ping_blocking(subnet: str, timeout: int) -> list[str]:
    """Blocking TCP-SYN ping. A host that answers on any probed port is live."""
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, sr

    network = IPv4Network(subnet, strict=False)
    pkt = IP(dst=str(network)) / TCP(dport=_PING_PORTS, flags="S")
    answered, _ = sr(pkt, timeout=timeout, verbose=False)
    live = set()
    for _, rcv in answered:
        if rcv.haslayer(TCP):
            live.add(rcv.src)
    return list(live)


def _resolve_macs_blocking(ips: list[str], timeout: int) -> dict[str, str]:
    """Targeted ARP for specific IPs that are missing a MAC."""
    if not ips:
        return {}
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, srp

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips)
    answered, _ = srp(pkt, timeout=timeout, retry=1, verbose=False)
    return {rcv.psrc: rcv.hwsrc.upper() for _, rcv in answered}


async def arp_sweep(subnet: str, timeout: int = 2, retries: int = 2) -> list[DiscoveredDevice]:
    """ARP sweep with retransmission (concurrent-safe via executor)."""
    loop = asyncio.get_event_loop()
    pairs = await loop.run_in_executor(None, _arp_sweep_blocking, subnet, timeout, retries)
    return [DiscoveredDevice(ip=ip, mac=mac) for ip, mac in pairs]


async def icmp_sweep(subnet: str, timeout: int = 2) -> list[DiscoveredDevice]:
    """ICMP echo sweep (concurrent-safe via executor)."""
    loop = asyncio.get_event_loop()
    ips = await loop.run_in_executor(None, _icmp_sweep_blocking, subnet, timeout)
    return [DiscoveredDevice(ip=ip) for ip in ips]


async def syn_ping(subnet: str, timeout: int = 2) -> list[DiscoveredDevice]:
    """TCP-SYN ping sweep (concurrent-safe via executor)."""
    loop = asyncio.get_event_loop()
    ips = await loop.run_in_executor(None, _syn_ping_blocking, subnet, timeout)
    return [DiscoveredDevice(ip=ip) for ip in ips]


async def resolve_macs(ips: list[str], timeout: int = 2) -> dict[str, str]:
    """Resolve MACs for a specific set of IPs via targeted ARP."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _resolve_macs_blocking, ips, timeout)


# ── mDNS / DNS-SD ────────────────────────────────────────────────────────────────

# A broad catalogue of DNS-SD service types seen on real consumer/IoT networks.
_MDNS_SERVICE_TYPES = [
    "_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
    "_device-info._tcp.local.", "_ssh._tcp.local.", "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.", "_afpovertcp._tcp.local.", "_nfs._tcp.local.",
    "_rfb._tcp.local.", "_telnet._tcp.local.",
    # Apple ecosystem
    "_hap._tcp.local.", "_homekit._tcp.local.", "_airplay._tcp.local.",
    "_raop._tcp.local.", "_airport._tcp.local.", "_adisk._tcp.local.",
    "_companion-link._tcp.local.", "_mediaremotetv._tcp.local.",
    "_appletv-v2._tcp.local.", "_touch-able._tcp.local.", "_daap._tcp.local.",
    "_dpap._tcp.local.", "_apple-mobdev2._tcp.local.",
    # Google / Cast / Nest
    "_googlecast._tcp.local.", "_googlezone._tcp.local.", "_google._tcp.local.",
    "_privet._tcp.local.",
    # Smart home / matter / IoT
    "_matter._tcp.local.", "_matterc._udp.local.", "_esphomelib._tcp.local.",
    "_homeassistant._tcp.local.", "_hue._tcp.local.", "_ewelink._tcp.local.",
    "_amzn-wplay._tcp.local.", "_amzn-alexa._tcp.local.",
    # Printers / scanners
    "_printer._tcp.local.", "_ipp._tcp.local.", "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.", "_scanner._tcp.local.", "_uscan._tcp.local.",
    "_uscans._tcp.local.",
    # Media / streaming
    "_spotify-connect._tcp.local.", "_sonos._tcp.local.", "_roku._tcp.local.",
    "_viziocast._tcp.local.", "_nvstream._tcp.local.", "_plexmediasvr._tcp.local.",
    # Misc
    "_xbox._tcp.local.", "_psn._tcp.local.", "_miio._udp.local.",
]


async def mdns_listen(timeout: int = 3) -> list[DiscoveredDevice]:
    """Browse a broad set of DNS-SD service types using async zeroconf.

    Uses AsyncZeroconf so there is no blocking-I/O warning, and resolves each
    discovered instance after the browse window closes.
    """
    from zeroconf import ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

    found_names: list[tuple[str, str]] = []  # (service_type, name)

    def on_change(zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            found_names.append((service_type, name))

    devices: dict[str, DiscoveredDevice] = {}

    aiozc = AsyncZeroconf()
    browsers = [
        AsyncServiceBrowser(aiozc.zeroconf, stype, handlers=[on_change])
        for stype in _MDNS_SERVICE_TYPES
    ]

    await asyncio.sleep(timeout)

    # Resolve each instance (async — no blocking I/O in the handler)
    for stype, name in found_names:
        try:
            info = await aiozc.async_get_service_info(stype, name, timeout=2000)
        except Exception:
            info = None
        if info is None:
            continue
        svc_name = stype.split(".")[0].lstrip("_")
        for addr_bytes in info.addresses:
            try:
                ip = socket.inet_ntoa(addr_bytes)
            except OSError:
                continue  # skip IPv6 / malformed
            host = (info.server or "").rstrip(".") or None
            if ip in devices:
                devices[ip].merge(DiscoveredDevice(ip=ip, hostname=host, services=[svc_name]))
            else:
                devices[ip] = DiscoveredDevice(ip=ip, hostname=host, services=[svc_name])

    for b in browsers:
        try:
            await b.async_cancel()
        except Exception:
            pass
    try:
        await aiozc.async_close()
    except Exception:
        pass

    return list(devices.values())


# ── SSDP / UPnP ──────────────────────────────────────────────────────────────────

# Several search targets so we elicit responses from a wide range of UPnP stacks.
_SSDP_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:dial-multiscreen-org:service:dial:1",
]


async def ssdp_discover(timeout: int = 3, retries: int = 2) -> list[DiscoveredDevice]:
    """Send UPnP/SSDP M-SEARCH for several targets and collect LOCATION URLs."""
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    devices: dict[str, DiscoveredDevice] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)

    # Fire all search targets, repeated for reliability
    for _ in range(max(1, retries)):
        for st in _SSDP_TARGETS:
            msearch = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                f"ST: {st}\r\n"
                "\r\n"
            )
            try:
                sock.sendto(msearch.encode(), (SSDP_ADDR, SSDP_PORT))
            except Exception:
                pass

    # Collect responses until the overall window elapses
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            continue
        except Exception:
            break
        ip = addr[0]
        response = data.decode(errors="ignore")
        location = next(
            (line.split(":", 1)[1].strip()
             for line in response.splitlines()
             if line.lower().startswith("location:")),
            None,
        )
        if ip in devices:
            if location and not devices[ip].upnp_location:
                devices[ip].upnp_location = location
            if "upnp" not in devices[ip].services:
                devices[ip].services.append("upnp")
        else:
            devices[ip] = DiscoveredDevice(ip=ip, upnp_location=location, services=["upnp"])

    sock.close()
    return list(devices.values())


# ── Hostname enrichment ────────────────────────────────────────────────────────

async def reverse_dns(ip: str) -> str | None:
    """Reverse-DNS (PTR) lookup, hard-capped at 2s so a slow DNS never stalls the scan."""
    loop = asyncio.get_event_loop()
    try:
        name, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=2.0,
        )
        return name.rstrip(".") if name else None
    except Exception:
        return None


def _encode_netbios_name(name: str) -> bytes:
    """First-level encode a NetBIOS name (16 bytes -> 32 nibble-encoded bytes)."""
    padded = name.ljust(16, "\x00")[:16]
    out = bytearray()
    for ch in padded.encode("ascii", "ignore"):
        out.append((ch >> 4) + ord("A"))
        out.append((ch & 0x0F) + ord("A"))
    return bytes(out)


def _skip_dns_name(data: bytes, idx: int) -> int:
    """Advance past a (possibly compressed) DNS/NetBIOS encoded name."""
    while idx < len(data):
        length = data[idx]
        if length == 0x00:
            return idx + 1
        if length & 0xC0 == 0xC0:   # compression pointer (2 bytes)
            return idx + 2
        idx += length + 1
    return idx


async def netbios_name(ip: str, timeout: float = 0.5) -> str | None:
    """Query NetBIOS node status (UDP/137) and return the workstation name."""
    loop = asyncio.get_event_loop()

    def _query() -> str | None:
        # NBSTAT node-status request for the wildcard name "*"
        tid = 0x4242
        header = struct.pack(">HHHHHH", tid, 0x0000, 1, 0, 0, 0)
        qname = b"\x20" + _encode_netbios_name("*") + b"\x00"
        question = qname + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
        packet = header + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(2048)
        except Exception:
            return None
        finally:
            s.close()

        try:
            if len(data) < 12:
                return None
            qdcount = struct.unpack(">H", data[4:6])[0]
            ancount = struct.unpack(">H", data[6:8])[0]
            if ancount < 1:
                return None

            idx = 12
            # Skip any echoed question records
            for _ in range(qdcount):
                idx = _skip_dns_name(data, idx)
                idx += 4  # QTYPE + QCLASS

            # Answer RR: NAME, TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
            idx = _skip_dns_name(data, idx)
            idx += 2 + 2 + 4          # TYPE, CLASS, TTL
            idx += 2                  # RDLENGTH
            num_names = data[idx]
            idx += 1

            best: str | None = None
            for _ in range(num_names):
                if idx + 18 > len(data):
                    break
                raw = data[idx:idx + 15].decode("ascii", "ignore").strip()
                suffix = data[idx + 15]
                flags = struct.unpack(">H", data[idx + 16:idx + 18])[0]
                idx += 18
                is_group = bool(flags & 0x8000)
                # suffix 0x00 on a unique name = workstation/redirector name
                if suffix == 0x00 and not is_group and raw and best is None:
                    best = raw
            return best
        except Exception:
            return None

    try:
        return await loop.run_in_executor(None, _query)
    except Exception:
        return None


async def enrich_hostnames(devices: list[DiscoveredDevice]) -> None:
    """Fill in missing hostnames via reverse-DNS, then NetBIOS, in place."""
    async def _one(dev: DiscoveredDevice):
        if dev.hostname:
            return
        host = await reverse_dns(dev.ip)
        if not host:
            host = await netbios_name(dev.ip)
        if host:
            dev.hostname = host

    await asyncio.gather(*[_one(d) for d in devices], return_exceptions=True)


# ── Merge + orchestration ────────────────────────────────────────────────────────

def merge_devices(device_lists: list[list[DiscoveredDevice]]) -> list[DiscoveredDevice]:
    """Merge multiple discovery result sets by IP address."""
    merged: dict[str, DiscoveredDevice] = {}
    for devices in device_lists:
        for dev in devices:
            if dev.ip in merged:
                merged[dev.ip].merge(dev)
            else:
                merged[dev.ip] = dev
    return list(merged.values())


async def run_discovery(
    subnet: str,
    timeout: int = 2,
    passive: bool = False,
    intensity: str = "default",
) -> list[DiscoveredDevice]:
    """Run all discovery vectors, merge, resolve MACs, and enrich hostnames.

    intensity:
        "fast"    — ARP (1 retry) + mDNS + SSDP, short windows
        "default" — ARP (2 retries) + ICMP + SYN-ping + mDNS + SSDP
        "deep"    — like default with longer windows and 3 ARP retries
    """
    _check_root()

    # Tune timing per intensity
    if intensity == "fast":
        arp_to, arp_retry = max(1, timeout), 1
        icmp_to = syn_to = 0
        mdns_to, ssdp_to = max(2, timeout), max(2, timeout)
    elif intensity == "deep":
        arp_to, arp_retry = max(3, timeout), 3
        icmp_to = syn_to = max(2, timeout)
        mdns_to, ssdp_to = max(5, timeout), max(4, timeout)
    else:  # default
        arp_to, arp_retry = max(2, timeout), 2
        icmp_to = syn_to = max(2, timeout)
        mdns_to, ssdp_to = max(3, timeout), max(3, timeout)

    tasks = [arp_sweep(subnet, arp_to, arp_retry), mdns_listen(mdns_to)]
    labels = ["ARP", "mDNS"]

    if intensity != "fast":
        tasks.append(icmp_sweep(subnet, icmp_to)); labels.append("ICMP")
        tasks.append(syn_ping(subnet, syn_to));    labels.append("SYN-ping")

    if not passive:
        tasks.append(ssdp_discover(timeout=ssdp_to)); labels.append("SSDP")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    device_lists = []
    for label, result in zip(labels, results):
        if isinstance(result, Exception):
            print_error(f"{label} discovery failed: {result}")
            continue
        device_lists.append(result)

    merged = merge_devices(device_lists)

    # Resolve MACs for any IP that came only from ICMP / SYN / mDNS / SSDP
    macless = [d.ip for d in merged if not d.mac]
    if macless:
        try:
            mac_map = await resolve_macs(macless, timeout=max(1, timeout))
            for d in merged:
                if not d.mac and d.ip in mac_map:
                    d.mac = mac_map[d.ip]
        except Exception as e:
            print_error(f"MAC resolution failed: {e}")

    # Enrich hostnames (reverse-DNS + NetBIOS)
    try:
        await enrich_hostnames(merged)
    except Exception as e:
        print_error(f"Hostname enrichment failed: {e}")

    return merged