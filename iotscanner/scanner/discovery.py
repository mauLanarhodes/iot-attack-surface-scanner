"""Device discovery via ARP sweep, mDNS, and UPnP/SSDP."""

import asyncio
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from iotscanner.utils.console import print_error


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
        print_error("ARP scan requires root. Run with sudo.")
        sys.exit(1)


def get_local_subnet() -> str:
    """Auto-detect the local subnet (best-effort)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Assume /24 for local networks
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


async def arp_sweep(subnet: str, timeout: int = 2) -> list[DiscoveredDevice]:
    """Send ARP broadcast to all IPs in subnet and collect replies."""
    from scapy.all import ARP, Ether, srp

    network = IPv4Network(subnet, strict=False)
    target = str(network)

    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    answered, _ = srp(arp_request, timeout=timeout, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append(
            DiscoveredDevice(
                ip=received.psrc,
                mac=received.hwsrc.upper(),
            )
        )
    return devices


async def mdns_listen(timeout: int = 2) -> list[DiscoveredDevice]:
    """Listen for mDNS service announcements using zeroconf."""
    from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf

    devices: dict[str, DiscoveredDevice] = {}

    service_types = [
        "_http._tcp.local.",
        "_hap._tcp.local.",
        "_googlecast._tcp.local.",
        "_matter._tcp.local.",
        "_printer._tcp.local.",
        "_ipp._tcp.local.",
    ]

    def on_service_state_change(
        zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ):
        if state_change is not ServiceStateChange.Added:
            return
        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            return

        for addr_bytes in info.addresses:
            ip = socket.inet_ntoa(addr_bytes)
            svc_name = service_type.split(".")[0].lstrip("_")

            if ip in devices:
                devices[ip].merge(
                    DiscoveredDevice(
                        ip=ip,
                        hostname=info.server,
                        services=[svc_name],
                    )
                )
            else:
                devices[ip] = DiscoveredDevice(
                    ip=ip,
                    hostname=info.server,
                    services=[svc_name],
                )

    zc = Zeroconf()
    browsers = []
    for stype in service_types:
        browsers.append(ServiceBrowser(zc, stype, handlers=[on_service_state_change]))

    await asyncio.sleep(timeout)
    zc.close()

    return list(devices.values())


async def ssdp_discover(timeout: int = 3) -> list[DiscoveredDevice]:
    """Send UPnP/SSDP M-SEARCH and collect LOCATION URLs from responses."""
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    devices: dict[str, DiscoveredDevice] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 2))
    sock.settimeout(timeout)
    sock.sendto(MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                response = data.decode(errors="ignore")

                location = None
                for line in response.splitlines():
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        break

                if ip in devices:
                    if location and not devices[ip].upnp_location:
                        devices[ip].upnp_location = location
                    if "upnp" not in devices[ip].services:
                        devices[ip].services.append("upnp")
                else:
                    devices[ip] = DiscoveredDevice(
                        ip=ip,
                        upnp_location=location,
                        services=["upnp"],
                    )
            except socket.timeout:
                break
    finally:
        sock.close()

    return list(devices.values())


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
    subnet: str, timeout: int = 2, passive: bool = False
) -> list[DiscoveredDevice]:
    """Run all discovery methods concurrently and return merged results.

    TODO: Stage 2 — add port probing as an additional discovery step here.
    """
    _check_root()

    tasks = [
        arp_sweep(subnet, timeout),
        mdns_listen(timeout),
    ]

    if not passive:
        tasks.append(ssdp_discover(timeout=3))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    device_lists = []
    for result in results:
        if isinstance(result, Exception):
            # Silently skip failed discovery methods
            continue
        device_lists.append(result)

    return merge_devices(device_lists)
