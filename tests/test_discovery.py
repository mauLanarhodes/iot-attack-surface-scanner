"""Tests for the discovery module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from iotscanner.scanner.discovery import (
    DiscoveredDevice,
    arp_sweep,
    merge_devices,
    run_discovery,
)


def _make_arp_reply(ip: str, mac: str):
    """Create a mock Scapy ARP reply packet."""
    reply = MagicMock()
    reply.psrc = ip
    reply.hwsrc = mac
    return reply


class TestArpSweep:
    @patch("scapy.all.srp")
    def test_arp_returns_devices(self, mock_srp):
        """ARP sweep should return DiscoveredDevice objects from replies."""
        replies = [
            (MagicMock(), _make_arp_reply("192.168.1.1", "A4:91:B1:00:00:01")),
            (MagicMock(), _make_arp_reply("192.168.1.42", "DC:A6:32:00:00:02")),
            (MagicMock(), _make_arp_reply("192.168.1.77", "50:C7:BF:00:00:03")),
        ]
        mock_srp.return_value = (replies, [])

        devices = asyncio.run(arp_sweep("192.168.1.0/24", timeout=1))

        assert len(devices) == 3
        assert devices[0].ip == "192.168.1.1"
        assert devices[0].mac == "A4:91:B1:00:00:01"
        assert devices[1].ip == "192.168.1.42"
        assert devices[2].ip == "192.168.1.77"

    @patch("scapy.all.srp")
    def test_arp_empty_network(self, mock_srp):
        """ARP sweep should return empty list when no replies."""
        mock_srp.return_value = ([], [])
        devices = asyncio.run(arp_sweep("10.0.0.0/24", timeout=1))
        assert devices == []


class TestMergeDevices:
    def test_merge_by_ip(self):
        """Devices from different sources with the same IP should merge."""
        arp_devices = [
            DiscoveredDevice(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01"),
        ]
        mdns_devices = [
            DiscoveredDevice(
                ip="192.168.1.1",
                hostname="router.local",
                services=["http"],
            ),
        ]

        merged = merge_devices([arp_devices, mdns_devices])

        assert len(merged) == 1
        assert merged[0].ip == "192.168.1.1"
        assert merged[0].mac == "AA:BB:CC:DD:EE:01"
        assert merged[0].hostname == "router.local"
        assert "http" in merged[0].services

    def test_merge_different_ips(self):
        """Devices with different IPs should not merge."""
        list1 = [DiscoveredDevice(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01")]
        list2 = [DiscoveredDevice(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:02")]

        merged = merge_devices([list1, list2])
        assert len(merged) == 2

    def test_merge_services_deduplicated(self):
        """Merging should not duplicate services."""
        list1 = [DiscoveredDevice(ip="192.168.1.1", services=["http", "upnp"])]
        list2 = [DiscoveredDevice(ip="192.168.1.1", services=["http", "mdns"])]

        merged = merge_devices([list1, list2])
        assert len(merged) == 1
        assert sorted(merged[0].services) == ["http", "mdns", "upnp"]


class TestPassiveFlag:
    @patch("iotscanner.scanner.discovery.ssdp_discover")
    @patch("iotscanner.scanner.discovery.mdns_listen")
    @patch("iotscanner.scanner.discovery.arp_sweep")
    @patch("iotscanner.scanner.discovery.os.geteuid", return_value=0)
    def test_passive_skips_ssdp(self, mock_euid, mock_arp, mock_mdns, mock_ssdp):
        """With passive=True, SSDP discovery should not be called."""
        mock_arp.return_value = []
        mock_mdns.return_value = []
        mock_ssdp.return_value = []

        asyncio.run(run_discovery("192.168.1.0/24", timeout=1, passive=True))

        mock_arp.assert_called_once()
        mock_mdns.assert_called_once()
        mock_ssdp.assert_not_called()

    @patch("iotscanner.scanner.discovery.ssdp_discover")
    @patch("iotscanner.scanner.discovery.mdns_listen")
    @patch("iotscanner.scanner.discovery.arp_sweep")
    @patch("iotscanner.scanner.discovery.os.geteuid", return_value=0)
    def test_active_includes_ssdp(self, mock_euid, mock_arp, mock_mdns, mock_ssdp):
        """Without passive flag, SSDP discovery should be called."""
        mock_arp.return_value = []
        mock_mdns.return_value = []
        mock_ssdp.return_value = []

        asyncio.run(run_discovery("192.168.1.0/24", timeout=1, passive=False))

        mock_ssdp.assert_called_once()
