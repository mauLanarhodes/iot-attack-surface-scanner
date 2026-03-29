"""Tests for the fingerprint module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from iotscanner.scanner.discovery import DiscoveredDevice
from iotscanner.scanner.fingerprint import (
    _oui_cache,
    fetch_upnp_xml,
    http_banner_grab,
    oui_lookup,
)

# Reset OUI cache before tests
import iotscanner.scanner.fingerprint as fp_module


SAMPLE_UPNP_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>Living Room Speaker</friendlyName>
    <manufacturer>Sonos Inc.</manufacturer>
    <modelName>Sonos One</modelName>
    <modelDescription>Smart Speaker</modelDescription>
    <modelNumber>S13</modelNumber>
  </device>
</root>
"""


class TestOuiLookup:
    def setup_method(self):
        # Reset the cache before each test
        fp_module._oui_cache = None

    def test_known_oui(self):
        """Known OUI prefix should return the correct vendor."""
        vendor = oui_lookup("DC:A6:32:00:00:01")
        assert vendor is not None
        assert "Raspberry Pi" in vendor

    def test_unknown_oui(self):
        """Unknown OUI prefix should return None, not raise an error."""
        vendor = oui_lookup("00:00:00:00:00:00")
        # 00:00:00 may or may not be in the DB, but it should not crash
        assert vendor is None or isinstance(vendor, str)

    def test_completely_fake_oui(self):
        """A fabricated OUI that definitely doesn't exist should return None."""
        vendor = oui_lookup("ZZ:ZZ:ZZ:00:00:00")
        assert vendor is None


class TestUpnpXmlParsing:
    def test_parse_upnp_xml(self):
        """UPnP XML should be parsed into device info fields."""
        mock_response = MagicMock()
        mock_response.content = SAMPLE_UPNP_XML
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("iotscanner.scanner.fingerprint.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(fetch_upnp_xml("http://192.168.1.10:8080/desc.xml"))

        assert result["friendly_name"] == "Living Room Speaker"
        assert result["manufacturer"] == "Sonos Inc."
        assert result["model_name"] == "Sonos One"
        assert result["model_description"] == "Smart Speaker"
        assert result["model_number"] == "S13"

    def test_fetch_failure_returns_empty(self):
        """If the HTTP fetch fails, return dict with None values."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("iotscanner.scanner.fingerprint.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(fetch_upnp_xml("http://192.168.1.10:8080/desc.xml"))

        assert result["friendly_name"] is None
        assert result["model_name"] is None
        assert result["manufacturer"] is None


class TestHttpBannerGrab:
    def test_banner_grab_success(self):
        """Should extract the Server header from HTTP response."""
        mock_response = MagicMock()
        mock_response.headers = {"server": "nginx/1.18.0"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("iotscanner.scanner.fingerprint.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(http_banner_grab("192.168.1.1"))

        assert result == "nginx/1.18.0"

    def test_banner_grab_no_server_header(self):
        """Should return None when no Server header present."""
        mock_response = MagicMock()
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("iotscanner.scanner.fingerprint.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(http_banner_grab("192.168.1.1"))

        assert result is None

    def test_banner_grab_connection_failure(self):
        """Should return None on connection failure."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("iotscanner.scanner.fingerprint.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.run(http_banner_grab("192.168.1.1"))

        assert result is None
