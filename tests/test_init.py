import asyncio
import contextlib
import logging
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from aiohttp import ClientError, ClientSession, ContentTypeError, TCPConnector
from aioresponses import aioresponses

import unifi_discovery
from unifi_discovery import (
    DISCOVERY_PORT,
    UBNT_V1_REQUEST,
    UBNT_V2_REQUEST,
    AIOUnifiScanner,
    UnifiDevice,
    UnifiDiscovery,
    UnifiService,
    _deduplicate_by_mac,
    _merge_devices,
    async_clear_cache,
    async_console_is_alive,
    create_udp_socket,
    parse_ubnt_response,
)

CONSOLE_EPHEMERAL_PORT = 44306


@pytest.fixture(autouse=True)
def _clear_scan_cache():
    """Clear the module-level scan cache between tests."""
    async_clear_cache()
    yield
    async_clear_cache()


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


@pytest_asyncio.fixture
async def mock_discovery_aio_protocol():
    """Fixture to mock an asyncio connection."""
    loop = asyncio.get_running_loop()
    future = asyncio.Future()

    async def _wait_for_connection():
        transport, protocol = await future
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return transport, protocol

    async def _mock_create_datagram_endpoint(func, sock=None):
        protocol: UnifiDiscovery = func()
        transport = MagicMock()
        protocol.connection_made(transport)
        if sock is not None:
            sock.close()
        with contextlib.suppress(asyncio.InvalidStateError):
            future.set_result((transport, protocol))
        return transport, protocol

    with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram_endpoint):
        yield _wait_for_connection


@pytest.mark.asyncio
async def test_async_scanner_specific_address(
    mock_discovery_aio_protocol, mock_aioresponse
):
    """Test scanner with a specific address."""
    scanner = AIOUnifiScanner()
    task = asyncio.ensure_future(
        scanner.async_scan(timeout=10, address="192.168.212.1", consoles_only=False)
    )
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        b"\x01\x00\x00\x8e\x02\x00\n\xe0c\xda\x00^\x08\xc0\xa8\xd4\x01\x01\x00\x06\xe0c\xda\x00^\x08\n\x00\x04\x00\x13\xe60\x0b\x00\x04Gate\x0c\x00\nUVC G4 Pro\x17\x00\x04\x00\x00\x00\x00\x03\x00'UVC.S5L.v4.46.18.67.ceacbaa.211202.1017\x10\x00\x02c\xa5 \x00$32f695ba-835b-5822-bc54-e290e1789ff1",
        ("192.168.212.1", DISCOVERY_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.212.1",
            hw_addr="e0:63:da:00:5e:08",
            ip_info=("e0:63:da:00:5e:08;192.168.212.1",),
            addr_entry=None,
            fw_version="UVC.S5L.v4.46.18.67.ceacbaa.211202.1017",
            mac_address=None,
            uptime=1304112,
            hostname="Gate",
            platform="UVC G4 Pro",
            model=None,
            signature_version="1",
        )
    ]


@pytest.mark.asyncio
async def test_async_scanner_broadcast(mock_discovery_aio_protocol, mock_aioresponse):
    """Test scanner with a broadcast."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=401)
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        payload={
            "hardware": {"shortname": "UDMPROSE"},
            "name": "UDM Pro SE",
            "mac": "245A4CDD6616",
            "isSingleUser": True,
            "isSsoEnabled": True,
            "directConnectDomain": "xyz.id.ui.direct",
        },
    )

    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01, consoles_only=False))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    protocol.datagram_received(
        b"",
        ("127.0.0.1", DISCOVERY_PORT),
    )
    protocol.datagram_received(
        None,
        ("127.0.0.1", DISCOVERY_PORT),
    )
    protocol.datagram_received(
        b"\x01\x00\x00\xa5\x01\x00\x06$ZLu\xba\xe6\x02\x00\n$ZLu\xba\xe6\xc0\xa8\xd5/\x03\x001UFP-UAP-B.MT7622_SOC.v0.4.0.4.340d302.220106.0349\x04\x00\x04\xc0\xa8\xd5/\x05\x00\x06$ZLu\xba\xe6\n\x00\x04\x00\x0c\xda/\x0b\x00\x11AlexanderTechRoom\x0c\x00\tUFP-UAP-B\x10\x00\x02\xa6 \x14\x00\x18Unifi-Protect-UAP-Bridge\x17\x00\x01\x00",
        ("192.168.213.252", DISCOVERY_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr="24:5a:4c:dd:66:16",
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname="UDM-Pro-SE",
            platform="UDMPROSE",
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: True,
                UnifiService.Access: True,
            },
            direct_connect_domain="xyz.id.ui.direct",
            is_sso_enabled=True,
            is_single_user=True,
        ),
        UnifiDevice(
            source_ip="192.168.213.252",
            hw_addr="24:5a:4c:75:ba:e6",
            ip_info=("24:5a:4c:75:ba:e6;192.168.213.47",),
            addr_entry="192.168.213.47",
            fw_version="UFP-UAP-B.MT7622_SOC.v0.4.0.4.340d302.220106.0349",
            mac_address="24:5a:4c:75:ba:e6",
            uptime=842287,
            hostname="AlexanderTechRoom",
            platform="UFP-UAP-B",
            model="Unifi-Protect-UAP-Bridge",
            signature_version="1",
            services={
                UnifiService.Protect: False,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        ),
    ]


@pytest.mark.asyncio
async def test_async_scanner_no_system_response(
    mock_discovery_aio_protocol, mock_aioresponse
):
    """Test scanner with a broadcast when the system api does not response."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/api/system", status=404)

    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01, consoles_only=False))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    protocol.datagram_received(
        b"",
        ("127.0.0.1", DISCOVERY_PORT),
    )
    protocol.datagram_received(
        None,
        ("127.0.0.1", DISCOVERY_PORT),
    )
    protocol.datagram_received(
        b"\x01\x00\x00\xa5\x01\x00\x06$ZLu\xba\xe6\x02\x00\n$ZLu\xba\xe6\xc0\xa8\xd5/\x03\x001UFP-UAP-B.MT7622_SOC.v0.4.0.4.340d302.220106.0349\x04\x00\x04\xc0\xa8\xd5/\x05\x00\x06$ZLu\xba\xe6\n\x00\x04\x00\x0c\xda/\x0b\x00\x11AlexanderTechRoom\x0c\x00\tUFP-UAP-B\x10\x00\x02\xa6 \x14\x00\x18Unifi-Protect-UAP-Bridge\x17\x00\x01\x00",
        ("192.168.213.252", DISCOVERY_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr=None,
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname=None,
            platform=None,
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        ),
        UnifiDevice(
            source_ip="192.168.213.252",
            hw_addr="24:5a:4c:75:ba:e6",
            ip_info=("24:5a:4c:75:ba:e6;192.168.213.47",),
            addr_entry="192.168.213.47",
            fw_version="UFP-UAP-B.MT7622_SOC.v0.4.0.4.340d302.220106.0349",
            mac_address="24:5a:4c:75:ba:e6",
            uptime=842287,
            hostname="AlexanderTechRoom",
            platform="UFP-UAP-B",
            model="Unifi-Protect-UAP-Bridge",
            signature_version="1",
            services={
                UnifiService.Protect: False,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        ),
    ]


@pytest.mark.asyncio
async def test_async_scanner_system_api_missing_mac(
    mock_discovery_aio_protocol, mock_aioresponse
):
    """Test scanner with a broadcast when the system api responds but no mac."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        payload={
            "hardware": {"shortname": "UCKP"},
            "name": "UniFi-CloudKey-Gen2-Plus",
        },
    )
    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr=None,
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname="UniFi-CloudKey-Gen2-Plus",
            platform="UCKP",
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        )
    ]


@pytest.mark.asyncio
async def test_async_scanner_system_api_returns_html(
    mock_discovery_aio_protocol, mock_aioresponse, caplog
):
    """Test scanner with a broadcast when the system api responds but no mac."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        exception=ContentTypeError,
    )
    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr=None,
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname=None,
            platform=None,
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        )
    ]


@pytest.mark.asyncio
async def test_async_scanner_access_service_detected(
    mock_discovery_aio_protocol, mock_aioresponse
) -> None:
    """Test scanner detects Access service."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=401)
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        payload={
            "hardware": {"shortname": "UNVR"},
            "name": "UNVR",
            "mac": "E4388332C9B1",
            "isSingleUser": False,
            "isSsoEnabled": True,
            "directConnectDomain": "abc.id.ui.direct",
        },
    )
    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr="e4:38:83:32:c9:b1",
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname="UNVR",
            platform="UNVR",
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: True,
                UnifiService.Access: True,
            },
            direct_connect_domain="abc.id.ui.direct",
            is_sso_enabled=True,
            is_single_user=False,
        )
    ]


@pytest.mark.asyncio
async def test_async_scanner_access_service_not_available(
    mock_discovery_aio_protocol, mock_aioresponse
) -> None:
    """Test scanner when Access service is not available."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get(
        "https://192.168.203.1/proxy/protect/api", exception=ClientError
    )
    mock_aioresponse.get(
        "https://192.168.203.1/proxy/network/api", exception=ClientError
    )
    mock_aioresponse.get(
        "https://192.168.203.1/proxy/access/api", exception=ClientError
    )
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        payload={
            "hardware": {"shortname": "UCKP"},
            "name": "CloudKey",
            "mac": "28704E522AFF",
        },
    )
    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01, consoles_only=False))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    await task
    assert scanner.found_devices == [
        UnifiDevice(
            source_ip="192.168.203.1",
            hw_addr="28:70:4e:52:2a:ff",
            ip_info=None,
            addr_entry=None,
            fw_version=None,
            mac_address=None,
            uptime=None,
            hostname="CloudKey",
            platform="UCKP",
            model=None,
            signature_version=None,
            services={
                UnifiService.Protect: False,
                UnifiService.Network: False,
                UnifiService.Access: False,
            },
            direct_connect_domain=None,
            is_sso_enabled=None,
            is_single_user=None,
        )
    ]


@pytest.mark.asyncio
async def test_async_scanner_falls_back_to_any_source_port_if_socket_in_use():
    """Test port fallback."""
    hold_socket = create_udp_socket(DISCOVERY_PORT)
    assert hold_socket.getsockname() == ("0.0.0.0", DISCOVERY_PORT)
    random_socket = create_udp_socket(DISCOVERY_PORT)
    assert random_socket.getsockname() is not None


@pytest.mark.asyncio
async def test_async_console_is_alive(mock_aioresponse):
    """Test if a console is alive."""
    mock_aioresponse.get("https://1.2.3.1/api/system", status=401)
    mock_aioresponse.get("https://1.2.3.2/api/system", status=200)
    mock_aioresponse.get("https://1.2.3.3/api/system", exception=ClientError)
    mock_aioresponse.get("https://1.2.3.4/api/system", exception=asyncio.TimeoutError)

    async with ClientSession(connector=TCPConnector(ssl=False)) as session:
        assert await async_console_is_alive(session, "1.2.3.1") is True
        assert await async_console_is_alive(session, "1.2.3.2") is True
        assert await async_console_is_alive(session, "1.2.3.3") is False
        assert await async_console_is_alive(session, "1.2.3.4") is False


@pytest.mark.asyncio
async def test_async_scan_caches_broadcast_results(
    mock_discovery_aio_protocol, mock_aioresponse, monkeypatch
):
    """Test that broadcast scans are cached and not repeated."""
    # Drop the min-timeout threshold so the fast test scan is still cacheable.
    monkeypatch.setattr("unifi_discovery.SCAN_CACHE_MIN_TIMEOUT", 0)
    scanner1 = AIOUnifiScanner()
    scanner2 = AIOUnifiScanner()

    # Register HTTP mocks up front so the scan's probe phase cannot race
    # against fixture setup.
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/api/system", status=404)

    task = asyncio.ensure_future(scanner1.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    result1 = await task

    # Second scan: should return cached results without new network activity
    result2 = await scanner2.async_scan(timeout=0.01)

    assert result1 == result2
    assert len(result1) == 1

    # Mutating a cached device must raise since UnifiDevice is frozen
    with pytest.raises(AttributeError):
        result1[0].services = {}
    # The services mapping itself must also be immutable
    with pytest.raises(TypeError):
        result1[0].services[UnifiService.Protect] = False


@pytest.mark.asyncio
async def test_async_scan_short_timeout_bypasses_cache_and_warns(
    mock_discovery_aio_protocol, mock_aioresponse, caplog
):
    """Scans below SCAN_CACHE_MIN_TIMEOUT skip the cache and log a warning."""
    scanner = AIOUnifiScanner()
    caplog.set_level(logging.WARNING, logger="unifi_discovery")

    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get("https://192.168.203.1/api/system", status=404)
    await task

    # Cache must be empty — short scan should not populate it.
    assert unifi_discovery._scan_cache is None
    # And the user must have been warned.
    assert any(
        "SCAN_CACHE_MIN_TIMEOUT" in rec.message and rec.levelname == "WARNING"
        for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_async_scanner_consoles_only_filters(
    mock_discovery_aio_protocol, mock_aioresponse
):
    """Test that consoles_only=True (default) filters out non-console devices."""
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.203.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/network/api", status=401)
    mock_aioresponse.get("https://192.168.203.1/proxy/access/api", status=404)
    mock_aioresponse.get(
        "https://192.168.203.1/api/system",
        payload={
            "hardware": {"shortname": "UDMPROSE"},
            "name": "UDM Pro SE",
            "mac": "245A4CDD6616",
        },
    )

    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    # Console echo (detected as console)
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.203.1", CONSOLE_EPHEMERAL_PORT),
    )
    # Non-console V1 device (camera)
    protocol.datagram_received(
        b"\x01\x00\x00\x8e\x02\x00\n\xe0c\xda\x00^\x08\xc0\xa8\xd4\x01\x01\x00\x06\xe0c\xda\x00^\x08\n\x00\x04\x00\x13\xe60\x0b\x00\x04Gate\x0c\x00\nUVC G4 Pro\x17\x00\x04\x00\x00\x00\x00\x03\x00'UVC.S5L.v4.46.18.67.ceacbaa.211202.1017\x10\x00\x02c\xa5 \x00$32f695ba-835b-5822-bc54-e290e1789ff1",
        ("192.168.212.1", DISCOVERY_PORT),
    )
    await task
    # Default: only console returned
    assert len(scanner.found_devices) == 1
    assert scanner.found_devices[0].source_ip == "192.168.203.1"
    assert scanner.found_devices[0].services[UnifiService.Protect] is True


@pytest.mark.asyncio
async def test_async_scanner_console_v1_echo_plus_v2_response(
    mock_discovery_aio_protocol, mock_aioresponse
):
    """
    Test console detected via V1 echo still gets service-probed after V2 merge.

    Consoles echo the V1 request from an ephemeral port (signature_version=None)
    AND respond to V2 requests with product_name/version. After merging,
    the console must still be identified and probed for services.
    """
    scanner = AIOUnifiScanner()
    mock_aioresponse.get("https://192.168.7.1/proxy/protect/api", status=401)
    mock_aioresponse.get("https://192.168.7.1/proxy/network/api", status=401)
    mock_aioresponse.get("https://192.168.7.1/proxy/access/api", status=404)
    mock_aioresponse.get(
        "https://192.168.7.1/api/system",
        payload={
            "hardware": {"shortname": "UDMPROMAX"},
            "name": "UDM Pro Max",
            "mac": "E063DA005E08",
            "isSingleUser": True,
            "isSsoEnabled": True,
            "directConnectDomain": "test.id.ui.direct",
        },
    )
    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    # Console echoes V1 request from ephemeral port (creates device with sig=None)
    protocol.datagram_received(
        UBNT_V1_REQUEST,
        ("192.168.7.1", CONSOLE_EPHEMERAL_PORT),
    )
    # Console also responds to V2 with real fields (merges into same device)
    protocol.datagram_received(
        V2_RESPONSE,
        ("192.168.7.1", DISCOVERY_PORT),
    )
    await task
    assert len(scanner.found_devices) == 1
    device = scanner.found_devices[0]
    # V2 fields merged in
    assert device.product_name == "UDMPROMAX"
    assert device.version == "10.3.47"
    # Services were probed (the critical assertion — would fail without the fix)
    assert device.services == {
        UnifiService.Protect: True,
        UnifiService.Network: True,
        UnifiService.Access: False,
    }
    # System API data merged
    assert device.hostname == "UDM-Pro-Max"
    assert device.platform == "UDMPROMAX"
    assert device.hw_addr == "e0:63:da:00:5e:08"
    assert device.direct_connect_domain == "test.id.ui.direct"


# --- V2 response test payload ---
# Version=2, Command=9, data_len=39
# Fields: hw_addr(0x01), product_name(0x15), version(0x16), fw_version(0x03)
V2_RESPONSE = (
    b"\x02\x09"  # version=2, command=9
    b"\x00\x27"  # data_len=39
    b"\x01\x00\x06\xe0\x63\xda\x00\x5e\x08"  # 0x01 hw_addr
    b"\x15\x00\x09UDMPROMAX"  # 0x15 product_name
    b"\x16\x00\x07"
    b"10.3.47"  # 0x16 version
    b"\x03\x00\x05"
    b"7.0.0"  # 0x03 fw_version
)

# --- V0 response test payload (UNVR-like) ---
# Version=0, Command=0, data_len=26
# Fields: hw_addr(0x01), product_name(0x15), version(0x16)
V0_RESPONSE = (
    b"\x00\x00"  # version=0, command=0
    b"\x00\x1a"  # data_len=26
    b"\x01\x00\x06\xe4\x38\x83\x32\xc9\xb1"  # 0x01 hw_addr
    b"\x15\x00\x04UNVR"  # 0x15 product_name
    b"\x16\x00\x07"
    b"v4.2.16"  # 0x16 version
)

# --- V2 response with unknown fields (seq, source_mac, is_default) ---
V2_RESPONSE_WITH_EXTRA_FIELDS = (
    b"\x02\x06"  # version=2, command=6
    b"\x00\x1b"  # data_len=27
    b"\x01\x00\x06\xe0\x63\xda\x00\x5e\x08"  # 0x01 hw_addr (9 bytes)
    b"\x12\x00\x02\x00\x01"  # 0x12 seq=1 (5 bytes)
    b"\x13\x00\x06\xe0\x63\xda\x00\x5e\x08"  # 0x13 source_mac (9 bytes)
    b"\x17\x00\x01\x00"  # 0x17 is_default=False (4 bytes)
)


def test_parse_v1_response():
    """Test parsing a standard V1 response."""
    payload = (
        b"\x01\x00\x00\x8e"
        b"\x02\x00\n\xe0c\xda\x00^\x08\xc0\xa8\xd4\x01"
        b"\x01\x00\x06\xe0c\xda\x00^\x08"
        b"\n\x00\x04\x00\x13\xe60"
        b"\x0b\x00\x04Gate"
        b"\x0c\x00\nUVC G4 Pro"
        b"\x17\x00\x04\x00\x00\x00\x00"
        b"\x03\x00'UVC.S5L.v4.46.18.67.ceacbaa.211202.1017"
        b"\x10\x00\x02c\xa5"
        b" \x00$32f695ba-835b-5822-bc54-e290e1789ff1"
    )
    device = parse_ubnt_response(payload, ("192.168.212.1", DISCOVERY_PORT))
    assert device is not None
    assert device.source_ip == "192.168.212.1"
    assert device.hw_addr == "e0:63:da:00:5e:08"
    assert device.hostname == "Gate"
    assert device.platform == "UVC G4 Pro"
    assert device.signature_version == "1"
    assert device.product_name is None
    assert device.version is None


def test_parse_v2_response():
    """Test parsing a V2 discovery response."""
    device = parse_ubnt_response(V2_RESPONSE, ("192.168.7.1", DISCOVERY_PORT))
    assert device is not None
    assert device.source_ip == "192.168.7.1"
    assert device.hw_addr == "e0:63:da:00:5e:08"
    assert device.product_name == "UDMPROMAX"
    assert device.version == "10.3.47"
    assert device.fw_version == "7.0.0"
    assert device.signature_version == "2"


def test_parse_v0_response():
    """Test parsing a V0 response (e.g. UNVR)."""
    device = parse_ubnt_response(V0_RESPONSE, ("192.168.7.8", 35827))
    assert device is not None
    assert device.source_ip == "192.168.7.8"
    assert device.hw_addr == "e4:38:83:32:c9:b1"
    assert device.product_name == "UNVR"
    assert device.version == "v4.2.16"
    assert device.signature_version == "0"


def test_parse_v2_response_ignores_unknown_field_ids():
    """Test that V2 response with unknown field IDs doesn't crash."""
    # 0x12 (seq) and 0x13 (source_mac) are known protocol fields
    # but not mapped to UnifiDevice — they should be silently skipped
    device = parse_ubnt_response(
        V2_RESPONSE_WITH_EXTRA_FIELDS, ("192.168.7.1", DISCOVERY_PORT)
    )
    assert device is not None
    assert device.hw_addr == "e0:63:da:00:5e:08"
    assert device.signature_version == "2"


def test_parse_response_none_payload():
    """Test parsing None payload."""
    assert parse_ubnt_response(None, ("192.168.1.1", DISCOVERY_PORT)) is None


def test_parse_response_too_short():
    """Test parsing too-short payload."""
    assert parse_ubnt_response(b"\x01\x00", ("192.168.1.1", DISCOVERY_PORT)) is None


def test_parse_response_unknown_version():
    """Test parsing unknown version/command combination."""
    payload = b"\x05\x00\x00\x00"  # version 5, not valid
    assert parse_ubnt_response(payload, ("192.168.1.1", DISCOVERY_PORT)) is None


def test_parse_response_truncated_payload():
    """Test that a truncated payload (data_len > actual data) doesn't crash."""
    # Header claims 100 bytes of data but only 9 bytes follow
    payload = (
        b"\x01\x00"  # version=1, command=0
        b"\x00\x64"  # data_len=100 (lie)
        b"\x01\x00\x06\xe0\x63\xda\x00\x5e\x08"  # 0x01 hw_addr (only 9 bytes)
    )
    device = parse_ubnt_response(payload, ("192.168.1.1", DISCOVERY_PORT))
    assert device is not None
    assert device.hw_addr == "e0:63:da:00:5e:08"
    assert device.signature_version == "1"


def test_parse_v2_echo_rejected():
    """
    Test that a V2 request echo (command=8) is not parsed as a response.

    Consoles echo incoming packets from an ephemeral port. Our V2 request
    (version=2, command=8, data_len=0) must not be mistaken for a V2 response.
    """
    assert parse_ubnt_response(UBNT_V2_REQUEST, ("192.168.7.1", 44306)) is None


def test_merge_devices():
    """Test merging V1 and V2 device records is order-independent."""
    v1_device = UnifiDevice(
        source_ip="192.168.7.1",
        hw_addr="e0:63:da:00:5e:08",
        ip_info=("e0:63:da:00:5e:08;192.168.7.1",),
        hostname="UDM",
        platform="UDMPROMAX",
        uptime=12345,
        fw_version="7.0.0",
        signature_version="1",
    )
    v2_device = UnifiDevice(
        source_ip="192.168.7.1",
        hw_addr="e0:63:da:00:5e:08",
        product_name="UDMPROMAX",
        version="10.3.47",
        fw_version="7.0.0",
        signature_version="2",
    )
    merged_v1_first = _merge_devices(v1_device, v2_device)
    merged_v2_first = _merge_devices(v2_device, v1_device)

    # Both orders should produce equivalent results
    assert merged_v1_first.hostname == "UDM"
    assert merged_v1_first.platform == "UDMPROMAX"
    assert merged_v1_first.uptime == 12345
    assert merged_v1_first.product_name == "UDMPROMAX"
    assert merged_v1_first.version == "10.3.47"
    assert merged_v1_first.hw_addr == "e0:63:da:00:5e:08"
    assert merged_v1_first.fw_version == "7.0.0"

    assert merged_v2_first.hostname == "UDM"
    assert merged_v2_first.platform == "UDMPROMAX"
    assert merged_v2_first.uptime == 12345
    assert merged_v2_first.product_name == "UDMPROMAX"
    assert merged_v2_first.version == "10.3.47"
    assert merged_v2_first.hw_addr == "e0:63:da:00:5e:08"
    assert merged_v2_first.fw_version == "7.0.0"


def test_merge_devices_ip_info_dedup():
    """Test that merging devices deduplicates ip_info entries."""
    d1 = UnifiDevice(
        source_ip="10.0.0.1",
        ip_info=("aa:bb:cc:dd:ee:ff;10.0.0.1", "aa:bb:cc:dd:ee:ff;10.0.0.2"),
    )
    d2 = UnifiDevice(
        source_ip="10.0.0.1",
        ip_info=("aa:bb:cc:dd:ee:ff;10.0.0.1", "aa:bb:cc:dd:ee:ff;10.0.0.3"),
    )
    merged = _merge_devices(d1, d2)
    assert merged.ip_info == (
        "aa:bb:cc:dd:ee:ff;10.0.0.1",
        "aa:bb:cc:dd:ee:ff;10.0.0.2",
        "aa:bb:cc:dd:ee:ff;10.0.0.3",
    )


def test_deduplicate_by_mac():
    """Test that devices with the same MAC from different VLANs are deduplicated."""
    response_list = {
        # Primary: rich V2 response
        "192.168.7.1": UnifiDevice(
            source_ip="192.168.7.1",
            hw_addr="58:d6:1f:3b:c1:f4",
            product_name="UDMPROMAX",
            version="10.3.47",
            fw_version="7.0.0",
            signature_version="2",
            ip_info=("58:d6:1f:3b:c1:f4;192.168.7.1",),
            services={
                UnifiService.Protect: True,
                UnifiService.Network: True,
                UnifiService.Access: False,
            },
        ),
        # VLAN echo with hostname from system API
        "192.168.23.1": UnifiDevice(
            source_ip="192.168.23.1",
            hw_addr="58:d6:1f:3b:c1:f4",
            hostname="UDMP-Max",
            platform="UDMPROMAX",
            signature_version=None,
            services={
                UnifiService.Protect: True,
                UnifiService.Network: True,
                UnifiService.Access: True,
            },
        ),
        # Another VLAN echo (bare)
        "192.168.90.1": UnifiDevice(
            source_ip="192.168.90.1",
            hw_addr="58:d6:1f:3b:c1:f4",
            signature_version=None,
        ),
        # Different device — must not be affected
        "192.168.7.99": UnifiDevice(
            source_ip="192.168.7.99",
            hw_addr="68:d7:9a:e2:45:57",
            hostname="Camera",
            signature_version="1",
        ),
    }

    _deduplicate_by_mac(response_list)

    # VLAN duplicates removed
    assert "192.168.23.1" not in response_list
    assert "192.168.90.1" not in response_list
    # Primary kept with merged fields
    assert "192.168.7.1" in response_list
    primary = response_list["192.168.7.1"]
    assert primary.product_name == "UDMPROMAX"
    assert primary.version == "10.3.47"
    assert primary.hostname == "UDMP-Max"  # merged from VLAN echo
    # Services: Access was True in VLAN echo, should be merged
    assert primary.services[UnifiService.Access] is True
    # Unrelated device untouched
    assert "192.168.7.99" in response_list
    assert response_list["192.168.7.99"].hostname == "Camera"


def test_deduplicate_by_mac_no_hwaddr():
    """Test that devices without hw_addr are not deduplicated."""
    response_list = {
        "192.168.17.1": UnifiDevice(
            source_ip="192.168.17.1",
            hw_addr=None,
            signature_version=None,
        ),
        "192.168.7.1": UnifiDevice(
            source_ip="192.168.7.1",
            hw_addr=None,
            signature_version=None,
        ),
    }

    _deduplicate_by_mac(response_list)

    # Both kept — can't deduplicate without MAC
    assert len(response_list) == 2
