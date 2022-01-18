import asyncio
import contextlib
from unittest.mock import MagicMock, patch

import pytest

from unifi_discovery import (
    DISCOVERY_PORT,
    UBNT_REQUEST_PAYLOAD,
    AIOUnifiScanner,
    UnifiDevice,
    UnifiDiscovery,
    create_udp_socket,
)


@pytest.fixture
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
        with contextlib.suppress(asyncio.InvalidStateError):
            future.set_result((transport, protocol))
        return transport, protocol

    with patch.object(loop, "create_datagram_endpoint", _mock_create_datagram_endpoint):
        yield _wait_for_connection


@pytest.mark.asyncio
async def test_async_scanner_specific_address(mock_discovery_aio_protocol):
    """Test scanner with a specific address."""
    scanner = AIOUnifiScanner()

    task = asyncio.ensure_future(
        scanner.async_scan(timeout=10, address="192.168.212.1")
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
            ip_info=["e0:63:da:00:5e:08;192.168.212.1"],
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
async def test_async_scanner_broadcast(mock_discovery_aio_protocol):
    """Test scanner with a broadcast."""
    scanner = AIOUnifiScanner()

    task = asyncio.ensure_future(scanner.async_scan(timeout=0.01))
    _, protocol = await mock_discovery_aio_protocol()
    protocol.datagram_received(
        UBNT_REQUEST_PAYLOAD,
        ("192.168.203.1", DISCOVERY_PORT),
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
            signature_version="1",
        ),
        UnifiDevice(
            source_ip="192.168.213.252",
            hw_addr="24:5a:4c:75:ba:e6",
            ip_info=["24:5a:4c:75:ba:e6;192.168.213.47"],
            addr_entry="192.168.213.47",
            fw_version="UFP-UAP-B.MT7622_SOC.v0.4.0.4.340d302.220106.0349",
            mac_address="24:5a:4c:75:ba:e6",
            uptime=842287,
            hostname="AlexanderTechRoom",
            platform="UFP-UAP-B",
            model="Unifi-Protect-UAP-Bridge",
            signature_version="1",
        ),
    ]


@pytest.mark.asyncio
async def test_async_scanner_falls_back_to_any_source_port_if_socket_in_use():
    """Test port fallback."""
    hold_socket = create_udp_socket(DISCOVERY_PORT)
    assert hold_socket.getsockname() == ("0.0.0.0", DISCOVERY_PORT)
    random_socket = create_udp_socket(DISCOVERY_PORT)
    assert random_socket.getsockname() is not None
