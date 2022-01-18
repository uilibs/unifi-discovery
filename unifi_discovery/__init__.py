from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass
from struct import unpack
from typing import Callable, cast

_LOGGER = logging.getLogger(__name__)

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = b"\x01\x00\x00\x00"
UBNT_V1_SIGNATURE = b"\x01\x00\x00"
DISCOVERY_PORT = 10001
BROADCAST_FREQUENCY = 3


def mac_repr(data):
    return ":".join(("%02x" % b) for b in data)


def ip_repr(data):
    return ".".join(("%d" % b) for b in data)


# field type -> (field name; parsing function (bytes->str); \
#                is it expected to be seen multiple times?)
FIELD_PARSERS = {
    0x01: ("hw_addr", mac_repr, False),
    0x02: (
        "ip_info",
        lambda data: f"{mac_repr(data[0:6])};{ip_repr(data[6:10])}",
        True,
    ),
    0x03: ("fw_version", bytes.decode, False),
    0x04: ("addr_entry", ip_repr, False),
    0x05: ("mac_address", mac_repr, False),
    0x0A: ("uptime", lambda data: int.from_bytes(data, "big"), False),
    0x0B: ("hostname", bytes.decode, False),
    0x0C: ("platform", bytes.decode, False),
    0x14: ("model", bytes.decode, False),
}


@dataclass
class UnifiDevice:
    """A device discovered."""

    source_ip: str
    hw_addr: str | None = None
    ip_info: list[str] | None = None
    addr_entry: str | None = None
    fw_version: str | None = None
    mac_address: str | None = None
    uptime: str | None = None
    hostname: str | None = None
    platform: str | None = None
    model: str | None = None
    signature_version: str | None = None


def async_get_source_ip(target_ip: str) -> str | None:
    """Return the source ip that will reach target_ip."""
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.setblocking(False)  # must be non-blocking for async
    try:
        test_sock.connect((target_ip, 1))
        return cast(str, test_sock.getsockname()[0])
    except Exception:  # pylint: disable=broad-except
        _LOGGER.debug(
            "The system could not auto detect the source ip for %s on your operating system",
            target_ip,
        )
        return None
    finally:
        test_sock.close()


def iter_fields(data, _len):
    pointer = 0
    while pointer < _len:
        fieldType, fieldLen = unpack(">BH", data[pointer : pointer + 3])
        pointer += 3
        fieldData = data[pointer : pointer + fieldLen]
        pointer += fieldLen
        yield fieldType, fieldData


def parse_ubnt_response(
    payload: bytes | None, from_address: tuple[str, int]
) -> UnifiDevice | None:
    # We received a broadcast packet in reply to our discovery
    fields: dict[str, str | list[str]] = {"source_ip": from_address[0]}

    if payload is None or len(payload) < 4:
        return None
    if (
        payload[0:4] == UBNT_REQUEST_PAYLOAD and from_address[1] != DISCOVERY_PORT
    ):  # Check for a UBNT discovery request
        # (first 4 bytes of the payload should be \x01\x00\x00\x00)
        return UnifiDevice(**fields)  # type: ignore
    elif payload[0:3] == UBNT_V1_SIGNATURE:  # Check for a valid UBNT discovery reply
        # (first 3 bytes of the payload should be \x01\x00\x00)
        fields["signature_version"] = "1"  # this is not always correct
        field_parsers_packet_specific = {**FIELD_PARSERS}
    else:
        return None

    # Walk the reply payload, staring from offset 04
    # (just after reply signature and payload size).
    # Take into account the payload length in offset 3
    for field_type, field_data in iter_fields(payload[4:], payload[3]):

        if field_type not in field_parsers_packet_specific:
            continue

        # Parse the field and store in Device
        field_name, field_parser, is_many = field_parsers_packet_specific[field_type]
        value = field_parser(field_data)  # type: ignore
        if is_many:
            if field_name not in fields:
                fields[field_name] = []
            field_list = fields[field_name]
            assert not isinstance(field_list, str)
            field_list.append(value)
        else:
            fields[field_name] = value

    return UnifiDevice(**fields)  # type: ignore


def create_udp_socket(discovery_port: int) -> socket.socket:
    """Create a udp socket used for communicating with the device."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # Legacy devices require source port to be the discovery port
        sock.bind(("", discovery_port))
    except OSError as err:
        _LOGGER.debug("Port %s is not available: %s", discovery_port, err)
        sock.bind(("", 0))
    sock.setblocking(False)
    return sock


class UnifiDiscovery(asyncio.DatagramProtocol):
    def __init__(
        self,
        destination: tuple[str, int],
        on_response: Callable[[bytes, tuple[str, int]], None],
    ) -> None:
        self.transport = None
        self.destination = destination
        self.on_response = on_response

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Trigger on_response."""
        self.on_response(data, addr)

    def error_received(self, ex: Exception | None) -> None:
        """Handle error."""
        _LOGGER.error("UnifiDiscovery error: %s", ex)

    def connection_lost(self, ex: Exception | None) -> None:
        """Do nothing on connection lost."""


class AIOUnifiScanner:
    """A unifi discovery scanner."""

    def __init__(self) -> None:
        self.found_devices: list[UnifiDevice] = []
        self.source_ip: str | None = None

    def _destination_from_address(self, address: str | None) -> tuple[str, int]:
        if address is None:
            address = "<broadcast>"
        return (address, DISCOVERY_PORT)

    def _process_response(
        self,
        data: bytes | None,
        from_address: tuple[str, int],
        address: str | None,
        response_list: dict[str, UnifiDevice],
    ) -> bool:
        """Process a response.

        Returns True if processing should stop
        """
        if from_address[0] == self.source_ip:
            return False
        response = parse_ubnt_response(data, from_address)
        if response is not None:
            response_list[from_address[0]] = response
            return from_address[0] == address
        return False

    async def _async_run_scan(
        self,
        transport: asyncio.DatagramTransport,
        destination: tuple[str, int],
        timeout: int,
        found_all_future: "asyncio.Future[bool]",
    ) -> None:
        """Send the scans."""
        self.source_ip = async_get_source_ip("255.255.255.255")
        _LOGGER.debug("discover: %s => %s", destination, UBNT_REQUEST_PAYLOAD)
        transport.sendto(UBNT_REQUEST_PAYLOAD, destination)
        quit_time = time.monotonic() + timeout
        remain_time = float(timeout)
        while True:
            time_out = min(remain_time, timeout / BROADCAST_FREQUENCY)
            if time_out <= 0:
                return
            try:
                await asyncio.wait_for(
                    asyncio.shield(found_all_future), timeout=time_out
                )
            except asyncio.TimeoutError:
                if time.monotonic() >= quit_time:
                    return
                # No response, send broadcast again in cast it got lost
                _LOGGER.debug("discover: %s => %s", destination, UBNT_REQUEST_PAYLOAD)
                transport.sendto(UBNT_REQUEST_PAYLOAD, destination)
            else:
                return  # found_all
            remain_time = quit_time - time.monotonic()

    async def async_scan(
        self, timeout: int = 10, address: str | None = None
    ) -> list[UnifiDevice]:
        """Discover on port 10001."""
        sock = create_udp_socket(DISCOVERY_PORT)
        destination = self._destination_from_address(address)
        found_all_future: asyncio.Future[bool] = asyncio.Future()
        response_list: dict[str, UnifiDevice] = {}

        def _on_response(data: bytes, addr: tuple[str, int]) -> None:
            _LOGGER.debug("discover: %s <= %s", addr, data)
            if self._process_response(data, addr, address, response_list):
                found_all_future.set_result(True)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UnifiDiscovery(
                destination=destination,
                on_response=_on_response,
            ),
            sock=sock,
        )
        try:
            await self._async_run_scan(
                cast(asyncio.DatagramTransport, transport),
                destination,
                timeout,
                found_all_future,
            )
        finally:
            transport.close()

        self.found_devices = list(response_list.values())
        return self.found_devices
