from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from contextlib import suppress
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from http import HTTPStatus
from ipaddress import ip_address, ip_network
from struct import unpack
from typing import TYPE_CHECKING, Awaitable, Callable, cast

from aiohttp import (
    ClientError,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    TCPConnector,
)

if TYPE_CHECKING:
    from pyroute2 import IPRoute  # type: ignore


class UnifiService(Enum):
    Protect = auto()


_LOGGER = logging.getLogger(__name__)


IGNORE_NETWORKS = (
    ip_network("169.254.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("::ffff:127.0.0.0/104"),
    ip_network("224.0.0.0/4"),
)


PROBE_PLATFORMS = {"UDMPROSE", "UDMPRO", "UNVR", "UNVRPRO", "UCKP", None}

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = b"\x01\x00\x00\x00"
UBNT_V1_SIGNATURE = b"\x01\x00\x00"
DISCOVERY_PORT = 10001
BROADCAST_FREQUENCY = 3
ARP_CACHE_POPULATE_TIME = 10
ARP_TIMEOUT = 10
IGNORE_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


# Some MAC addresses will drop the leading zero so
# our mac validation must allow a single char
VALID_MAC_ADDRESS = re.compile("^([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2})$")


def mac_repr(data):
    return ":".join(("%02x" % b) for b in data)


def _format_mac(mac: str) -> str:
    return ":".join(mac.lower()[i : i + 2] for i in range(0, 12, 2))


def ip_repr(data):
    return ".".join(("%d" % b) for b in data)


def _fill_neighbor(neighbours, ip, mac):
    """Add a neighbor if it is valid."""
    try:
        ip_addr = ip_address(ip)
    except ValueError:
        return
    if any(ip_addr in network for network in IGNORE_NETWORKS):
        return
    if not VALID_MAC_ADDRESS.match(mac):
        return
    mac = ":".join([i.zfill(2) for i in mac.split(":")])
    if mac in IGNORE_MACS:
        return
    neighbours[ip] = mac


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


def _services_dict():
    """Create an dict with known services."""
    return {service: False for service in UnifiService}


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
    services: dict[UnifiService, bool] = field(default_factory=_services_dict)
    direct_connect_domain: str | None = None
    is_sso_enabled: bool | None = None
    is_single_user: bool | None = None


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


class ArpSearch:
    """Gather system network data."""

    def __init__(self):
        """Init system network data."""
        self.ip_route: IPRoute | None = None

    async def async_get_neighbors(self):
        """Get neighbors from the arp table."""
        self.ip_route = None
        with suppress(Exception):
            from pyroute2 import IPRoute  # pylint: disable=import-outside-toplevel

            self.ip_route = IPRoute()
        if self.ip_route:
            return await self._async_get_neighbors_ip_route()
        return await self._async_get_neighbors_arp()

    async def _async_get_neighbors_arp(self):
        """Get neighbors with arp command."""
        neighbours = {}
        arp = await asyncio.create_subprocess_exec(
            "arp",
            "-a",
            "-n",
            stdin=None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_data, _ = await asyncio.wait_for(arp.communicate(), ARP_TIMEOUT)
        except asyncio.TimeoutError:
            if arp:
                with suppress(TypeError):
                    await arp.kill()
                del arp
            return neighbours
        except AttributeError:
            return neighbours

        for line in out_data.decode().splitlines():
            chomped = line.strip()
            data = chomped.split()
            if len(data) < 4:
                continue
            ip = data[1].strip("()")
            mac = data[3]
            _fill_neighbor(neighbours, ip, mac)

        return neighbours

    async def _async_get_neighbors_ip_route(self):
        """Get neighbors with pyroute2."""
        neighbours = {}
        loop = asyncio.get_running_loop()
        # This shouldn't ever block but it does
        # interact with netlink so its safer to run
        # in the executor
        for neighbour in await loop.run_in_executor(None, self.ip_route.get_neighbours):
            ip = None
            mac = None
            for key, value in neighbour["attrs"]:
                if key == "NDA_DST":
                    ip = value
                elif key == "NDA_LLADDR":
                    mac = value
            if ip and mac:
                _fill_neighbor(neighbours, ip, mac)

        return neighbours


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

    async def _add_missing_hw_addresses(
        self, response_list: dict[str, UnifiDevice]
    ) -> None:
        """Add any missing hardware addresses to the response list."""
        if not any(device.hw_addr is None for device in response_list.values()):
            return
        arp = ArpSearch()
        neighbors = await arp.async_get_neighbors()
        for source, device in response_list.items():
            if device.hw_addr is None and device.source_ip in neighbors:
                response_list[source] = replace(
                    device,
                    hw_addr=neighbors[device.source_ip],
                    ip_info=[f"{neighbors[device.source_ip]};{device.source_ip}"],
                )

    async def _probe_services_and_system(
        self, response_list: dict[str, UnifiDevice]
    ) -> None:
        """Check which services are available and update the services dict."""
        timeout = ClientTimeout(total=5.0)
        async with ClientSession(
            connector=TCPConnector(ssl=False), timeout=timeout
        ) as s:
            device_tasks: dict[str, Awaitable] = {}
            system_tasks: dict[str, Awaitable] = {}
            for device in response_list.values():
                if device.platform in PROBE_PLATFORMS:
                    source_ip = device.source_ip
                    device_tasks[source_ip] = s.get(
                        f"https://{source_ip}/proxy/protect/api"
                    )
                    system_tasks[source_ip] = s.get(f"https://{source_ip}/api/system")
            results: list[ClientResponse | Exception] = await asyncio.gather(
                *(*device_tasks.values(), *system_tasks.values()),
                return_exceptions=True,
            )
            device_task_len = len(device_tasks)
            for idx, source_ip in enumerate(device_tasks):
                device_response = results[idx]
                response_list[source_ip].services[UnifiService.Protect] = (
                    device_response.status == HTTPStatus.UNAUTHORIZED
                    if not isinstance(device_response, Exception)
                    else False
                )
                system_response = results[idx + device_task_len]
                if isinstance(system_response, Exception):
                    continue
                try:
                    system = await system_response.json()
                except (asyncio.TimeoutError, ClientError):
                    _LOGGER.exception("Failed to get system info for %s", source_ip)
                    continue
                if not system:
                    continue
                device = response_list[source_ip]
                short_name = system.get("hardware", {}).get("shortname")
                response_list[source_ip] = replace(
                    device,
                    platform=device.platform or short_name,
                    hostname=device.hostname or system.get("name").replace(" ", "-"),
                    hw_addr=device.hw_addr or _format_mac(system.get("mac")),
                    direct_connect_domain=system.get("directConnectDomain"),
                    is_sso_enabled=system.get("isSsoEnabled"),
                    is_single_user=system.get("isSingleUser"),
                )

    async def async_scan(
        self, timeout: int = 31, address: str | None = None
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

        await self._probe_services_and_system(response_list)
        await self._add_missing_hw_addresses(response_list)

        self.found_devices = list(response_list.values())
        return self.found_devices
