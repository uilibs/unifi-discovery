from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from http import HTTPStatus
from ipaddress import ip_address, ip_network
from struct import unpack
from typing import TYPE_CHECKING, NamedTuple, cast

from aiohttp import (
    ClientError,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    ContentTypeError,
    TCPConnector,
)

if TYPE_CHECKING:
    from pyroute2.iproute import IPRoute


class _ProbeResult(NamedTuple):
    service_responses: tuple[ClientResponse | BaseException, ...]
    system: ClientResponse | BaseException


class UnifiService(Enum):
    Protect = auto()
    Network = auto()
    Access = auto()


_LOGGER = logging.getLogger(__name__)

BROADCAST_IP = "255.255.255.255"
MULTICAST_IP = "233.89.188.1"
MDNS_TARGET_IP = "224.0.0.251"
PUBLIC_TARGET_IP = "1.1.1.1"

IGNORE_NETWORKS = (
    ip_network("169.254.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("::ffff:127.0.0.0/104"),
    ip_network("224.0.0.0/4"),
)


# UBNT discovery packet payload and reply signature
UBNT_V1_REQUEST = b"\x01\x00\x00\x00"
UBNT_V2_REQUEST = b"\x02\x08\x00\x00"  # version=2, command=8, data_len=0
DISCOVERY_PORT = 10001
BROADCAST_FREQUENCY = 3
ARP_CACHE_POPULATE_TIME = 10
ARP_TIMEOUT = 10
IGNORE_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

API_TIMEOUT = ClientTimeout(total=5.0)
SCAN_CACHE_TTL = 300  # seconds to cache broadcast scan results
SYSTEM_API_ENDPOINT = "/api/system"
PROTECT_API_ENDPOINT = "/proxy/protect/api"
NETWORK_API_ENDPOINT = "/proxy/network/api"
ACCESS_API_ENDPOINT = "/proxy/access/api"
SERVICE_ENDPOINTS: tuple[tuple[UnifiService, str], ...] = (
    (UnifiService.Protect, PROTECT_API_ENDPOINT),
    (UnifiService.Network, NETWORK_API_ENDPOINT),
    (UnifiService.Access, ACCESS_API_ENDPOINT),
)

# Some MAC addresses will drop the leading zero so
# our mac validation must allow a single char
VALID_MAC_ADDRESS = re.compile("^([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2})$")


def mac_repr(data):
    return ":".join(f"{b:02x}" for b in data)


def _format_mac(mac: str) -> str:
    return ":".join(mac.lower()[i : i + 2] for i in range(0, 12, 2))


def ip_repr(data):
    return ".".join(f"{b:d}" for b in data)


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
FIELD_PARSERS_V1 = {
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

# V2/V0 responses use a different set of field IDs.
# Known protocol fields not mapped to UnifiDevice: 0x12 (seq), 0x13 (source_mac),
# 0x17 (is_default). These are parsed by the device firmware but not exposed here.
FIELD_PARSERS_V2 = {
    0x01: ("hw_addr", mac_repr, False),
    0x02: (
        "ip_info",
        lambda data: f"{mac_repr(data[0:6])};{ip_repr(data[6:10])}",
        True,
    ),
    0x03: ("fw_version", bytes.decode, False),
    0x15: ("product_name", bytes.decode, False),
    0x16: ("version", bytes.decode, False),
}


def _services_dict():
    """Create an dict with known services."""
    return dict.fromkeys(UnifiService, False)


@dataclass(frozen=True)
class UnifiDevice:
    """A device discovered."""

    source_ip: str
    hw_addr: str | None = None
    ip_info: list[str] | None = None
    addr_entry: str | None = None
    fw_version: str | None = None
    mac_address: str | None = None
    uptime: int | None = None
    hostname: str | None = None
    platform: str | None = None
    model: str | None = None
    signature_version: str | None = None
    services: dict[UnifiService, bool] = field(default_factory=_services_dict)
    direct_connect_domain: str | None = None
    is_sso_enabled: bool | None = None
    is_single_user: bool | None = None
    product_name: str | None = None
    version: str | None = None


def _merge_devices(existing: UnifiDevice, new: UnifiDevice) -> UnifiDevice:
    """
    Merge two device records for the same IP, filling None gaps from new.

    Order-independent: only updates fields on *existing* that are None
    with non-None values from *new*. The ip_info lists are combined.
    """
    updates: dict[str, object] = {}
    for f in existing.__dataclass_fields__:
        if f in ("source_ip", "services"):
            continue
        old_val = getattr(existing, f)
        new_val = getattr(new, f)
        if f == "ip_info":
            if old_val and new_val:
                seen = set(old_val)
                combined = list(old_val)
                for v in new_val:
                    if v not in seen:
                        combined.append(v)
                        seen.add(v)
                updates[f] = combined
            elif old_val is None and new_val is not None:
                updates[f] = new_val
        elif old_val is None and new_val is not None:
            updates[f] = new_val
    return replace(existing, **updates)


def _deduplicate_by_mac(
    response_list: dict[str, UnifiDevice],
) -> dict[str, UnifiDevice]:
    """
    Deduplicate devices that share the same hw_addr.

    Consoles respond from every VLAN interface, creating multiple entries
    with the same MAC but different source IPs. We keep the entry with the
    richest data (most non-None fields) and merge the others into it.
    Devices without hw_addr are always kept as-is.
    """
    # Group IPs by hw_addr
    mac_to_ips: dict[str, list[str]] = {}
    for ip, device in response_list.items():
        if device.hw_addr is not None:
            mac_to_ips.setdefault(device.hw_addr, []).append(ip)

    # Nothing to deduplicate
    if all(len(ips) <= 1 for ips in mac_to_ips.values()):
        return response_list

    to_remove: set[str] = set()
    for mac, ips in mac_to_ips.items():
        if len(ips) <= 1:
            continue

        # Pick the entry with the most populated fields as the primary
        def _richness(ip: str) -> int:
            d = response_list[ip]
            return sum(
                1
                for f in d.__dataclass_fields__
                if f not in ("source_ip", "services") and getattr(d, f) is not None
            )

        ips.sort(key=_richness, reverse=True)
        primary_ip = ips[0]
        primary = response_list[primary_ip]

        # Merge services from duplicates (take True over False)
        merged_services = dict(primary.services)
        for dup_ip in ips[1:]:
            dup = response_list[dup_ip]
            primary = _merge_devices(primary, dup)
            for svc, available in dup.services.items():
                if available:
                    merged_services[svc] = True
            to_remove.add(dup_ip)

        response_list[primary_ip] = replace(primary, services=merged_services)

    for ip in to_remove:
        del response_list[ip]

    return response_list


async def async_console_is_alive(session: ClientSession, target_ip: str) -> bool:
    """
    Check if a console is alive.

    The passed in session must not validate ssl.
    """
    try:
        await session.get(
            f"https://{target_ip}{SYSTEM_API_ENDPOINT}", timeout=API_TIMEOUT
        )
    except (TimeoutError, ClientError):
        return False
    return True


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
    data_end = min(_len, len(data))
    while pointer + 3 <= data_end:
        fieldType, fieldLen = unpack(">BH", data[pointer : pointer + 3])
        pointer += 3
        if pointer + fieldLen > data_end:
            break
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
        payload[0:4] == UBNT_V1_REQUEST and from_address[1] != DISCOVERY_PORT
    ):  # Check for a UBNT discovery request
        # (first 4 bytes of the payload should be \x01\x00\x00\x00)
        return UnifiDevice(**fields)  # type: ignore

    version = payload[0]
    command = payload[1]
    data_len = unpack(">H", payload[2:4])[0]

    if version == 1 and command == 0:
        fields["signature_version"] = "1"
        field_parsers = FIELD_PARSERS_V1
    elif version == 2 and command in (6, 9):
        fields["signature_version"] = "2"
        field_parsers = FIELD_PARSERS_V2
    elif version == 0 and data_len > 0:
        # Some devices (e.g. UNVR) respond with version 0
        fields["signature_version"] = "0"
        field_parsers = FIELD_PARSERS_V2
    else:
        return None

    # Walk the reply payload, starting from offset 04
    # (just after reply signature and payload size).
    for field_type, field_data in iter_fields(payload[4:], data_len):
        if field_type not in field_parsers:
            continue

        # Parse the field and store in Device
        field_name, field_parser, is_many = field_parsers[field_type]
        try:
            value = field_parser(field_data)  # type: ignore
        except Exception:
            continue
        if is_many:
            if field_name not in fields:
                fields[field_name] = []
            field_list = cast(list, fields[field_name])
            field_list.append(value)
        else:
            fields[field_name] = value

    # Filter to only fields that exist on UnifiDevice
    valid = UnifiDevice.__dataclass_fields__
    return UnifiDevice(**{k: v for k, v in fields.items() if k in valid})  # type: ignore


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


def create_multicast_socket(discovery_port: int) -> socket.socket:
    """Create a udp socket that joins the UniFi multicast group."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", discovery_port))
    except OSError as err:
        _LOGGER.debug("Multicast port %s is not available: %s", discovery_port, err)
        sock.bind(("", 0))
    mreq = socket.inet_aton(MULTICAST_IP) + socket.inet_aton("0.0.0.0")
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError as err:
        _LOGGER.debug("Failed to join multicast group %s: %s", MULTICAST_IP, err)
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
        self._imported_iproute = False

    def _get_iproute(self):
        """Get the iproute object."""
        with suppress(Exception):
            from pyroute2.iproute import (  # noqa: PLC0415
                IPRoute,
            )

            return IPRoute()
        return None

    async def async_get_neighbors(self):
        """Get neighbors from the arp table."""
        if not self._imported_iproute:
            self.ip_route = await asyncio.get_running_loop().run_in_executor(
                None, self._get_iproute
            )
            self._imported_iproute = True
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
        except TimeoutError:
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


# Module-level scan cache and lock for deduplication across instances
_scan_cache: tuple[float, list[UnifiDevice]] | None = None
_scan_lock: asyncio.Lock | None = None
_scan_lock_loop: asyncio.AbstractEventLoop | None = None


def _get_scan_lock() -> asyncio.Lock:
    """Get or create the module-level scan lock for the current event loop."""
    global _scan_lock, _scan_lock_loop  # noqa: PLW0603
    loop = asyncio.get_running_loop()
    if _scan_lock is None or _scan_lock_loop is not loop:
        _scan_lock = asyncio.Lock()
        _scan_lock_loop = loop
    return _scan_lock


def _copy_devices(devices: list[UnifiDevice]) -> list[UnifiDevice]:
    """Return a shallow copy of the device list. Devices are frozen and safe to share."""
    return list(devices)


def async_clear_cache() -> None:
    """Clear the scan result cache."""
    global _scan_cache  # noqa: PLW0603
    _scan_cache = None


def _is_console(device: UnifiDevice) -> bool:
    """Return True if the device is a UniFi OS console."""
    return device.version is not None or any(device.services.values())


def _filter_devices(
    devices: list[UnifiDevice], consoles_only: bool
) -> list[UnifiDevice]:
    """Optionally filter to consoles only."""
    if not consoles_only:
        return devices
    return [d for d in devices if _is_console(d)]


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
        """
        Process a response.

        Returns True if processing should stop
        """
        if from_address[0] == self.source_ip:
            return False
        response = parse_ubnt_response(data, from_address)
        if response is not None:
            existing = response_list.get(from_address[0])
            if existing is None:
                response_list[from_address[0]] = response
            else:
                # Merge V1+V2 responses: fill None gaps from new response
                response_list[from_address[0]] = _merge_devices(existing, response)
            return from_address[0] == address
        return False

    async def _async_run_scan(
        self,
        transport: asyncio.DatagramTransport,
        destination: tuple[str, int],
        timeout: int,
        found_all_future: asyncio.Future[bool],
        multicast_transport: asyncio.DatagramTransport | None = None,
    ) -> None:
        """Send the scans."""
        self.source_ip = (
            async_get_source_ip(BROADCAST_IP)
            or async_get_source_ip(MDNS_TARGET_IP)
            or async_get_source_ip(PUBLIC_TARGET_IP)
        )
        _LOGGER.debug("source_ip: %s", self.source_ip)

        multicast_dest = (MULTICAST_IP, DISCOVERY_PORT)

        def _send_all() -> None:
            """Send V1+V2 on broadcast and multicast."""
            _LOGGER.debug("discover: %s => V1+V2", destination)
            transport.sendto(UBNT_V1_REQUEST, destination)
            transport.sendto(UBNT_V2_REQUEST, destination)
            if multicast_transport is not None:
                _LOGGER.debug("discover: %s => V1+V2 (multicast)", multicast_dest)
                multicast_transport.sendto(UBNT_V1_REQUEST, multicast_dest)
                multicast_transport.sendto(UBNT_V2_REQUEST, multicast_dest)

        _send_all()
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
            except TimeoutError:
                if time.monotonic() >= quit_time:
                    return
                # No response, send again in case it got lost
                _send_all()
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
        async with ClientSession(
            connector=TCPConnector(ssl=False), timeout=API_TIMEOUT
        ) as session:
            await self._probe_services_and_system_with_session(response_list, session)

    async def _probe_services_and_system_with_session(
        self, response_list: dict[str, UnifiDevice], session: ClientSession
    ) -> None:
        """Check which services are available and update the services dict with a provided session."""
        console_ips: list[str] = [
            device.source_ip
            for device in response_list.values()
            if device.signature_version is None or device.version is not None
        ]
        if not console_ips:
            return

        async def _probe_console(source_ip: str) -> _ProbeResult:
            *service_responses, system = await asyncio.gather(
                *(
                    session.get(f"https://{source_ip}{endpoint}")
                    for _, endpoint in SERVICE_ENDPOINTS
                ),
                session.get(f"https://{source_ip}{SYSTEM_API_ENDPOINT}"),
                return_exceptions=True,
            )
            return _ProbeResult(tuple(service_responses), system)

        all_results = await asyncio.gather(*(_probe_console(ip) for ip in console_ips))
        for source_ip, result in zip(console_ips, all_results, strict=True):
            services: dict[UnifiService, bool] = {}
            for (service, _), response in zip(
                SERVICE_ENDPOINTS, result.service_responses, strict=True
            ):
                if isinstance(response, BaseException):
                    if isinstance(response, asyncio.CancelledError):
                        raise response
                    services[service] = False
                else:
                    services[service] = response.status == HTTPStatus.UNAUTHORIZED
                    response.release()
            response_list[source_ip] = replace(
                response_list[source_ip], services=services
            )
            system_response = result.system
            if isinstance(system_response, BaseException):
                if isinstance(system_response, asyncio.CancelledError):
                    raise system_response
                continue
            try:
                system = await system_response.json()
            except ContentTypeError as ex:
                _LOGGER.debug("System endpoint not available for %s: %s", source_ip, ex)
                continue
            except (TimeoutError, ClientError):
                _LOGGER.exception("Failed to get system info for %s", source_ip)
                continue
            finally:
                system_response.release()
            if not system:
                continue
            device = response_list[source_ip]
            short_name = system.get("hardware", {}).get("shortname")
            mac = system.get("mac")
            response_list[source_ip] = replace(
                device,
                platform=device.platform or short_name,
                hostname=device.hostname
                or (system.get("name") or "").replace(" ", "-"),
                hw_addr=device.hw_addr or (_format_mac(mac) if mac else None),
                direct_connect_domain=system.get("directConnectDomain"),
                is_sso_enabled=system.get("isSsoEnabled"),
                is_single_user=system.get("isSingleUser"),
            )

    async def async_scan(
        self,
        timeout: int = 31,
        address: str | None = None,
        consoles_only: bool = True,
    ) -> list[UnifiDevice]:
        """
        Discover on port 10001.

        Args:
            timeout: Scan duration in seconds.
            address: Target a specific IP instead of broadcast.
            consoles_only: If True (default), only return UniFi OS consoles.

        """
        # Targeted scans bypass the cache
        if address is not None:
            result = await self._async_do_scan(timeout, address)
            self.found_devices = _filter_devices(result, consoles_only)
            return self.found_devices

        global _scan_cache  # noqa: PLW0603
        now = time.monotonic()

        # Return cached results if still fresh
        if _scan_cache is not None and now - _scan_cache[0] < SCAN_CACHE_TTL:
            self.found_devices = _filter_devices(
                _copy_devices(_scan_cache[1]), consoles_only
            )
            return self.found_devices

        lock = _get_scan_lock()
        async with lock:
            # Re-check after acquiring lock (another caller may have filled cache)
            now = time.monotonic()
            if _scan_cache is not None and now - _scan_cache[0] < SCAN_CACHE_TTL:
                self.found_devices = _filter_devices(
                    _copy_devices(_scan_cache[1]), consoles_only
                )
                return self.found_devices

            result = await self._async_do_scan(timeout, address)
            _scan_cache = (time.monotonic(), result)
            self.found_devices = _filter_devices(_copy_devices(result), consoles_only)
            return self.found_devices

    async def _async_do_scan(
        self, timeout: int = 31, address: str | None = None
    ) -> list[UnifiDevice]:
        """Perform the actual network scan."""
        sock = create_udp_socket(DISCOVERY_PORT)
        destination = self._destination_from_address(address)
        found_all_future: asyncio.Future[bool] = asyncio.Future()
        response_list: dict[str, UnifiDevice] = {}

        def _on_response(data: bytes, addr: tuple[str, int]) -> None:
            _LOGGER.debug("discover: %s <= %s", addr, data)
            if self._process_response(data, addr, address, response_list):
                if not found_all_future.done():
                    found_all_future.set_result(True)

        loop = asyncio.get_running_loop()

        transport, _ = await loop.create_datagram_endpoint(
            lambda: UnifiDiscovery(
                destination=destination,
                on_response=_on_response,
            ),
            sock=sock,
        )

        # Create multicast socket for discovering devices that only respond to multicast
        multicast_transport: asyncio.DatagramTransport | None = None
        if address is None:
            try:
                mcast_sock = create_multicast_socket(DISCOVERY_PORT)
            except OSError:
                _LOGGER.debug("Failed to create multicast socket, skipping")
            else:
                try:
                    mcast_transport, _ = await loop.create_datagram_endpoint(
                        lambda: UnifiDiscovery(
                            destination=(MULTICAST_IP, DISCOVERY_PORT),
                            on_response=_on_response,
                        ),
                        sock=mcast_sock,
                    )
                    multicast_transport = cast(
                        asyncio.DatagramTransport, mcast_transport
                    )
                except OSError:
                    _LOGGER.debug("Failed to register multicast endpoint, skipping")
                    mcast_sock.close()

        try:
            await self._async_run_scan(
                cast(asyncio.DatagramTransport, transport),
                destination,
                timeout,
                found_all_future,
                multicast_transport=multicast_transport,
            )
        finally:
            transport.close()
            if multicast_transport is not None:
                multicast_transport.close()

        await self._probe_services_and_system(response_list)
        await self._add_missing_hw_addresses(response_list)
        _deduplicate_by_mac(response_list)

        self.found_devices = list(response_list.values())
        return self.found_devices
