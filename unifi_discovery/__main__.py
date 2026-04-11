"""Command-line entry point for unifi_discovery."""

from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import fields

from . import AIOUnifiScanner


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="unifi-discovery",
        description="Broadcast-scan the local network for UniFi devices.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Scan duration in seconds (default: 10).",
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Target a specific IP instead of broadcasting.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Include non-console devices (consoles only by default).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    scanner = AIOUnifiScanner()
    devices = await scanner.async_scan(
        timeout=args.timeout,
        address=args.address,
        consoles_only=not args.all,
    )
    if not devices:
        print("No devices found.")
        return 1
    for device in devices:
        print(f"--- {device.source_ip} ---")
        for f in fields(device):
            value = getattr(device, f.name)
            if not value and value != 0:
                continue
            if f.name == "services":
                value = {svc.name: ok for svc, ok in value.items()}
            print(f"  {f.name}: {value}")
    return 0


def main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
