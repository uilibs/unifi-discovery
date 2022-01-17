import asyncio
import logging
import pprint

from unifi_discovery import AIOUnifiScanner

logging.basicConfig(level=logging.DEBUG)


async def go():
    scanner = AIOUnifiScanner()
    pprint.pprint(await scanner.async_scan())


asyncio.run(go())
