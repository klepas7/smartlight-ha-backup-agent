import os
import asyncio
import logging
from datetime import datetime, timezone

import aiohttp


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("smartlight_backup_agent")


async def heartbeat():
    logger.info("SmartLight Backup Agent started")

    while True:
        logger.info(
            "Agent heartbeat: %s",
            datetime.now(timezone.utc).isoformat(),
        )

        await asyncio.sleep(60)


async def main():
    logger.info("Initializing SmartLight Backup Agent")

    async with aiohttp.ClientSession() as session:
        logger.info("HTTP client initialized")

        await heartbeat()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped")
