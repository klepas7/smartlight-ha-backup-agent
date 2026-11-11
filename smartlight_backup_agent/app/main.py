
import os
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone

import aiohttp


OPTIONS_PATH = Path("/data/options.json")

DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
HEARTBEAT_INTERVAL = 60


def load_options():
    if not OPTIONS_PATH.exists():
        raise RuntimeError("Add-on options file not found: /data/options.json")

    with OPTIONS_PATH.open("r", encoding="utf-8") as file:
        options = json.load(file)

    client_code = options.get("client_code", "").strip()
    api_key = options.get("api_key", "").strip()
    server_url = options.get("server_url", DEFAULT_SERVER_URL).rstrip("/")
    log_level = options.get("log_level", "info").upper()

    if not client_code:
        raise RuntimeError("Client code is not configured")

    if not api_key:
        raise RuntimeError("API key is not configured")

    return client_code, api_key, server_url, log_level


CLIENT_CODE, API_KEY, SERVER_URL, LOG_LEVEL = load_options()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("smartlight_backup_agent")


async def heartbeat(session):
    url = f"{SERVER_URL}/api/agent/heartbeat"

    headers = {
        "X-Client-Key": API_KEY,
    }

    while True:
        try:
            async with session.post(url, headers=headers) as response:
                if response.status == 200:
                    logger.info("Heartbeat successful: %s", CLIENT_CODE)
                else:
                    body = await response.text()
                    logger.error(
                        "Heartbeat failed: HTTP %s - %s",
                        response.status,
                        body,
                    )

        except Exception:
            logger.exception("Heartbeat connection error")

        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def main():
    logger.info("Initializing SmartLight Backup Agent")
    logger.info("Client: %s", CLIENT_CODE)
    logger.info("Server: %s", SERVER_URL)

    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        logger.info("HTTP client initialized")
        await heartbeat(session)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped")
    except Exception:
        logger.exception("Agent startup failed")
        raise
