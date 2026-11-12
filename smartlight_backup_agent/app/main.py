
import os
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime

import aiohttp

OPTIONS_PATH = Path("/data/options.json")
TEST_DONE_PATH = Path("/data/supervisor_backup_test_done")

DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
HEARTBEAT_INTERVAL = 60
SUPERVISOR_URL = "http://supervisor"

def load_options():
    if not OPTIONS_PATH.exists():
        raise RuntimeError("Add-on options file not found")

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
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("smartlight_backup_agent")


def supervisor_headers():
    token = os.getenv("SUPERVISOR_TOKEN")

    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is missing")

    return {"Authorization": f"Bearer {token}"}


async def test_supervisor_api(session):
    url = f"{SUPERVISOR_URL}/backups"

    try:
        async with session.get(
            url,
            headers=supervisor_headers()
        ) as response:

            if response.status != 200:
                body = await response.text()
                logger.error(
                    "Supervisor API failed: HTTP %s - %s",
                    response.status,
                    body
                )
                return False

            payload = await response.json(content_type=None)
            data = payload.get("data", payload)
            backups = data.get("backups", [])

            logger.info(
                "Supervisor API OK. Existing backups: %s",
                len(backups)
            )
            return True

    except Exception:
        logger.exception("Supervisor API connection error")
        return False


async def create_test_backup(session):
    if TEST_DONE_PATH.exists():
        logger.info("Test backup already created. Skipping.")
        return

    logger.info("Starting one-time full backup test...")

    url = f"{SUPERVISOR_URL}/backups/new/full"

    today = datetime.now().strftime("%Y-%m-%d %H:%M")

    payload = {
        "name": f"SmartLight API test - {today}",
        "compressed": True,
        "background": False
    }

    try:
        async with session.post(
            url,
            headers=supervisor_headers(),
            json=payload,
            timeout=None
        ) as response:

            body = await response.text()

            if response.status not in (200, 201):
                logger.error(
                    "Backup creation failed: HTTP %s - %s",
                    response.status,
                    body
                )
                return

            result = json.loads(body)
            data = result.get("data", result)
            slug = data.get("slug")

            if not slug:
                logger.error(
                    "Backup response did not contain a slug: %s",
                    body
                )
                return

            logger.info("Test backup created successfully. Slug: %s", slug)

        info_url = f"{SUPERVISOR_URL}/backups/{slug}/info"

        async with session.get(
            info_url,
            headers=supervisor_headers()
        ) as response:

            if response.status == 200:
                info_result = await response.json(content_type=None)
                info = info_result.get("data", info_result)

                logger.info(
                    "Backup verified: name=%s, size=%s MB, protected=%s",
                    info.get("name"),
                    info.get("size"),
                    info.get("protected")
                )
            else:
                logger.warning(
                    "Backup created, but info verification failed: HTTP %s",
                    response.status
                )

        TEST_DONE_PATH.write_text(
            slug,
            encoding="utf-8"
        )

        logger.info("One-time backup test completed.")

    except Exception:
        logger.exception("Test backup creation error")


async def heartbeat(session):
    url = f"{SERVER_URL}/api/agent/heartbeat"
    headers = {"X-Client-Key": API_KEY}

    while True:
        try:
            async with session.post(
                url,
                headers=headers
            ) as response:

                if response.status == 200:
                    logger.info(
                        "Heartbeat successful: %s",
                        CLIENT_CODE
                    )
                else:
                    body = await response.text()
                    logger.error(
                        "Heartbeat failed: HTTP %s - %s",
                        response.status,
                        body
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

        supervisor_ok = await test_supervisor_api(session)

        if supervisor_ok:
            await create_test_backup(session)

        await heartbeat(session)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped")
    except Exception:
        logger.exception("Fatal agent error")
        raise
