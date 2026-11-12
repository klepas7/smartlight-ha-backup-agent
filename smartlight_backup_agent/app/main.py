
import os
import json
import asyncio
import logging
import secrets
from pathlib import Path
from datetime import datetime

import aiohttp

OPTIONS_PATH = Path("/data/options.json")
TEST_DONE_PATH = Path("/data/supervisor_encrypted_test_done")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
SHARED_PASSWORD_PATH = Path("/share/smartlight_test_password.txt")

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


def get_test_password():
    if TEST_PASSWORD_PATH.exists():
        password = TEST_PASSWORD_PATH.read_text(
            encoding="utf-8"
        ).strip()

        if not password:
            raise RuntimeError("Stored test password is empty")

        logger.info("Existing test encryption password loaded")
        return password

    password = secrets.token_urlsafe(32)

    TEST_PASSWORD_PATH.write_text(password, encoding="utf-8")
    os.chmod(TEST_PASSWORD_PATH, 0o600)

    logger.info("New test encryption password generated and stored")
    return password


def export_test_password():
    if not TEST_PASSWORD_PATH.exists():
        logger.error("Test password file not found")
        return False

    password = TEST_PASSWORD_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not password:
        logger.error("Test password file is empty")
        return False

    try:
        SHARED_PASSWORD_PATH.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        SHARED_PASSWORD_PATH.write_text(
            password,
            encoding="utf-8"
        )

        os.chmod(SHARED_PASSWORD_PATH, 0o600)

        logger.info(
            "Existing test password exported to shared HA folder"
        )
        return True

    except Exception:
        logger.exception("Could not export test password")
        return False


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


async def create_encrypted_test_backup(session):
    if TEST_DONE_PATH.exists():
        logger.info("Encrypted test backup already created. Skipping.")
        return

    logger.info("Starting encrypted full backup test...")

    password = get_test_password()

    url = f"{SUPERVISOR_URL}/backups/new/full"
    today = datetime.now().strftime("%Y-%m-%d %H:%M")

    payload = {
        "name": f"SmartLight encrypted test - {today}",
        "password": password,
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
                    "Encrypted backup creation failed: HTTP %s - %s",
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

            logger.info(
                "Encrypted test backup created. Slug: %s",
                slug
            )

        info_url = f"{SUPERVISOR_URL}/backups/{slug}/info"

        async with session.get(
            info_url,
            headers=supervisor_headers()
        ) as response:

            if response.status != 200:
                logger.error(
                    "Backup info verification failed: HTTP %s",
                    response.status
                )
                return

            info_result = await response.json(content_type=None)
            info = info_result.get("data", info_result)

            protected = info.get("protected", False)

            logger.info(
                "Encrypted backup verified: name=%s, size=%s MB, protected=%s",
                info.get("name"),
                info.get("size"),
                protected
            )

            if protected is not True:
                logger.error(
                    "Encryption verification FAILED: protected is not true"
                )
                return

        TEST_DONE_PATH.write_text(slug, encoding="utf-8")
        os.chmod(TEST_DONE_PATH, 0o600)

        logger.info("Encrypted backup test completed successfully.")

    except Exception:
        logger.exception("Encrypted backup test error")


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

        export_test_password()

        supervisor_ok = await test_supervisor_api(session)

        if supervisor_ok:
            await create_encrypted_test_backup(session)

        await heartbeat(session)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped")
    except Exception:
        logger.exception("Fatal agent error")
        raise
