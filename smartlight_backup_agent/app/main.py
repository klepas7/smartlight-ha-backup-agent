
import os
import json
import asyncio
import logging
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone

import aiohttp
from securetar import SecureTarArchive

OPTIONS_PATH = Path("/data/options.json")
TEST_DONE_PATH = Path("/data/supervisor_encrypted_test_done")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
DOWNLOAD_DONE_PATH = Path("/data/supervisor_download_test_done")

DOWNLOAD_PATH = Path("/share/smartlight_supervisor_api_test.tar")

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
        raise RuntimeError("Client code is missing")
    if not api_key:
        raise RuntimeError("API key is missing")

    return client_code, api_key, server_url, log_level


CLIENT_CODE, API_KEY, SERVER_URL, LOG_LEVEL = load_options()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("smartlight_backup_agent")


def supervisor_headers():
    token = os.getenv("SUPERVISOR_TOKEN")

    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is missing")

    return {"Authorization": f"Bearer {token}"}


def get_test_password():
    if not TEST_PASSWORD_PATH.exists():
        raise RuntimeError(
            "Existing diagnostic password not found. "
            "Refusing to generate a different password."
        )

    password = TEST_PASSWORD_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not password:
        raise RuntimeError("Stored test password is empty")

    return password


async def supervisor_request(session, method, path, **kwargs):
    url = f"{SUPERVISOR_URL}{path}"

    async with session.request(
        method,
        url,
        headers=supervisor_headers(),
        **kwargs,
    ) as response:

        if response.status >= 400:
            body = await response.text()
            raise RuntimeError(
                f"Supervisor API error {response.status}: {body[:500]}"
            )

        if response.content_type == "application/json":
            return await response.json()

        return response


async def test_supervisor_api(session):
    logger.info("Checking Supervisor backup API")

    result = await supervisor_request(
        session,
        "GET",
        "/backups",
    )

    data = result.get("data", result)
    backups = data.get("backups", [])

    logger.info(
        "Supervisor API OK. Existing backups: %s",
        len(backups),
    )


async def download_backup_from_supervisor(session, slug):
    if DOWNLOAD_DONE_PATH.exists() and DOWNLOAD_PATH.exists():
        logger.info("Existing diagnostic download found")
        return

    logger.info("Downloading backup directly from Supervisor API")

    url = f"{SUPERVISOR_URL}/backups/{slug}/download"

    digest = hashlib.sha256()
    total_size = 0

    timeout = aiohttp.ClientTimeout(total=None)

    async with session.get(
        url,
        headers=supervisor_headers(),
        timeout=timeout,
    ) as response:

        if response.status != 200:
            body = await response.text()
            raise RuntimeError(
                f"Backup download failed: HTTP {response.status}: "
                f"{body[:500]}"
            )

        with DOWNLOAD_PATH.open("wb") as output:
            async for chunk in response.content.iter_chunked(
                1024 * 1024
            ):
                output.write(chunk)
                digest.update(chunk)
                total_size += len(chunk)

    DOWNLOAD_PATH.chmod(0o600)

    sha256 = digest.hexdigest()

    logger.info("Supervisor download completed")
    logger.info("Downloaded size: %s bytes", total_size)
    logger.info("Downloaded SHA256: %s", sha256)

    DOWNLOAD_DONE_PATH.write_text(
        json.dumps(
            {
                "slug": slug,
                "size": total_size,
                "sha256": sha256,
                "date": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    DOWNLOAD_DONE_PATH.chmod(0o600)


def validate_encrypted_backup():
    if not DOWNLOAD_PATH.exists():
        raise RuntimeError("Downloaded backup file not found")

    password = get_test_password()

    logger.info("Starting SecureTar password validation")

    validated = 0
    failed = 0

    with SecureTarArchive(
        DOWNLOAD_PATH,
        "r",
        password=password,
    ) as archive:

        members = archive.tar.getmembers()

        backup_json_member = next(
            (
                member
                for member in members
                if member.name.endswith("backup.json")
            ),
            None,
        )

        if backup_json_member is None:
            raise RuntimeError("backup.json not found")

        backup_json_file = archive.tar.extractfile(
            backup_json_member
        )

        if backup_json_file is None:
            raise RuntimeError("Cannot read backup.json")

        metadata = json.loads(
            backup_json_file.read().decode("utf-8")
        )

        if metadata.get("protected") is not True:
            raise RuntimeError(
                "Backup metadata does not indicate encryption"
            )

        inner_archives = [
            member
            for member in members
            if member.isfile()
            and (
                member.name.endswith(".tar.gz")
                or member.name.endswith(".tar")
            )
        ]

        if not inner_archives:
            raise RuntimeError("No inner archives found")

        logger.info(
            "Protected backup confirmed. Inner archives: %s",
            len(inner_archives),
        )

        for member in inner_archives:
            logger.info(
                "Validating encrypted archive: %s",
                member.name,
            )

            try:
                # Decrypts and validates the complete inner archive.
                # For SecureTar v2, invalid passwords are detected
                # when decrypted data does not form a valid TAR.
                archive.validate(member)

                validated += 1

                logger.info(
                    "Archive validated successfully: %s",
                    member.name,
                )

            except Exception as error:
                failed += 1

                logger.error(
                    "Archive validation failed: %s (%s)",
                    member.name,
                    type(error).__name__,
                )

                raise RuntimeError(
                    f"SecureTar validation failed for {member.name}"
                ) from error

    logger.info("====================================")
    logger.info(" SECURETAR VALIDATION RESULT")
    logger.info("====================================")
    logger.info("Validated archives: %s", validated)
    logger.info("Failed archives: %s", failed)
    logger.info("Password validation: SUCCESS")
    logger.info("Full archive decryption: SUCCESS")
    logger.info("====================================")


async def run_diagnostic(session):
    if not TEST_DONE_PATH.exists():
        raise RuntimeError(
            "Diagnostic backup marker not found"
        )

    slug = TEST_DONE_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not slug:
        raise RuntimeError("Diagnostic backup slug is empty")

    logger.info("Using diagnostic backup: %s", slug)

    await download_backup_from_supervisor(
        session,
        slug,
    )

    validate_encrypted_backup()


async def heartbeat(session):
    url = f"{SERVER_URL}/api/agent/heartbeat"

    headers = {
        "X-Client-Key": API_KEY,
        "Content-Type": "application/json",
    }

    payload = {
        "client_code": CLIENT_CODE,
        "agent_version": "0.1.6-diagnostic",
        "ha_version": os.getenv(
            "HASSIO_VERSION",
            "unknown",
        ),
    }

    try:
        async with session.post(
            url,
            json=payload,
            headers=headers,
        ) as response:

            if response.status == 200:
                logger.info("Heartbeat OK")
            else:
                logger.warning(
                    "Heartbeat failed: HTTP %s",
                    response.status,
                )

    except Exception as error:
        logger.warning("Heartbeat error: %s", error)


async def main():
    logger.info("====================================")
    logger.info(" SmartLight Backup Agent")
    logger.info(" Starting SecureTar validation")
    logger.info("====================================")

    timeout = aiohttp.ClientTimeout(
        total=60,
        connect=30,
    )

    async with aiohttp.ClientSession(
        timeout=timeout
    ) as session:

        try:
            await test_supervisor_api(session)
            await run_diagnostic(session)

        except Exception:
            logger.exception(
                "SecureTar diagnostic failed"
            )

        while True:
            await heartbeat(session)
            await asyncio.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
