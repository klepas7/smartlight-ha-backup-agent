
import os
import json
import asyncio
import logging
import secrets
import hashlib
import tarfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

import aiohttp

OPTIONS_PATH = Path("/data/options.json")
TEST_DONE_PATH = Path("/data/supervisor_encrypted_test_done")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
DOWNLOAD_DONE_PATH = Path("/data/supervisor_download_test_done")

DOWNLOAD_PATH = Path("/share/smartlight_supervisor_api_test.tar")
INNER_TEST_PATH = Path("/share/smartlight_inner_archive_test.tmp")

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
    if TEST_PASSWORD_PATH.exists():
        password = TEST_PASSWORD_PATH.read_text(
            encoding="utf-8"
        ).strip()

        if not password:
            raise RuntimeError("Stored test password is empty")

        return password

    password = secrets.token_urlsafe(32)

    TEST_PASSWORD_PATH.write_text(
        password,
        encoding="utf-8",
    )
    TEST_PASSWORD_PATH.chmod(0o600)

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


async def create_encrypted_test_backup(session):
    if TEST_DONE_PATH.exists():
        slug = TEST_DONE_PATH.read_text(
            encoding="utf-8"
        ).strip()

        if slug:
            logger.info(
                "Existing diagnostic backup found: %s",
                slug,
            )
            return slug

        TEST_DONE_PATH.unlink()

    password = get_test_password()

    logger.info("Creating encrypted diagnostic backup")

    result = await supervisor_request(
        session,
        "POST",
        "/backups/new/full",
        json={
            "name": "SmartLight encryption diagnostic",
            "password": password,
            "compressed": True,
            "background": False,
        },
        timeout=aiohttp.ClientTimeout(total=None),
    )

    data = result.get("data", result)
    slug = data.get("slug")

    if not slug:
        raise RuntimeError(
            f"Supervisor did not return backup slug: {result}"
        )

    logger.info("Diagnostic backup created: %s", slug)

    info_result = await supervisor_request(
        session,
        "GET",
        f"/backups/{slug}/info",
    )

    info = info_result.get("data", info_result)
    protected = info.get("protected")

    logger.info(
        "Supervisor backup protected flag: %s",
        protected,
    )

    if protected is not True:
        raise RuntimeError(
            "Diagnostic backup is not marked as protected"
        )

    TEST_DONE_PATH.write_text(
        slug,
        encoding="utf-8",
    )
    TEST_DONE_PATH.chmod(0o600)

    return slug


async def download_backup_from_supervisor(session, slug):
    if DOWNLOAD_DONE_PATH.exists() and DOWNLOAD_PATH.exists():
        logger.info(
            "Diagnostic download already exists; reusing it"
        )
        return

    logger.info(
        "Downloading backup directly from Supervisor API"
    )

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

    logger.info(
        "Supervisor download completed. Size: %s bytes",
        total_size,
    )
    logger.info("Downloaded backup SHA256: %s", sha256)

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


def inspect_backup_archive():
    logger.info("Inspecting downloaded backup archive")

    if not DOWNLOAD_PATH.exists():
        raise RuntimeError("Downloaded backup file not found")

    with tarfile.open(DOWNLOAD_PATH, "r:") as outer:
        members = outer.getmembers()

        backup_json_member = next(
            (
                member
                for member in members
                if member.name.endswith("backup.json")
            ),
            None,
        )

        if backup_json_member is None:
            raise RuntimeError(
                "backup.json not found in downloaded archive"
            )

        backup_json_file = outer.extractfile(
            backup_json_member
        )

        if backup_json_file is None:
            raise RuntimeError(
                "Cannot read backup.json"
            )

        metadata = json.loads(
            backup_json_file.read().decode("utf-8")
        )

        protected = metadata.get("protected")

        logger.info(
            "Downloaded archive metadata protected: %s",
            protected,
        )

        inner_archives = [
            member
            for member in members
            if member.isfile()
            and (
                member.name.endswith(".tar")
                or member.name.endswith(".tar.gz")
            )
            and not member.name.endswith("backup.tar")
        ]

        logger.info(
            "Inner archives found: %s",
            len(inner_archives),
        )

        if not inner_archives:
            raise RuntimeError(
                "No inner component archives found"
            )

        selected = inner_archives[0]

        logger.info(
            "Inspecting inner archive: %s",
            selected.name,
        )

        source = outer.extractfile(selected)

        if source is None:
            raise RuntimeError(
                "Cannot read inner archive"
            )

        with INNER_TEST_PATH.open("wb") as target:
            shutil.copyfileobj(source, target)

    INNER_TEST_PATH.chmod(0o600)

    with INNER_TEST_PATH.open("rb") as file:
        magic = file.read(32)

    logger.info(
        "Inner archive first bytes (hex): %s",
        magic.hex(),
    )

    plain_tar_readable = False
    plain_tar_error = None

    try:
        with tarfile.open(
            INNER_TEST_PATH,
            "r:*",
        ) as inner:
            inner.getmembers()
            plain_tar_readable = True

    except Exception as error:
        plain_tar_error = type(error).__name__

    logger.info(
        "Inner archive readable as ordinary TAR: %s",
        plain_tar_readable,
    )

    if plain_tar_error:
        logger.info(
            "Ordinary TAR read error: %s",
            plain_tar_error,
        )

    if protected is not True:
        raise RuntimeError(
            "Downloaded archive metadata does not indicate encryption"
        )

    if plain_tar_readable:
        logger.warning(
            "Inner archive is readable as ordinary TAR. "
            "Encryption requires further investigation."
        )
    else:
        logger.info(
            "Inner archive is not readable as ordinary TAR. "
            "This is consistent with encrypted backup content, "
            "but is not by itself cryptographic proof."
        )

    INNER_TEST_PATH.unlink(missing_ok=True)

    logger.info("Diagnostic archive inspection completed")


async def run_encryption_diagnostic(session):
    slug = await create_encrypted_test_backup(session)

    await download_backup_from_supervisor(
        session,
        slug,
    )

    inspect_backup_archive()


async def heartbeat(session):
    url = f"{SERVER_URL}/api/agent/heartbeat"

    headers = {
        "X-Client-Key": API_KEY,
        "Content-Type": "application/json",
    }

    payload = {
        "client_code": CLIENT_CODE,
        "agent_version": "0.1.5-diagnostic",
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
        logger.warning(
            "Heartbeat error: %s",
            error,
        )


async def main():
    logger.info("====================================")
    logger.info(" SmartLight Backup Agent")
    logger.info(" Starting diagnostic version")
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

            await run_encryption_diagnostic(
                session
            )

        except Exception:
            logger.exception(
                "Encryption diagnostic failed"
            )

        while True:
            await heartbeat(session)
            await asyncio.sleep(
                HEARTBEAT_INTERVAL
            )


if __name__ == "__main__":
    asyncio.run(main())
