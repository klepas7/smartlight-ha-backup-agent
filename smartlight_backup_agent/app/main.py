
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
UPLOAD_DONE_PATH = Path("/data/supervisor_upload_test_done.json")

DOWNLOAD_PATH = Path("/share/smartlight_supervisor_api_test.tar")
SHARED_PASSWORD_PATH = Path("/share/smartlight_test_password.txt")

DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
HEARTBEAT_INTERVAL = 60
SUPERVISOR_URL = "http://supervisor"
CHUNK_SIZE = 8 * 1024 * 1024


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
        raise RuntimeError("Diagnostic password file not found")

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

    DOWNLOAD_DONE_PATH.write_text(
        json.dumps(
            {
                "slug": slug,
                "size": total_size,
                "sha256": digest.hexdigest(),
                "date": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    DOWNLOAD_DONE_PATH.chmod(0o600)

    logger.info(
        "Supervisor download completed: %s bytes",
        total_size,
    )
    logger.info(
        "Downloaded SHA256: %s",
        digest.hexdigest(),
    )


def validate_encrypted_backup():
    if not DOWNLOAD_PATH.exists():
        raise RuntimeError("Downloaded backup file not found")

    password = get_test_password()

    logger.info("Starting SecureTar validation")

    validated = 0

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
                "Validating archive: %s",
                member.name,
            )

            archive.validate(member)
            validated += 1

            logger.info(
                "Archive validated: %s",
                member.name,
            )

    logger.info(
        "SecureTar validation successful: %s archives",
        validated,
    )

    # Remove the temporary plaintext password export.
    if SHARED_PASSWORD_PATH.exists():
        SHARED_PASSWORD_PATH.unlink()
        logger.info("Removed temporary plaintext password export")


def calculate_file_sha256(path):
    digest = hashlib.sha256()
    file_size = 0

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break

            digest.update(chunk)
            file_size += len(chunk)

    return file_size, digest.hexdigest()


async def server_request(session, method, path, **kwargs):
    url = f"{SERVER_URL}{path}"

    headers = kwargs.pop("headers", {})
    headers["X-Client-Key"] = API_KEY

    async with session.request(
        method,
        url,
        headers=headers,
        **kwargs,
    ) as response:

        body_text = await response.text()

        if response.status >= 400:
            raise RuntimeError(
                f"NAS API error {response.status}: {body_text[:1000]}"
            )

        if not body_text:
            return {}

        try:
            return json.loads(body_text)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"NAS returned invalid JSON: {body_text[:500]}"
            )


async def initiate_upload(
    session,
    slug,
    file_size,
    file_sha256,
):
    idempotency_key = f"ha-{slug}-{file_sha256}"

    payload = {
        "idempotency_key": idempotency_key,
        "filename": f"{slug}.tar",
        "file_size": file_size,
        "sha256": file_sha256,
        "backup_type": "manual",
    }

    logger.info("Initiating NAS upload")

    result = await server_request(
        session,
        "POST",
        "/api/agent/uploads/initiate",
        json=payload,
    )

    upload_id = result.get("upload_id")

    if not upload_id:
        raise RuntimeError(
            f"NAS did not return upload_id: {result}"
        )

    server_chunk_size = result.get("chunk_size")

    if server_chunk_size != CHUNK_SIZE:
        raise RuntimeError(
            f"Unexpected NAS chunk size: {server_chunk_size}"
        )

    logger.info(
        "NAS upload session: %s",
        upload_id,
    )
    logger.info(
        "Total chunks: %s",
        result.get("total_chunks"),
    )

    return upload_id


async def get_upload_status(session, upload_id):
    result = await server_request(
        session,
        "GET",
        f"/api/agent/uploads/{upload_id}/status",
    )

    return result


async def upload_missing_chunks(session, upload_id):
    status = await get_upload_status(
        session,
        upload_id,
    )

    missing_chunks = status.get("missing_chunks")

    if missing_chunks is None:
        received_chunks = set(
            status.get("received_chunks", [])
        )

        total_chunks = status.get("total_chunks")

        if total_chunks is None:
            raise RuntimeError(
                f"NAS status missing total_chunks: {status}"
            )

        missing_chunks = [
            index
            for index in range(total_chunks)
            if index not in received_chunks
        ]

    total_chunks = status.get("total_chunks")

    logger.info(
        "NAS upload status: %s received, %s missing",
        status.get("received_count"),
        len(missing_chunks),
    )

    if status.get("status") == "verified":
        logger.info("NAS already has a verified upload")
        return

    timeout = aiohttp.ClientTimeout(
        total=None,
        connect=30,
    )

    for chunk_index in missing_chunks:
        offset = chunk_index * CHUNK_SIZE

        with DOWNLOAD_PATH.open("rb") as file:
            file.seek(offset)
            chunk_data = file.read(CHUNK_SIZE)

        if not chunk_data:
            raise RuntimeError(
                f"Empty chunk at index {chunk_index}"
            )

        chunk_sha256 = hashlib.sha256(
            chunk_data
        ).hexdigest()

        headers = {
            "X-Client-Key": API_KEY,
            "X-Chunk-SHA256": chunk_sha256,
            "Content-Type": "application/octet-stream",
        }

        logger.info(
            "Uploading chunk %s/%s (%s bytes)",
            chunk_index + 1,
            total_chunks,
            len(chunk_data),
        )

        result = await server_request(
            session,
            "PUT",
            (
                f"/api/agent/uploads/{upload_id}"
                f"/chunks/{chunk_index}"
            ),
            headers=headers,
            data=chunk_data,
            timeout=timeout,
        )

        logger.info(
            "Chunk %s result: %s",
            chunk_index,
            result.get("status"),
        )

    final_status = await get_upload_status(
        session,
        upload_id,
    )

    if final_status.get("missing_count", 0) != 0:
        raise RuntimeError(
            f"NAS still reports missing chunks: {final_status}"
        )

    logger.info("All chunks received by NAS")


async def complete_upload(session, upload_id, expected_sha256):
    logger.info("Requesting NAS upload completion")

    result = await server_request(
        session,
        "POST",
        f"/api/agent/uploads/{upload_id}/complete",
    )

    returned_sha256 = result.get("sha256")

    if returned_sha256 and returned_sha256 != expected_sha256:
        raise RuntimeError(
            "NAS final SHA256 does not match local file"
        )

    status = result.get("status")

    if status not in ("verified", "already_completed"):
        # The API may return a different status for an
        # already-completed idempotent request.
        if status != "already_received":
            raise RuntimeError(
                f"Unexpected NAS completion response: {result}"
            )

    logger.info("NAS completion response: %s", result)

    if returned_sha256:
        logger.info("NAS final SHA256 matches local SHA256")

    return result


async def upload_backup_to_nas(session, slug):
    if UPLOAD_DONE_PATH.exists():
        try:
            previous = json.loads(
                UPLOAD_DONE_PATH.read_text(encoding="utf-8")
            )

            if previous.get("slug") == slug:
                logger.info(
                    "This diagnostic backup is already uploaded"
                )
                logger.info(
                    "Previous NAS storage key: %s",
                    previous.get("storage_key"),
                )
                return

        except Exception:
            logger.warning(
                "Previous upload marker is invalid; checking NAS again"
            )

    file_size, file_sha256 = calculate_file_sha256(
        DOWNLOAD_PATH
    )

    logger.info(
        "Local backup size: %s bytes",
        file_size,
    )
    logger.info(
        "Local backup SHA256: %s",
        file_sha256,
    )

    upload_id = await initiate_upload(
        session,
        slug,
        file_size,
        file_sha256,
    )

    await upload_missing_chunks(
        session,
        upload_id,
    )

    result = await complete_upload(
        session,
        upload_id,
        file_sha256,
    )

    UPLOAD_DONE_PATH.write_text(
        json.dumps(
            {
                "slug": slug,
                "upload_id": upload_id,
                "filename": result.get("filename", f"{slug}.tar"),
                "size_bytes": result.get("size_bytes", file_size),
                "sha256": result.get("sha256", file_sha256),
                "storage_key": result.get("storage_key"),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    UPLOAD_DONE_PATH.chmod(0o600)

    logger.info("====================================")
    logger.info(" NAS UPLOAD COMPLETED")
    logger.info("====================================")
    logger.info("Upload ID: %s", upload_id)
    logger.info("File size: %s bytes", file_size)
    logger.info("SHA256: %s", file_sha256)
    logger.info("Storage key: %s", result.get("storage_key"))
    logger.info("====================================")


async def run_diagnostic_and_upload(session):
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

    await upload_backup_to_nas(
        session,
        slug,
    )


async def heartbeat(session):
    url = f"{SERVER_URL}/api/agent/heartbeat"

    headers = {
        "X-Client-Key": API_KEY,
        "Content-Type": "application/json",
    }

    payload = {
        "client_code": CLIENT_CODE,
        "agent_version": "0.1.7",
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
    logger.info(" Starting NAS upload test")
    logger.info("====================================")

    timeout = aiohttp.ClientTimeout(
        total=120,
        connect=30,
    )

    async with aiohttp.ClientSession(
        timeout=timeout
    ) as session:

        try:
            await test_supervisor_api(session)

            await run_diagnostic_and_upload(
                session
            )

        except Exception:
            logger.exception(
                "Backup validation or NAS upload failed"
            )

        while True:
            await heartbeat(session)
            await asyncio.sleep(
                HEARTBEAT_INTERVAL
            )


if __name__ == "__main__":
    asyncio.run(main())
