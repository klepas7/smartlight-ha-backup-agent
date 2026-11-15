import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

import aiohttp
from securetar import SecureTarArchive


OPTIONS_PATH = Path("/data/options.json")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
TEST_STATE_PATH = Path("/data/backup_test_state.json")
SCHEDULE_STATE_PATH = Path("/data/backup_schedule_state.json")

SUPERVISOR_URL = "http://supervisor"
DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
AGENT_VERSION = "0.1.14"

HEARTBEAT_INTERVAL = 60
POLICY_SYNC_INTERVAL = 300
CHUNK_SIZE = 8 * 1024 * 1024
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

INSTANCE_ID = str(uuid.uuid4())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("smartlight_backup_agent")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_options():
    if not OPTIONS_PATH.exists():
        raise RuntimeError("Add-on options file not found")

    with OPTIONS_PATH.open("r", encoding="utf-8") as file:
        options = json.load(file)

    for key in ("client_code", "api_key"):
        value = options.get(key, "")
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"Missing Add-on option: {key}")

    policy = {
        "backup_enabled": options.get("backup_enabled", True),
        "backup_day": options.get("backup_day", "sunday"),
        "backup_time": options.get("backup_time", "03:00"),
        "timezone": options.get("timezone", "Europe/Vilnius"),
        "retention_weekly": options.get("retention_weekly", 2),
        "retention_monthly": options.get("retention_monthly", 1),
    }

    interrupt_after = int(
        options.get("backup_test_interrupt_after_chunks", 3)
    )

    if interrupt_after < 0:
        raise RuntimeError(
            "backup_test_interrupt_after_chunks cannot be negative"
        )

    return {
        "client_code": options["client_code"].strip(),
        "api_key": options["api_key"].strip(),
        "server_url": options.get(
            "server_url", DEFAULT_SERVER_URL
        ).rstrip("/"),
        "backup_test_now": bool(
            options.get("backup_test_now", False)
        ),
        "backup_test_interrupt_after_chunks": interrupt_after,
        "backup_once_datetime": options.get(
            "backup_once_datetime", ""
        ).strip(),
        "backup_once_type": options.get(
            "backup_once_type", "full"
        ).strip().lower(),
        "policy": policy,
    }


def load_state(path=TEST_STATE_PATH):
    if not path.exists():
        return {}

    try:
        state = json.loads(
            path.read_text(encoding="utf-8")
        )
    except Exception as error:
        raise RuntimeError(
            f"Backup state file {path} is unreadable; "
            f"refusing to restart workflow: {error}"
        ) from error

    if not isinstance(state, dict):
        raise RuntimeError(
            "Backup test state must contain a JSON object"
        )

    return state


def save_state(state, path=TEST_STATE_PATH):
    temporary = path.with_suffix(".tmp")

    temporary.write_text(
        json.dumps(state, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def supervisor_headers():
    token = os.getenv("SUPERVISOR_TOKEN")

    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is missing")

    return {
        "Authorization": f"Bearer {token}"
    }


def get_backup_password():
    if not TEST_PASSWORD_PATH.is_file():
        raise RuntimeError(
            "Backup password file not found: "
            "/data/supervisor_test_password"
        )

    password = TEST_PASSWORD_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not password:
        raise RuntimeError("Backup password file is empty")

    return password


def calculate_file_sha256(path):
    digest = hashlib.sha256()
    size = 0

    with path.open("rb") as file:
        while True:
            block = file.read(DOWNLOAD_CHUNK_SIZE)

            if not block:
                break

            digest.update(block)
            size += len(block)

    return size, digest.hexdigest()


async def supervisor_json_request(
    session, method, path, **kwargs
):
    timeout = kwargs.pop("timeout", None)

    async with session.request(
        method,
        f"{SUPERVISOR_URL}{path}",
        headers=supervisor_headers(),
        timeout=timeout,
        **kwargs,
    ) as response:

        body = await response.text()

        if response.status >= 400:
            raise RuntimeError(
                f"Supervisor API error {response.status}: "
                f"{body[:1000]}"
            )

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Supervisor returned invalid JSON: {body[:500]}"
            ) from error


async def create_or_reuse_backup(
    session,
    config,
    state,
    state_path=TEST_STATE_PATH,
    backup_label="test",
    backup_mode="full",
):
    existing_slug = state.get("slug")

    if existing_slug:
        logger.info(
            "Reusing existing Supervisor backup slug: %s",
            existing_slug,
        )
        return existing_slug

    if state.get("status") in (
        "requesting",
        "request_uncertain",
    ):
        raise RuntimeError(
            "Previous backup request has an uncertain result. "
            "Check Supervisor backup list before retrying; "
            "refusing to create a duplicate."
        )

    if state.get("status") == "failed":
        raise RuntimeError(
            "Previous Supervisor backup request failed. "
            "Inspect logs and state before retrying."
        )

    password = get_backup_password()

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d-%H%M%S"
    )

    backup_name = (
        f"SmartLight-{config['client_code']}-{backup_label}-{timestamp}"
    )

    state.update({
        "status": "requesting",
        "backup_name": backup_name,
        "backup_request_started_at": utc_now(),
    })

    save_state(state, state_path)

    if backup_mode not in ("full", "partial"):
        raise RuntimeError(f"Unsupported Supervisor backup mode: {backup_mode}")

    endpoint = (
        "/backups/new/full"
        if backup_mode == "full"
        else "/backups/new/partial"
    )

    payload = {
        "name": backup_name,
        "password": password,
        "compressed": True,
        "background": False,
    }

    if backup_mode == "partial":
        payload.update({
            "homeassistant": True,
            "homeassistant_exclude_database": True,
            "addons": [],
            "folders": [],
        })

    logger.info(
        "Starting Supervisor %s backup",
        backup_mode.upper(),
    )
    logger.info("Backup name: %s", backup_name)
    logger.info("Encryption: enabled")
    if backup_mode == "partial":
        logger.info(
            "Partial scope: Home Assistant config only; "
            "database excluded; no add-ons or extra folders"
        )

    long_timeout = aiohttp.ClientTimeout(
        total=None,
        connect=30,
    )

    try:
        result = await supervisor_json_request(
            session,
            "POST",
            endpoint,
            json=payload,
            timeout=long_timeout,
        )

    except Exception as error:
        state.update({
            "status": "request_uncertain",
            "backup_request_error": str(error)[:1000],
            "backup_request_failed_at": utc_now(),
        })

        save_state(state, state_path)
        raise

    data = result.get("data", result)
    slug = data.get("slug")

    if not slug:
        state.update({
            "status": "request_uncertain",
            "backup_request_response": result,
        })

        save_state(state, state_path)

        raise RuntimeError(
            f"Supervisor response did not contain backup slug: {result}"
        )

    state.update({
        "status": "backup_created",
        "slug": slug,
        "backup_created_at": utc_now(),
    })

    save_state(state, state_path)

    logger.info("SUPERVISOR BACKUP CREATED")
    logger.info("Backup slug: %s", slug)
    logger.info("Encryption: enabled")

    return slug


async def download_backup(
    session,
    slug,
    state,
    state_path=TEST_STATE_PATH,
):
    download_path = Path(
        f"/data/supervisor_backup_{slug}.tar"
    )

    partial_path = Path(f"{download_path}.part")

    if download_path.is_file():
        size, digest = calculate_file_sha256(download_path)

        saved_size = state.get("download_size")
        saved_digest = state.get("download_sha256")

        if saved_size == size and saved_digest == digest:
            logger.info(
                "Using existing downloaded backup "
                "(%s bytes, SHA256 %s)",
                size,
                digest,
            )
            return download_path, size, digest

        logger.warning(
            "Existing local backup does not match saved metadata; "
            "downloading again"
        )

        download_path.unlink()

    if partial_path.exists():
        partial_path.unlink()

    logger.info("Downloading Supervisor backup %s", slug)

    timeout = aiohttp.ClientTimeout(
        total=None,
        connect=30,
    )

    digest = hashlib.sha256()
    total_size = 0

    async with session.get(
        f"{SUPERVISOR_URL}/backups/{slug}/download",
        headers=supervisor_headers(),
        timeout=timeout,
    ) as response:

        if response.status != 200:
            body = await response.text()

            raise RuntimeError(
                "Supervisor backup download failed: "
                f"HTTP {response.status}: {body[:1000]}"
            )

        with partial_path.open("wb") as output:
            async for block in response.content.iter_chunked(
                DOWNLOAD_CHUNK_SIZE
            ):
                output.write(block)
                digest.update(block)
                total_size += len(block)

            output.flush()
            os.fsync(output.fileno())

    if total_size <= 0:
        partial_path.unlink(missing_ok=True)
        raise RuntimeError(
            "Supervisor returned an empty backup file"
        )

    partial_path.chmod(0o600)
    partial_path.replace(download_path)
    download_path.chmod(0o600)

    file_digest = digest.hexdigest()

    state.update({
        "download_path": str(download_path),
        "download_size": total_size,
        "download_sha256": file_digest,
        "downloaded_at": utc_now(),
    })

    save_state(state, state_path)

    logger.info(
        "Backup download completed: %s bytes",
        total_size,
    )
    logger.info("Downloaded SHA256: %s", file_digest)

    return download_path, total_size, file_digest


def validate_encrypted_backup(path):
    password = get_backup_password()
    validated = 0

    logger.info(
        "Starting SecureTar encrypted backup validation"
    )

    with SecureTarArchive(
        path,
        "r",
        password=password,
    ) as archive:

        members = archive.tar.getmembers()

        metadata_member = next(
            (
                member for member in members
                if member.name.endswith("backup.json")
            ),
            None,
        )

        if metadata_member is None:
            raise RuntimeError(
                "backup.json not found in backup archive"
            )

        metadata_file = archive.tar.extractfile(
            metadata_member
        )

        if metadata_file is None:
            raise RuntimeError("Cannot read backup.json")

        metadata = json.loads(
            metadata_file.read().decode("utf-8")
        )

        if metadata.get("protected") is not True:
            raise RuntimeError(
                "Backup metadata does not confirm encryption"
            )

        inner_archives = [
            member for member in members
            if member.isfile()
            and (
                member.name.endswith(".tar.gz")
                or member.name.endswith(".tar")
            )
        ]

        if not inner_archives:
            raise RuntimeError(
                "No inner backup archives found"
            )

        logger.info(
            "Encrypted backup confirmed; "
            "validating %s inner archives",
            len(inner_archives),
        )

        for member in inner_archives:
            archive.validate(member)
            validated += 1

            logger.info(
                "Validated archive %s",
                member.name,
            )

    logger.info(
        "SecureTar validation successful: %s inner archives",
        validated,
    )

    return validated
async def nas_request(
    session, method, path, config, **kwargs
):
    headers = kwargs.pop("headers", {})
    headers["X-Client-Key"] = config["api_key"]

    async with session.request(
        method,
        f"{config['server_url']}{path}",
        headers=headers,
        **kwargs,
    ) as response:

        body = await response.text()

        if response.status >= 400:
            raise RuntimeError(
                f"NAS API error {response.status}: "
                f"{body[:1000]}"
            )

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"NAS returned invalid JSON: {body[:500]}"
            ) from error


async def initiate_or_resume_upload(
    session,
    config,
    state,
    file_size,
    file_sha256,
    slug,
    state_path=TEST_STATE_PATH,
    backup_type="manual",
):
    upload_id = state.get("upload_id")

    if upload_id:
        logger.info(
            "Reusing saved NAS upload session: %s",
            upload_id,
        )
        return upload_id

    idempotency_key = f"ha-{slug}-{file_sha256}"

    payload = {
        "idempotency_key": idempotency_key,
        "filename": f"{slug}.tar",
        "file_size": file_size,
        "sha256": file_sha256,
        "backup_type": backup_type,
    }

    result = await nas_request(
        session,
        "POST",
        "/api/agent/uploads/initiate",
        config,
        json=payload,
    )

    upload_id = result.get("upload_id")

    if not upload_id:
        raise RuntimeError(
            f"NAS did not return upload_id: {result}"
        )

    if result.get("chunk_size") != CHUNK_SIZE:
        raise RuntimeError(
            "NAS chunk size mismatch: "
            f"expected {CHUNK_SIZE}, "
            f"got {result.get('chunk_size')}"
        )

    state.update({
        "upload_id": upload_id,
        "upload_idempotency_key": idempotency_key,
        "upload_initiated_at": utc_now(),
        "upload_status": result.get("status"),
    })

    save_state(state, state_path)

    logger.info("NAS upload session: %s", upload_id)
    logger.info(
        "Total chunks: %s",
        result.get("total_chunks"),
    )

    return upload_id


async def get_upload_status(session, config, upload_id):
    return await nas_request(
        session,
        "GET",
        f"/api/agent/uploads/{upload_id}/status",
        config,
    )


async def upload_backup_chunks(
    session,
    config,
    state,
    path,
    upload_id,
    interrupt_after,
    state_path=TEST_STATE_PATH,
):
    status = await get_upload_status(
        session,
        config,
        upload_id,
    )

    if status.get("status") == "verified":
        logger.info(
            "NAS already reports this upload as verified"
        )

        result = await nas_request(
            session,
            "POST",
            f"/api/agent/uploads/{upload_id}/complete",
            config,
        )

        if result.get("status") != "verified":
            raise RuntimeError(
                "NAS verified session returned unexpected "
                f"completion response: {result}"
            )

        state.update({
            "status": "completed",
            "upload_status": "verified",
            "nas_storage_key": result.get("storage_key"),
            "nas_size_bytes": state.get("download_size"),
            "nas_sha256": state.get("download_sha256"),
            "completed_at": utc_now(),
        })

        save_state(state, state_path)

        logger.info(
            "NAS upload was already verified: %s",
            result.get("storage_key"),
        )

        return True

    if status.get("status") == "failed":
        raise RuntimeError(
            "NAS upload session is failed: "
            f"{status.get('failure_reason')}"
        )

    if status.get("status") not in (
        "initiated",
        "uploading",
    ):
        raise RuntimeError(
            f"Unexpected NAS upload status: {status.get('status')}"
        )

    missing_chunks = status.get("missing_chunks")

    if not isinstance(missing_chunks, list):
        raise RuntimeError(
            f"NAS status omitted missing_chunks: {status}"
        )

    total_chunks = status.get("total_chunks")

    if not isinstance(total_chunks, int):
        raise RuntimeError(
            f"NAS status omitted total_chunks: {status}"
        )

    received_count = status.get("received_count", 0)

    logger.info(
        "NAS upload status: %s/%s chunks received; %s missing",
        received_count,
        total_chunks,
        len(missing_chunks),
    )

    if state.get("pause_for_restart"):
        if state.get("paused_instance_id") == INSTANCE_ID:
            logger.info(
                "Upload intentionally paused. "
                "Restart the Add-on to resume."
            )
            return False

        logger.info(
            "Add-on restart detected; "
            "resuming interrupted NAS upload"
        )

        state["pause_for_restart"] = False
        state["resumed_after_restart_at"] = utc_now()
        save_state(state, state_path)

    uploaded_this_run = 0

    timeout = aiohttp.ClientTimeout(
        total=None,
        connect=30,
    )

    for chunk_index in missing_chunks:
        offset = chunk_index * CHUNK_SIZE

        with path.open("rb") as file:
            file.seek(offset)
            chunk_data = file.read(CHUNK_SIZE)

        expected_size = min(
            CHUNK_SIZE,
            status["file_size"] - offset,
        )

        if len(chunk_data) != expected_size:
            raise RuntimeError(
                f"Local backup chunk {chunk_index} "
                f"has unexpected size: {len(chunk_data)}"
            )

        chunk_sha256 = hashlib.sha256(
            chunk_data
        ).hexdigest()

        headers = {
            "X-Chunk-SHA256": chunk_sha256,
            "Content-Type": "application/octet-stream",
        }

        logger.info(
            "Uploading chunk %s/%s (%s bytes)",
            chunk_index + 1,
            total_chunks,
            len(chunk_data),
        )

        result = await nas_request(
            session,
            "PUT",
            f"/api/agent/uploads/{upload_id}/chunks/{chunk_index}",
            config,
            headers=headers,
            data=chunk_data,
            timeout=timeout,
        )

        if result.get("status") not in (
            "received",
            "already_received",
        ):
            raise RuntimeError(
                f"Unexpected NAS chunk response "
                f"for {chunk_index}: {result}"
            )

        uploaded_this_run += 1

        logger.info(
            "Chunk %s result: %s",
            chunk_index,
            result.get("status"),
        )

        state.update({
            "upload_status": "uploading",
            "last_uploaded_chunk": chunk_index,
            "last_chunk_uploaded_at": utc_now(),
        })

        save_state(state, state_path)

        # Tyčinis nutrūkimas atliekamas tik vieną kartą.
        if (
            interrupt_after > 0
            and uploaded_this_run >= interrupt_after
            and not state.get("interruption_test_done", False)
        ):
            state.update({
                "pause_for_restart": True,
                "interruption_test_done": True,
                "paused_instance_id": INSTANCE_ID,
                "paused_after_chunks": uploaded_this_run,
                "paused_at": utc_now(),
            })

            save_state(state, state_path)

            logger.warning(
                "TEST INTERRUPTION: uploaded %s chunks. "
                "Restart the Add-on now; the next run "
                "will resume from NAS missing_chunks.",
                uploaded_this_run,
            )

            return False

    final_status = await get_upload_status(
        session,
        config,
        upload_id,
    )

    if final_status.get("missing_count") != 0:
        raise RuntimeError(
            f"NAS still reports missing chunks: {final_status}"
        )

    logger.info(
        "All NAS chunks received; requesting final verification"
    )

    result = await nas_request(
        session,
        "POST",
        f"/api/agent/uploads/{upload_id}/complete",
        config,
        timeout=timeout,
    )

    if result.get("status") != "verified":
        raise RuntimeError(
            f"NAS did not verify completed upload: {result}"
        )

    if result.get("sha256"):
        expected_sha = state.get("download_sha256")

        if result["sha256"] != expected_sha:
            raise RuntimeError(
                "NAS final SHA256 does not match "
                "local backup SHA256"
            )

    state.update({
        "status": "completed",
        "upload_status": "verified",
        "nas_storage_key": result.get("storage_key"),
        "nas_size_bytes": result.get("size_bytes"),
        "nas_sha256": result.get("sha256"),
        "completed_at": utc_now(),
        "pause_for_restart": False,
    })

    save_state(state, state_path)

    logger.info("====================================")
    logger.info("NAS UPLOAD VERIFIED")
    logger.info("Upload ID: %s", upload_id)
    logger.info("Size: %s bytes", result.get("size_bytes"))
    logger.info("SHA256: %s", result.get("sha256"))
    logger.info("Storage key: %s", result.get("storage_key"))
    logger.info("====================================")

    return True
async def run_backup_test(session, config):
    state = load_state()

    if (
        state.get("status") == "completed"
        and state.get("upload_status") == "verified"
    ):
        logger.info(
            "Backup test and NAS upload already completed"
        )
        return

    slug = await create_or_reuse_backup(
        session,
        config,
        state,
    )

    path, file_size, file_sha256 = await download_backup(
        session,
        slug,
        state,
    )

    if not state.get("validated"):
        validated_count = validate_encrypted_backup(path)

        state.update({
            "validated": True,
            "validated_inner_archives": validated_count,
            "validated_at": utc_now(),
        })

        save_state(state)

    else:
        logger.info(
            "Encrypted backup validation already recorded"
        )

    upload_id = await initiate_or_resume_upload(
        session,
        config,
        state,
        file_size,
        file_sha256,
        slug,
    )

    await upload_backup_chunks(
        session,
        config,
        state,
        path,
        upload_id,
        config["backup_test_interrupt_after_chunks"],
    )


async def run_scheduled_backup(
    session,
    config,
    scheduled_date,
    backup_type,
):
    if backup_type not in ("weekly", "monthly"):
        raise RuntimeError(f"Unsupported scheduled backup type: {backup_type}")

    backup_mode = "full" if backup_type == "monthly" else "partial"
    state = load_state(SCHEDULE_STATE_PATH)

    if state.get("scheduled_date") not in (None, scheduled_date):
        if state.get("status") != "completed":
            raise RuntimeError(
                "A previous scheduled backup is not completed; "
                "refusing to overwrite its recovery state."
            )
        state = {}

    if state.get("scheduled_date") == scheduled_date:
        saved_type = state.get("backup_type")
        if saved_type not in (None, backup_type):
            raise RuntimeError(
                "Scheduled backup type changed for an existing date; "
                "refusing to reuse its recovery state."
            )

    state["scheduled_date"] = scheduled_date
    state["backup_type"] = backup_type
    save_state(state, SCHEDULE_STATE_PATH)

    if (
        state.get("status") == "completed"
        and state.get("upload_status") == "verified"
    ):
        logger.info(
            "Scheduled %s backup for %s already completed",
            backup_type.upper(),
            scheduled_date,
        )
        return True

    slug = await create_or_reuse_backup(
        session,
        config,
        state,
        state_path=SCHEDULE_STATE_PATH,
        backup_label=backup_mode,
        backup_mode=backup_mode,
    )

    path, file_size, file_sha256 = await download_backup(
        session,
        slug,
        state,
        state_path=SCHEDULE_STATE_PATH,
    )

    if not state.get("validated"):
        validated_count = validate_encrypted_backup(path)

        state.update({
            "validated": True,
            "validated_inner_archives": validated_count,
            "validated_at": utc_now(),
        })

        save_state(state, SCHEDULE_STATE_PATH)
    else:
        logger.info(
            "Scheduled encrypted backup validation already recorded"
        )

    upload_id = await initiate_or_resume_upload(
        session,
        config,
        state,
        file_size,
        file_sha256,
        slug,
        state_path=SCHEDULE_STATE_PATH,
        backup_type=backup_type,
    )

    return await upload_backup_chunks(
        session,
        config,
        state,
        path,
        upload_id,
        0,
        state_path=SCHEDULE_STATE_PATH,
    )


async def run_one_time_backup_if_due(session, config):
    target_text = config.get("backup_once_datetime", "")

    if not target_text:
        return

    try:
        target = datetime.fromisoformat(target_text)
    except ValueError as error:
        raise RuntimeError(
            "backup_once_datetime must use YYYY-MM-DDTHH:MM format"
        ) from error

    if target.tzinfo is not None:
        raise RuntimeError(
            "backup_once_datetime must be local time without UTC offset"
        )

    if config.get("backup_once_type") != "full":
        raise RuntimeError(
            "Only backup_once_type=full is currently supported"
        )

    timezone_name = config["policy"].get(
        "timezone",
        "Europe/Vilnius",
    )

    local_now = datetime.now(ZoneInfo(timezone_name))
    local_target = target.replace(tzinfo=ZoneInfo(timezone_name))

    if (
        local_now.date() != local_target.date()
        or local_now < local_target
    ):
        return

    scheduled_date = target.date().isoformat()
    state = load_state(SCHEDULE_STATE_PATH)

    if (
        state.get("scheduled_date") == scheduled_date
        and state.get("status") == "completed"
        and state.get("upload_status") == "verified"
    ):
        return

    logger.info(
        "One-time backup is due: type=FULL, scheduled=%s %s",
        target_text,
        timezone_name,
    )

    await run_scheduled_backup(
        session,
        config,
        scheduled_date,
        "monthly",
    )


async def sync_policy(session, config):
    logger.info("Fetching authoritative backup policy from NAS")

    remote_result = await nas_request(
        session,
        "GET",
        "/api/agent/policy",
        config,
    )

    remote_policy = remote_result.get("policy")

    if not isinstance(remote_policy, dict):
        raise RuntimeError(
            f"NAS returned invalid policy: {remote_result}"
        )

    required = (
        "backup_enabled",
        "backup_day",
        "backup_time",
        "timezone",
        "retention_weekly",
        "retention_monthly",
    )
    missing = [key for key in required if key not in remote_policy]
    if missing:
        raise RuntimeError(
            f"NAS policy is missing required fields: {', '.join(missing)}"
        )

    if not isinstance(remote_policy["backup_enabled"], (bool, int)):
        raise RuntimeError("NAS policy backup_enabled must be boolean")

    day = str(remote_policy["backup_day"]).lower()
    valid_days = {
        "monday", "tuesday", "wednesday", "thursday",
        "friday", "saturday", "sunday",
    }
    if day not in valid_days:
        raise RuntimeError(f"Invalid backup_day in NAS policy: {day}")

    try:
        datetime.strptime(remote_policy["backup_time"], "%H:%M")
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"Invalid backup_time in NAS policy: {remote_policy.get('backup_time')}"
        ) from error

    try:
        ZoneInfo(remote_policy["timezone"])
    except Exception as error:
        raise RuntimeError(
            f"Invalid timezone in NAS policy: {remote_policy.get('timezone')}"
        ) from error

    for key, maximum in (("retention_weekly", 52), ("retention_monthly", 24)):
        value = remote_policy[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise RuntimeError(f"Invalid {key} in NAS policy: {value}")

    remote_policy["backup_enabled"] = bool(remote_policy["backup_enabled"])
    remote_policy["backup_day"] = day

    logger.info("Backup policy fetched successfully from NAS")
    logger.info(
        "Policy: enabled=%s, day=%s, time=%s %s, weekly_retention=%s, monthly_retention=%s",
        remote_policy["backup_enabled"],
        remote_policy["backup_day"],
        remote_policy["backup_time"],
        remote_policy["timezone"],
        remote_policy["retention_weekly"],
        remote_policy["retention_monthly"],
    )

    return remote_policy


async def run_recurring_backup_if_due(session, config, policy):
    if not policy or not policy.get("backup_enabled"):
        return

    timezone_name = policy["timezone"]
    local_now = datetime.now(ZoneInfo(timezone_name))

    weekdays = {
        "monday": 0,
        "tuesday": 1,
        "wednesday": 2,
        "thursday": 3,
        "friday": 4,
        "saturday": 5,
        "sunday": 6,
    }
    scheduled_weekday = weekdays[policy["backup_day"]]

    if local_now.weekday() != scheduled_weekday:
        return

    scheduled_time = datetime.strptime(
        policy["backup_time"], "%H:%M"
    ).time()
    scheduled_at = local_now.replace(
        hour=scheduled_time.hour,
        minute=scheduled_time.minute,
        second=0,
        microsecond=0,
    )

    if local_now < scheduled_at:
        return

    scheduled_date = local_now.date().isoformat()
    backup_type = (
        "monthly"
        if local_now.day <= 7
        else "weekly"
    )

    state = load_state(SCHEDULE_STATE_PATH)
    if (
        state.get("scheduled_date") == scheduled_date
        and state.get("status") == "completed"
        and state.get("upload_status") == "verified"
    ):
        return

    logger.info(
        "Recurring backup is due: type=%s, scheduled=%s %s",
        backup_type.upper(),
        scheduled_at.isoformat(),
        timezone_name,
    )

    await run_scheduled_backup(
        session,
        config,
        scheduled_date,
        backup_type,
    )


async def heartbeat(session, config):
    payload = {
        "client_code": config["client_code"],
        "agent_version": AGENT_VERSION,
        "ha_version": os.getenv(
            "HASSIO_VERSION",
            "unknown",
        ),
    }

    try:
        await nas_request(
            session,
            "POST",
            "/api/agent/heartbeat",
            config,
            json=payload,
        )

        logger.info("Heartbeat OK")

    except Exception as error:
        logger.warning("Heartbeat failed: %s", error)


async def heartbeat_loop(session, config):
    while True:
        await heartbeat(session, config)
        await asyncio.sleep(HEARTBEAT_INTERVAL)


async def main():
    config = load_options()

    logger.info("====================================")
    logger.info(" SmartLight Backup Agent")
    logger.info(" Version: %s", AGENT_VERSION)
    logger.info(" Starting")
    logger.info("====================================")

    timeout = aiohttp.ClientTimeout(
        total=60,
        connect=30,
    )

    async with aiohttp.ClientSession(
        timeout=timeout
    ) as session:

        heartbeat_task = asyncio.create_task(
            heartbeat_loop(session, config)
        )

        last_policy_sync = 0
        active_policy = None

        try:
            while True:
                try:
                    loop_time = (
                        asyncio.get_running_loop().time()
                    )

                    if (
                        last_policy_sync == 0
                        or loop_time - last_policy_sync
                        >= POLICY_SYNC_INTERVAL
                    ):
                        try:
                            active_policy = await sync_policy(session, config)
                            config["policy"] = active_policy
                            last_policy_sync = loop_time
                        except Exception:
                            logger.exception(
                                "NAS policy sync failed; keeping last valid policy"
                            )
                            if active_policy is None:
                                raise

                    if config["backup_test_now"]:
                        await run_backup_test(session, config)

                    await run_one_time_backup_if_due(
                        session,
                        config,
                    )

                    if active_policy is not None:
                        await run_recurring_backup_if_due(
                            session,
                            config,
                            active_policy,
                        )

                except Exception:
                    logger.exception("Agent cycle failed")

                await asyncio.sleep(HEARTBEAT_INTERVAL)

        finally:
            heartbeat_task.cancel()

            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
