
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import aiohttp


OPTIONS_PATH = Path("/data/options.json")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
BACKUP_TEST_STATE_PATH = Path("/data/backup_test_state.json")

DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
SUPERVISOR_URL = "http://supervisor"

AGENT_VERSION = "0.1.10"

HEARTBEAT_INTERVAL = 60
POLICY_SYNC_INTERVAL = 300


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("smartlight_backup_agent")


def load_options():
    if not OPTIONS_PATH.exists():
        raise RuntimeError("Add-on options file not found")

    with OPTIONS_PATH.open("r", encoding="utf-8") as file:
        options = json.load(file)

    required = ["client_code", "api_key"]

    for key in required:
        if not options.get(key, "").strip():
            raise RuntimeError(f"Missing Add-on option: {key}")

    policy = {
        "backup_enabled": options.get("backup_enabled", True),
        "backup_day": options.get("backup_day", "sunday"),
        "backup_time": options.get("backup_time", "03:00"),
        "timezone": options.get("timezone", "Europe/Vilnius"),
        "retention_weekly": options.get("retention_weekly", 2),
        "retention_monthly": options.get("retention_monthly", 1),
    }

    return {
        "client_code": options["client_code"].strip(),
        "api_key": options["api_key"].strip(),
        "server_url": options.get(
            "server_url", DEFAULT_SERVER_URL
        ).rstrip("/"),
        "backup_test_now": bool(
            options.get("backup_test_now", False)
        ),
        "policy": policy,
    }


def supervisor_headers():
    token = os.getenv("SUPERVISOR_TOKEN")

    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is missing")

    return {
        "Authorization": f"Bearer {token}",
    }


def get_backup_password():
    if not TEST_PASSWORD_PATH.exists():
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


def save_backup_test_state(state):
    temporary_path = BACKUP_TEST_STATE_PATH.with_suffix(".tmp")

    temporary_path.write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )

    temporary_path.chmod(0o600)
    temporary_path.replace(BACKUP_TEST_STATE_PATH)
    BACKUP_TEST_STATE_PATH.chmod(0o600)


def load_backup_test_state():
    if not BACKUP_TEST_STATE_PATH.exists():
        return None

    try:
        return json.loads(
            BACKUP_TEST_STATE_PATH.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        logger.exception("Cannot read backup test state")
        raise RuntimeError(
            "Backup test state is invalid; "
            "refusing to risk creating a duplicate backup"
        )


async def supervisor_request(session, method, path, **kwargs):
    url = f"{SUPERVISOR_URL}{path}"

    headers = kwargs.pop("headers", {})
    headers.update(supervisor_headers())

    async with session.request(
        method,
        url,
        headers=headers,
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
        except json.JSONDecodeError:
            raise RuntimeError(
                f"Supervisor returned invalid JSON: {body[:500]}"
            )


async def create_test_backup(session, config):
    existing_state = load_backup_test_state()

    if existing_state:
        logger.info(
            "Backup test already processed. State: %s",
            existing_state.get("status", "unknown"),
        )
        return

    password = get_backup_password()

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d-%H%M%S"
    )

    backup_name = (
        f"SmartLight-{config['client_code']}-test-{timestamp}"
    )

    # Save the request state BEFORE calling Supervisor.
    # This prevents duplicate backups if the Agent restarts
    # while Supervisor is processing the request.
    save_backup_test_state({
        "status": "requesting",
        "backup_name": backup_name,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    logger.info("====================================")
    logger.info("Starting one-time Supervisor backup test")
    logger.info("Backup name: %s", backup_name)
    logger.info("Backup type: full")
    logger.info("Encryption: enabled")
    logger.info("====================================")

    # A full backup can take a long time.
    # No total timeout is imposed on this request.
    timeout = aiohttp.ClientTimeout(
        total=None,
        connect=30,
    )

    try:
        result = await supervisor_request(
            session,
            "POST",
            "/backups/new/full",
            json={
                "name": backup_name,
                "password": password,
                "compressed": True,
                "background": False,
            },
            timeout=timeout,
        )

        data = result.get("data", result)

        slug = data.get("slug")

        if not slug:
            raise RuntimeError(
                "Supervisor did not return backup slug: "
                f"{result}"
            )

        save_backup_test_state({
            "status": "completed",
            "backup_name": backup_name,
            "slug": slug,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })

        logger.info("====================================")
        logger.info("SUPERVISOR BACKUP CREATED")
        logger.info("Backup name: %s", backup_name)
        logger.info("Backup slug: %s", slug)
        logger.info("Encryption: enabled")
        logger.info("====================================")

    except Exception as error:
        save_backup_test_state({
            "status": "failed",
            "backup_name": backup_name,
            "error": str(error)[:1000],
            "failed_at": datetime.now(timezone.utc).isoformat(),
        })

        raise


async def reset_backup_test_if_disabled(config):
    if config["backup_test_now"]:
        return

    if BACKUP_TEST_STATE_PATH.exists():
        BACKUP_TEST_STATE_PATH.unlink()
        logger.info(
            "One-time backup test is disabled. "
            "Test trigger has been reset."
        )


async def server_request(session, method, path, config, **kwargs):
    url = f"{config['server_url']}{path}"

    headers = kwargs.pop("headers", {})
    headers["X-Client-Key"] = config["api_key"]

    async with session.request(
        method,
        url,
        headers=headers,
        **kwargs,
    ) as response:

        body = await response.text()

        if response.status >= 400:
            raise RuntimeError(
                f"NAS API error {response.status}: {body[:1000]}"
            )

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"NAS returned invalid JSON: {body[:500]}"
            )


async def sync_policy(session, config):
    logger.info("Synchronizing backup policy with NAS")

    local_policy = config["policy"]

    update_result = await server_request(
        session,
        "PUT",
        "/api/agent/policy",
        config,
        json=local_policy,
    )

    if update_result.get("status") != "updated":
        raise RuntimeError(
            f"Unexpected policy update response: {update_result}"
        )

    remote_result = await server_request(
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

    for key, expected in local_policy.items():
        actual = remote_policy.get(key)

        if key == "backup_enabled":
            actual = bool(actual)

        if actual != expected:
            raise RuntimeError(
                f"Policy mismatch for {key}: "
                f"HA={expected}, NAS={actual}"
            )

    logger.info("Backup policy synchronized successfully")
    logger.info(
        "Policy: enabled=%s, day=%s, time=%s, "
        "weekly=%s, monthly=%s",
        local_policy["backup_enabled"],
        local_policy["backup_day"],
        local_policy["backup_time"],
        local_policy["retention_weekly"],
        local_policy["retention_monthly"],
    )


async def heartbeat(session, config):
    payload = {
        "client_code": config["client_code"],
        "agent_version": AGENT_VERSION,
        "ha_version": os.getenv("HASSIO_VERSION", "unknown"),
    }

    try:
        await server_request(
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

    await reset_backup_test_if_disabled(config)

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

        try:
            while True:
                try:
                    loop_time = asyncio.get_running_loop().time()

                    if (
                        last_policy_sync == 0
                        or loop_time - last_policy_sync
                        >= POLICY_SYNC_INTERVAL
                    ):
                        await sync_policy(session, config)
                        last_policy_sync = loop_time

                    if config["backup_test_now"]:
                        await create_test_backup(session, config)

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
