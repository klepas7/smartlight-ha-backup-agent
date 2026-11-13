
import asyncio
import json
import logging
import os
from pathlib import Path

import aiohttp


OPTIONS_PATH = Path("/data/options.json")

DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
AGENT_VERSION = "0.1.8"

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
        "policy": policy,
    }


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

    # HA Add-on configuration is authoritative.
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

    # Read policy back from NAS and verify it.
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


async def main():
    config = load_options()

    logger.info("====================================")
    logger.info(" SmartLight Backup Agent")
    logger.info(" Version: %s", AGENT_VERSION)
    logger.info(" Starting policy synchronization")
    logger.info("====================================")

    timeout = aiohttp.ClientTimeout(
        total=60,
        connect=30,
    )

    async with aiohttp.ClientSession(
        timeout=timeout
    ) as session:

        last_policy_sync = 0

        while True:
            try:
                await heartbeat(session, config)

                loop_time = asyncio.get_running_loop().time()

                if (
                    last_policy_sync == 0
                    or loop_time - last_policy_sync
                    >= POLICY_SYNC_INTERVAL
                ):
                    await sync_policy(session, config)
                    last_policy_sync = loop_time

            except Exception:
                logger.exception("Agent cycle failed")

            await asyncio.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
