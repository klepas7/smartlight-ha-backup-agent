import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from securetar import SecureTarArchive


OPTIONS_PATH = Path("/data/options.json")
TEST_PASSWORD_PATH = Path("/data/supervisor_test_password")
TEST_STATE_PATH = Path("/data/backup_test_state.json")

SUPERVISOR_URL = "http://supervisor"
DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
AGENT_VERSION = "0.1.11"

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
        "backup_test_now": bool(options.get("backup_test_now", False)),
        "backup_test_interrupt_after_chunks": interrupt_after,
        "policy": policy,
    }


def load_state():
    if not TEST_STATE_PATH.exists():
        return {}

    try:
        state = json.loads(TEST_STATE_PATH.read_text(encoding="utf-8"))
    except Exception as error:
        raise RuntimeError(
            f"Backup test state file is unreadable; refusing to restart workflow: {error}"
        ) from error

    if not isinstance(state, dict):
        raise RuntimeError("Backup test state must contain a JSON object")
    return state


def save_state(state):
