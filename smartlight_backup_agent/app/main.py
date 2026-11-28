
import asyncio
import hashlib
import json
import logging
import os
import errno
import fcntl
import random
import re
import shutil
import tarfile
import time
from datetime import timedelta
import tempfile
from urllib.parse import urlsplit
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

import aiohttp
from securetar import SecureTarArchive


OPTIONS_PATH = Path("/data/options.json")
BACKUP_PASSWORD_PATH = Path("/data/backup_password")
LEGACY_PASSWORD_PATH = Path("/data/supervisor_test_password")
PASSWORD_CLIENT_PATH = Path("/data/backup_password_client_code")
SCHEDULE_STATE_PATH = Path("/data/backup_schedule_state.json")

SUPERVISOR_URL = "http://supervisor"
DEFAULT_SERVER_URL = "https://backup.smartlight.lt"
AGENT_VERSION = "1.0.3"

HEARTBEAT_INTERVAL = 60
POLICY_SYNC_INTERVAL = 300
CHUNK_SIZE = 8 * 1024 * 1024
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

INSTANCE_ID = str(uuid.uuid4())
BACKUP_DIR = Path("/backup")
LOCAL_LEDGER = Path("/data/smartlight_verified_local.json")
RESERVE = 256 * 1024**2
TELEMETRY = {"version":1,"stage":"idle"}
STAGE_AT = time.monotonic()

class AgentError(RuntimeError):
    def __init__(self,code,admin=False):
        self.code,self.admin=code,admin
        super().__init__(code)

class HttpError(AgentError):
    def __init__(self,status,code="nas"):
        self.status=status
        super().__init__("auth" if status in (401,403) else code, status in (401,403))

def stage(name,state=None,**fields):
    global STAGE_AT
    if TELEMETRY.get("stage") != name: STAGE_AT=time.monotonic()
    TELEMETRY.clear()
    TELEMETRY.update(version=1,stage=name)
    if state:
        for k in ("scheduled_date","backup_type"):
            if k in state: TELEMETRY[k]=state[k]
    TELEMETRY.update(fields)

def identity(path):
    if path.is_symlink() or not path.is_file(): raise AgentError("source",True)
    st=path.stat()
    return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]

def slug_ok(slug):
    return isinstance(slug,str) and re.fullmatch(r"[a-fA-F0-9]{8}",slug)

def archive_meta(path):
    with tarfile.open(path,"r:") as tar:
        member=next((m for m in tar if m.name in ("backup.json","./backup.json","snapshot.json","./snapshot.json")),None)
        if member is None or not member.isfile() or member.size>1024*1024: raise AgentError("source",True)
        with tar.extractfile(member) as f: return json.load(f)

def match_meta(meta,state):
    return (meta.get("slug")==state.get("slug") and meta.get("name")==state.get("backup_name")
            and meta.get("protected") is True and meta.get("type")==("full" if state["backup_type"]=="monthly" else "partial"))


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

    return {
        "client_code": options["client_code"].strip(),
        "api_key": options["api_key"].strip(),
        "server_url": options.get(
            "server_url", DEFAULT_SERVER_URL
        ).rstrip("/"),
        "log_level": str(options.get("log_level", "info")).lower(),
    }


def load_state(path=SCHEDULE_STATE_PATH):
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
            "Backup schedule state must contain a JSON object"
        )

    return state


def save_state(state, path=SCHEDULE_STATE_PATH):
    fd, tmp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd,"w") as f:
            json.dump(state,f,sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def supervisor_headers():
    token = os.getenv("SUPERVISOR_TOKEN")

    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is missing")

    return {
        "Authorization": f"Bearer {token}"
    }


def get_backup_password():
    if not BACKUP_PASSWORD_PATH.is_file() and LEGACY_PASSWORD_PATH.is_file():
        logger.warning(
            "Migrating existing backup password to the production file path"
        )
        os.replace(LEGACY_PASSWORD_PATH, BACKUP_PASSWORD_PATH)
        BACKUP_PASSWORD_PATH.chmod(0o600)

    if not BACKUP_PASSWORD_PATH.is_file():
        raise RuntimeError(
            "Backup password file not found: /data/backup_password"
        )

    password = BACKUP_PASSWORD_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not password:
        raise RuntimeError("Backup password file is empty")

    return password


def write_private_file(path, value):
    # Do not expose secrets through permissions or partially written files.
    fd, tmp = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(value)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_local_password():
    if BACKUP_PASSWORD_PATH.is_file() or LEGACY_PASSWORD_PATH.is_file():
        return get_backup_password()
    return None


async def provision_backup_credentials(session, config):
    url = urlsplit(config["server_url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise RuntimeError("Backup credential provisioning requires an HTTPS NAS URL")
    code = config["client_code"]
    if PASSWORD_CLIENT_PATH.exists():
        if PASSWORD_CLIENT_PATH.read_text(encoding="utf-8").strip() != code:
            raise RuntimeError("Local backup credential belongs to another client; recovery review required")

    local_password = read_local_password()
    # Pending local archive data must never be assigned a new password.
    pending = load_state(SCHEDULE_STATE_PATH)
    if local_password is None and pending.get("slug"):
        raise RuntimeError("Pending backup has no local encryption password; recovery review required")

    # Dedicated request: do not use nas_request, whose diagnostic messages
    # may contain the response body. Never send credentials across redirects.
    async with session.post(
        config["server_url"] + "/api/agent/backup-credentials",
        headers={"X-Client-Key": config["api_key"]},
        json={"client_code": code, "local_password": local_password},
        allow_redirects=False,
    ) as response:
        if response.status != 200:
            if response.status == 409:
                raise AgentError("auth",True)
            raise RuntimeError(f"NAS backup credential provisioning failed (HTTP {response.status})")
        try:
            data = await response.json()
            password = data["backup_password"]
            if data["client_code"] != code or not isinstance(password, str) or not password or password.strip() != password:
                raise ValueError()
        except Exception:
            raise RuntimeError("Invalid NAS backup credential response") from None
    if local_password is not None and password != local_password:
        raise RuntimeError("NAS backup password differs from local password; refusing to overwrite")
    # Bind future client reconfiguration to the existing credential.
    write_private_file(PASSWORD_CLIENT_PATH, code)
    write_private_file(BACKUP_PASSWORD_PATH, password)
    logger.info("Backup encryption credential synchronized with NAS Vault")


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
        allow_redirects=False,
        **kwargs,
    ) as response:

        body = await response.text()

        if response.status >= 400:
            code = "space" if "no space left on device" in body.lower() or "[errno 28]" in body.lower() else "uncertain"
            raise HttpError(response.status,code)

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise AgentError("uncertain",True) from None


async def supervisor_list(session):
    result=await supervisor_json_request(session,"GET","/backups")
    rows=result.get("data",result).get("backups")
    if not isinstance(rows,list): raise AgentError("uncertain",True)
    return rows

async def create_or_reuse_backup(session,config,state,state_path=SCHEDULE_STATE_PATH,backup_label="scheduled",backup_mode="full"):
    if state.get("slug"):
        if not slug_ok(state["slug"]): raise AgentError("source",True)
        return state["slug"]
    if state.get("status") in ("requesting","request_uncertain","failed","waiting_space"):
        # Exact unique persisted name; never adopt arbitrary user backups.
        if state.get("backup_name"):
            rows=await supervisor_list(session)
            matches=[r for r in rows if r.get("name")==state["backup_name"]]
            if len(matches)>1: raise AgentError("uncertain",True)
            if matches:
                slug=matches[0].get("slug")
                if not slug_ok(slug): raise AgentError("source",True)
                state.update(slug=slug,status="backup_created")
                save_state(state,state_path)
                return slug
        # Explicit confirmed ENOSPC can retry; uncertain lost response cannot.
        if state.get("status")!="waiting_space": raise AgentError("uncertain",True)
    usage=shutil.disk_usage(BACKUP_DIR)
    estimate=state.get("estimated_bytes",0)
    # No previous measurement: conservative reserve plus a modest estimate,
    # not a guarantee of compressed archive size.
    minimum=max(RESERVE, int(usage.total*0.03))+max(estimate,512*1024**2 if backup_mode=="full" else 64*1024**2)
    if usage.free<minimum: raise AgentError("space")
    task=state.setdefault("task_id",uuid.uuid4().hex)
    name=f"SmartLight-{config['client_code']}-{backup_label}-{state['scheduled_date']}-{task}"
    state.update(status="requesting",backup_name=name,backup_filename=name+".tar",backup_request_started_at=utc_now(),owner= config["client_code"])
    save_state(state,state_path)
    stage("creating",state)
    payload={"name":name,"filename":state["backup_filename"],"location":None,
             "password":get_backup_password(),"compressed":True,"background":False}
    if backup_mode=="partial":
        payload.update(homeassistant=True,homeassistant_exclude_database=True,addons=[],folders=[])
    try:
        result=await supervisor_json_request(session,"POST","/backups/new/"+backup_mode,
            json=payload,timeout=aiohttp.ClientTimeout(total=None,connect=30))
        data=result.get("data",result)
        slug=data.get("slug")
        if not slug_ok(slug): raise AgentError("uncertain",True)
    except Exception as e:
        state["status"]="waiting_space" if isinstance(e,HttpError) and e.code=="space" else "request_uncertain"
        save_state(state,state_path)
        if state["status"]=="waiting_space": raise AgentError("space") from None
        raise AgentError("uncertain",True) from None
    state.update(slug=slug,status="backup_created",backup_created_at=utc_now())
    save_state(state,state_path)
    logger.info("SUPERVISOR BACKUP CREATED: %s",slug)
    return slug

async def download_backup(session,slug,state,state_path=SCHEDULE_STATE_PATH):
    # No new local copy. Existing v1.0.2 staging files may be reused, never
    # created by 1.0.3. Direct original must match TAR and Supervisor metadata.
    if not slug_ok(slug): raise AgentError("source",True)
    legacy=Path(f"/data/supervisor_backup_{slug}.tar")
    candidates=[]
    fname=state.get("backup_filename")
    if fname and Path(fname).name==fname: candidates.append(BACKUP_DIR/fname)
    candidates.append(BACKUP_DIR/f"{slug}.tar")
    if not fname and state.get("backup_name") and Path(state["backup_name"]).name==state["backup_name"]:
        candidates.append(BACKUP_DIR/(state["backup_name"]+".tar"))
    if state.get("download_path")==str(legacy): candidates.insert(0,legacy)
    info=(await supervisor_json_request(session,"GET",f"/backups/{slug}/info"))
    info=info.get("data",info)
    if not match_meta(info,state): raise AgentError("source",True)
    chosen=None
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            try: meta=await asyncio.to_thread(archive_meta,candidate)
            except (OSError,tarfile.TarError,ValueError,AgentError): continue
            if match_meta(meta,state):
                chosen=candidate
                break
    if chosen is None: raise AgentError("source",True)
    before=identity(chosen)
    local=info.get("location_attributes",{}).get(".local",{})
    expected=local.get("size_bytes") or info.get("size_bytes")
    if type(expected) is int and expected!=before[2]: raise AgentError("source",True)
    if state.get("source_identity")==before and state.get("download_path")==str(chosen) and state.get("download_sha256"):
        return chosen,before[2],state["download_sha256"]
    stage("validating",state,bytes_total=before[2])
    size,digest=await asyncio.to_thread(calculate_file_sha256,chosen)
    if before!=identity(chosen) or size!=before[2]: raise AgentError("source",True)
    if state.get("download_sha256") and state["download_sha256"]!=digest: raise AgentError("integrity",True)
    state.update(download_path=str(chosen),download_size=size,download_sha256=digest,source_identity=before,validated=False)
    save_state(state,state_path)
    return chosen,size,digest


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
        allow_redirects=False,
        **kwargs,
    ) as response:

        if response.status >= 300:
            raise HttpError(response.status,"space" if response.status==507 else "nas")
        body = await response.text()

        if not body:
            return {}

        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise AgentError("nas") from None


async def initiate_or_resume_upload(
    session,
    config,
    state,
    file_size,
    file_sha256,
    slug,
    state_path=SCHEDULE_STATE_PATH,
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


def verify_receipt(result,config,state):
    expected_key=f"clients/{config['client_code']}/{state['backup_type']}/{state['upload_id']}.tar"
    if not (result.get("status")=="verified" and result.get("upload_id")==state["upload_id"]
            and result.get("client_code")==config["client_code"]
            and result.get("size_bytes")==state["download_size"]
            and result.get("sha256")==state["download_sha256"]
            and result.get("storage_key")==expected_key):
        raise AgentError("integrity",True)

def finish_verified(result,config,state,state_path):
    verify_receipt(result,config,state)
    state.update(status="completed",upload_status="verified",nas_storage_key=result["storage_key"],
                 nas_size_bytes=result["size_bytes"],nas_sha256=result["sha256"],completed_at=utc_now(),cleanup_pending=True)
    save_state(state,state_path)
    logger.info("NAS UPLOAD VERIFIED: %s",state["upload_id"])

async def poll_final(session,config,state,state_path):
    upload_id=state["upload_id"]
    stage("nas_verifying",state)
    # Re-submit is lock-protected and idempotent; restarts requeue assembly.
    result=await nas_request(session,"POST",f"/api/agent/uploads/{upload_id}/complete-async",config)
    if result.get("status")=="verified":
        finish_verified(result,config,state,state_path); return True
    await asyncio.sleep(15)
    return False

def read_chunk(path,offset,expected,source_identity):
    if identity(path)!=source_identity: raise AgentError("source",True)
    with path.open("rb") as f: f.seek(offset); data=f.read(expected)
    if len(data)!=expected or identity(path)!=source_identity: raise AgentError("source",True)
    return data

async def upload_backup_chunks(session,config,state,path,upload_id,state_path=SCHEDULE_STATE_PATH):
    status=await get_upload_status(session,config,upload_id)
    if status.get("status")=="verified":
        finish_verified(status,config,state,state_path); return True
    if status.get("status")=="assembling":
        return await poll_final(session,config,state,state_path)
    if status.get("status") not in ("initiated","uploading"): raise AgentError("nas",True)
    if status.get("file_size")!=state["download_size"] or status.get("chunk_size")!=CHUNK_SIZE:
        raise AgentError("integrity",True)
    missing=status.get("missing_chunks")
    total=(state["download_size"]+CHUNK_SIZE-1)//CHUNK_SIZE
    if not isinstance(missing,list) or len(set(missing))!=len(missing) or any(type(i) is not int or not 0<=i<total for i in missing):
        raise AgentError("nas",True)
    remaining=sum(min(CHUNK_SIZE,state["download_size"]-i*CHUNK_SIZE) for i in missing)
    done=state["download_size"]-remaining
    start=time.monotonic(); initial=done
    stage("uploading",state,bytes_done=done,bytes_total=state["download_size"])
    for i in missing:
        offset=i*CHUNK_SIZE; expected=min(CHUNK_SIZE,state["download_size"]-offset)
        data=await asyncio.to_thread(read_chunk,path,offset,expected,state["source_identity"])
        digest=hashlib.sha256(data).hexdigest()
        result=await nas_request(session,"PUT",f"/api/agent/uploads/{upload_id}/chunks/{i}",config,
            headers={"X-Chunk-SHA256":digest,"Content-Type":"application/octet-stream"},data=data,
            timeout=aiohttp.ClientTimeout(total=180,connect=30))
        if result.get("status") not in ("received","already_received"): raise AgentError("nas")
        done+=expected
        stage("uploading",state,bytes_done=done,bytes_total=state["download_size"],rate_bps=int((done-initial)/max(time.monotonic()-start,1)))
    if identity(path)!=state["source_identity"]: raise AgentError("source",True)
    state["upload_status"]="assembling"; save_state(state,state_path)
    return await poll_final(session,config,state,state_path)

async def cleanup_local(session,config,state,state_path):
    if not state.get("cleanup_pending"): return
    proof=await get_upload_status(session,config,state["upload_id"])
    verify_receipt(proof,config,state)
    stage("cleanup",state)
    slug=state["slug"]
    legacy=Path(f"/data/supervisor_backup_{slug}.tar")
    if state.get("download_path")==str(legacy) and legacy.is_file():
        before=identity(legacy)
        if before!=state.get("source_identity"):
            size,digest=await asyncio.to_thread(calculate_file_sha256,legacy)
            if before!=identity(legacy) or size!=state["download_size"] or digest!=state["download_sha256"]: raise AgentError("integrity",True)
        legacy.unlink()
    # Track only archives created by this version and verified under this client.
    if state.get("owner")==config["client_code"] and state.get("task_id"):
        ledger=load_state(LOCAL_LEDGER)
        ledger[state["upload_id"]]={k:state[k] for k in ("slug","backup_name","backup_type","download_size","download_sha256","upload_id","owner","completed_at","source_identity","download_path")}
        save_state(ledger,LOCAL_LEDGER)
        retention=config.get("policy",{}).get("local_retention")
        if type(retention) is int and retention in (0,1,2):
            ordered=sorted(ledger.values(),key=lambda x:x["completed_at"],reverse=True)
            for item in ordered[retention:]:
                if item["owner"]!=config["client_code"]: raise AgentError("source",True)
                try: receipt=await get_upload_status(session,config,item["upload_id"])
                except HttpError as e:
                    if e.status in (404,409): continue
                    raise
                verify_receipt(receipt,config,item)
                rows=await supervisor_list(session)
                matching=[r for r in rows if r.get("slug")==item["slug"]]
                if matching:
                    meta=matching[0]
                    if not match_meta(meta,item): raise AgentError("source",True)
                    locations=meta.get("locations")
                    if not isinstance(locations,list): raise AgentError("source",True)
                    if None in locations or ".local" in locations:
                        local=meta.get("location_attributes",{}).get(".local",{})
                        if local.get("size_bytes")!=item["download_size"]: raise AgentError("integrity",True)
                        owned=Path(item["download_path"])
                        if owned.parent!=BACKUP_DIR or not owned.is_file() or owned.is_symlink():
                            raise AgentError("source",True)
                        if not match_meta(await asyncio.to_thread(archive_meta,owned),item): raise AgentError("source",True)
                        # Crashes/restored source may change file identity. Hash before destructive local cleanup.
                        if identity(owned)!=item.get("source_identity"):
                            size,digest=await asyncio.to_thread(calculate_file_sha256,owned)
                            if size!=item["download_size"] or digest!=item["download_sha256"]: raise AgentError("integrity",True)
                        await supervisor_json_request(session,"DELETE",f"/backups/{item['slug']}",json={"location":".local"})
                del ledger[item["upload_id"]]; save_state(ledger,LOCAL_LEDGER)
    state["cleanup_pending"]=False
    save_state(state,state_path)
    stage("idle")

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
        estimates=state.get("measured_sizes",{})
        if state.get("download_size"): estimates[state["backup_type"]]=state["download_size"]
        state={"estimated_bytes":estimates.get(backup_type,0),"measured_sizes":estimates}

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
        await cleanup_local(session,config,state,SCHEDULE_STATE_PATH)
        return True

    # Check remote status before touching or rehashing the source.
    if state.get("upload_id"):
        try:
            remote=await get_upload_status(session,config,state["upload_id"])
        except HttpError as e:
            if e.status!=404: raise
            state.pop("upload_id",None); save_state(state,SCHEDULE_STATE_PATH)
        else:
            if remote.get("status")=="verified":
                finish_verified(remote,config,state,SCHEDULE_STATE_PATH)
                await cleanup_local(session,config,state,SCHEDULE_STATE_PATH)
                return True
            if remote.get("status")=="assembling":
                return await poll_final(session,config,state,SCHEDULE_STATE_PATH)

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
        stage("validating",state,bytes_total=file_size)
        try: validated_count = await asyncio.to_thread(validate_encrypted_backup,path)
        except Exception: raise AgentError("integrity",True) from None
        if identity(path)!=state["source_identity"]: raise AgentError("source",True)

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

    finished=await upload_backup_chunks(session,config,state,path,upload_id,state_path=SCHEDULE_STATE_PATH)
    if finished: await cleanup_local(session,config,state,SCHEDULE_STATE_PATH)
    return finished


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
        "initial_full_required",
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

    if type(remote_policy["initial_full_required"]) is not bool:
        raise RuntimeError(
            "NAS policy initial_full_required must be boolean"
        )

    retention=remote_policy.get("local_retention")
    if retention is not None and (type(retention) is not int or retention not in (0,1,2)):
        raise AgentError("nas",True)
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

    # Finish a previously scheduled backup before evaluating a new
    # schedule. Upload recovery must not wait for the next Sunday.
    pending = load_state(SCHEDULE_STATE_PATH)
    if pending.get("status")=="completed" and pending.get("upload_status")=="verified" and not pending.get("task_id") and slug_ok(pending.get("slug")):
        legacy=Path(f"/data/supervisor_backup_{pending['slug']}.tar")
        if legacy.is_file() and pending.get("download_path")==str(legacy):
            proof=await get_upload_status(session,config,pending["upload_id"])
            verify_receipt(proof,config,pending)
            before=identity(legacy)
            size,digest=await asyncio.to_thread(calculate_file_sha256,legacy)
            if before!=identity(legacy) or size!=pending["download_size"] or digest!=pending["download_sha256"]: raise AgentError("integrity",True)
            legacy.unlink()
    if pending.get("cleanup_pending"):
        await cleanup_local(session,config,pending,SCHEDULE_STATE_PATH)
    if pending.get("scheduled_date") and not (
        pending.get("status") == "completed"
        and pending.get("upload_status") == "verified"
    ):
        previous_type = pending.get("backup_type")
        previous_date = pending["scheduled_date"]

        if previous_type not in ("weekly", "monthly"):
            raise RuntimeError(
                "Unfinished backup has invalid backup_type; "
                "refusing to create another backup"
            )

        logger.info(
            "Resuming unfinished %s backup scheduled for %s",
            previous_type.upper(),
            previous_date,
        )

        await run_scheduled_backup(
            session, config, previous_date, previous_type
        )
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

    latest = local_now - timedelta(days=(local_now.weekday()-scheduled_weekday)%7)

    scheduled_time = datetime.strptime(
        policy["backup_time"], "%H:%M"
    ).time()
    scheduled_at = latest.replace(
        hour=scheduled_time.hour,
        minute=scheduled_time.minute,
        second=0,
        microsecond=0,
    )

    if local_now < scheduled_at:
        scheduled_at -= timedelta(days=7)

    scheduled_date = scheduled_at.date().isoformat()
    # The first verified FULL is mandatory for every client.
    backup_type = (
        "monthly"
        if policy["initial_full_required"] or scheduled_at.day <= 7
        else "weekly"
    )

    state = load_state(SCHEDULE_STATE_PATH)
    if (
        (state.get("scheduled_date") or "") >= scheduled_date
        and state.get("status") == "completed"
        and state.get("upload_status") == "verified"
    ):
        return

    # New installations wait for the next scheduled slot; established agents
    # catch up one missed slot rather than launching a historical backlog.
    if not state.get("scheduled_date") and scheduled_at.date()!=local_now.date():
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

    payload["backup_telemetry"]={**TELEMETRY,"stage_age":int(time.monotonic()-STAGE_AT)}
    try:
        usage=shutil.disk_usage(BACKUP_DIR)
        payload["backup_telemetry"].update(free_bytes=usage.free,total_bytes=usage.total)
    except OSError: pass
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
    log_level = getattr(logging, config["log_level"].upper(), None)
    if not isinstance(log_level, int):
        raise RuntimeError(f"Invalid log_level: {config['log_level']}")
    logger.setLevel(log_level)

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
        credentials_ready = False
        retries=0

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
                            logger.warning("NAS policy sync failed; keeping last valid policy")
                            if active_policy is None:
                                raise

                    if not credentials_ready:
                        await provision_backup_credentials(session, config)
                        credentials_ready = True

                    if active_policy is not None:
                        await run_recurring_backup_if_due(
                            session,
                            config,
                            active_policy,
                        )

                    retries=0
                    delay=HEARTBEAT_INTERVAL
                except Exception as error:
                    retries+=1
                    code=error.code if isinstance(error,AgentError) else ("space" if isinstance(error,OSError) and error.errno==errno.ENOSPC else "unknown")
                    delay=min(900,60*2**min(retries-1,4))+random.randint(0,15)
                    label="admin_required" if isinstance(error,AgentError) and error.admin else "waiting_space" if code=="space" else "retry_waiting"
                    stage(label,error=code,retry_count=retries,retry_after=delay)
                    logger.warning("Backup cycle deferred: %s (retry in %ss)",code,delay)

                await asyncio.sleep(delay)

        finally:
            heartbeat_task.cancel()

            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    with open("/data/.smartlight-agent.lock","a") as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        asyncio.run(main())

