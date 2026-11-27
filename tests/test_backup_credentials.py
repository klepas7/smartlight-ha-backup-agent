import asyncio
import importlib.util
import json
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.modules["aiohttp"] = types.ModuleType("aiohttp")
securetar = types.ModuleType("securetar")
securetar.SecureTarArchive = object
sys.modules["securetar"] = securetar
spec = importlib.util.spec_from_file_location("agent", Path(__file__).resolve().parents[1]/"smartlight_backup_agent/app/main.py")
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)

passed = 0
def check(name, result):
    global passed
    assert result, name
    passed += 1
    print(f"PASS {passed}: {name}")

class Response:
    def __init__(self, status, value):
        self.status, self.value = status, value
    async def __aenter__(self): return self
    async def __aexit__(self,*args): pass
    async def json(self): return self.value

class Session:
    def __init__(self, password, status=200, code="SL-A"):
        self.password, self.status, self.code = password, status, code
        self.calls=[]
    def post(self,url,**kwargs):
        self.calls.append((url,kwargs))
        return Response(self.status, {"client_code":self.code,"backup_password":self.password})

async def fails(fn):
    try: await fn
    except RuntimeError: return True
    raise AssertionError("Expected refusal")

async def test():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        ha.BACKUP_PASSWORD_PATH=root/"backup_password"
        ha.LEGACY_PASSWORD_PATH=root/"supervisor_test_password"
        ha.PASSWORD_CLIENT_PATH=root/"backup_password_client_code"
        ha.SCHEDULE_STATE_PATH=root/"backup_schedule_state.json"
        config={"client_code":"SL-A","api_key":"synthetic","server_url":"https://backup.example"}
        # Briedziai 1: original pending monthly, no password/slug.
        ha.save_state({"scheduled_date":"2026-11-27","backup_type":"monthly"},ha.SCHEDULE_STATE_PATH)
        state_before=ha.SCHEDULE_STATE_PATH.read_bytes()
        sess=Session("generated-secret")
        await ha.provision_backup_credentials(sess,config)
        check("Missing password fixed automatically",ha.get_backup_password()=="generated-secret")
        check("Pending Initial FULL preserved byte-for-byte",ha.SCHEDULE_STATE_PATH.read_bytes()==state_before)
        check("Password permissions private", stat.S_IMODE(ha.BACKUP_PASSWORD_PATH.stat().st_mode)==0o600)
        check("Client binding permissions private",stat.S_IMODE(ha.PASSWORD_CLIENT_PATH.stat().st_mode)==0o600)
        check("No password sent on new enrollment",sess.calls[0][1]["json"]["local_password"] is None)
        check("Redirects forbidden",sess.calls[0][1]["allow_redirects"] is False)
        await ha.provision_backup_credentials(sess,config)
        check("Restart sends same password",sess.calls[-1][1]["json"]["local_password"]=="generated-secret")
        check("Conflict refused",await fails(ha.provision_backup_credentials(Session("different"),config)))
        check("Conflict leaves password unchanged",ha.get_backup_password()=="generated-secret")
        check("Other client rejected",await fails(ha.provision_backup_credentials(sess,{**config,"client_code":"SL-B"})))
        check("HTTP endpoint refused",await fails(ha.provision_backup_credentials(sess,{**config,"server_url":"http://backup.example"})))
        check("Wrong response identity refused",await fails(ha.provision_backup_credentials(Session("generated-secret",code="SL-B"),config)))
        check("NAS error refused without state changes",await fails(ha.provision_backup_credentials(Session("untrusted",409),config)))
        check("Pending state still untouched",ha.SCHEDULE_STATE_PATH.read_bytes()==state_before)
        ha.BACKUP_PASSWORD_PATH.unlink()
        ha.PASSWORD_CLIENT_PATH.unlink()
        ha.LEGACY_PASSWORD_PATH.write_text("original-Test-HA")
        sess=Session("original-Test-HA")
        await ha.provision_backup_credentials(sess,config)
        check("Legacy password adopted exactly",sess.calls[0][1]["json"]["local_password"]=="original-Test-HA")
        check("Legacy password remains usable",ha.get_backup_password()=="original-Test-HA")
        ha.BACKUP_PASSWORD_PATH.unlink()
        ha.save_state({"scheduled_date":"2026-11-22","backup_type":"monthly","slug":"old-archive"},ha.SCHEDULE_STATE_PATH)
        check("Existing local archive without password fails closed",await fails(ha.provision_backup_credentials(sess,config)))
asyncio.run(test())
print(f"AGENT CREDENTIAL TESTS PASSED: {passed}")
