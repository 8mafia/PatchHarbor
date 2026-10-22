import copy
import json
import threading
import time

import paramiko
import pytest
from fastapi.testclient import TestClient

import app
import engine


def inventory(distro="ubuntu", version="24.04", codename="noble"):
    return {"os": {"ID": distro, "VERSION_ID": version, "VERSION_CODENAME": codename},
            "packages": [{"name": "php8.3-cli" if distro != "almalinux" else "php-cli", "version": "8.3.6-0ubuntu0.24.04.12"}],
            "runtime": "PHP 8.3.6 (cli)", "services": ["php8.3-fpm.service"], "containers": [], "disk": "", "docker_error": None, "notice": ""}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for mapping in (app.SERVERS, app.CREDS, app.PLANS, app.JOBS, app.PROBES):
        mapping.clear()
    app.ACTIVE.clear()
    monkeypatch.setattr(app, "DATA", tmp_path)
    yield


@pytest.fixture
def client():
    with TestClient(app.app) as c:
        c.headers["x-patch-token"] = app.TOKEN
        yield c


def add(client):
    r = client.post("/api/servers", json={"name": "test", "host": "192.0.2.1", "port": 2222, "username": "ops", "passwords": ["SECRET-A", "SECRET-B"], "sudo_password": "SECRET-SUDO"})
    assert r.status_code == 200
    sid = r.json()["id"]
    app.SERVERS[sid]["trusted"] = {"fingerprint": "SHA256:example"}
    app.SERVERS[sid]["inventory"] = inventory()
    return sid


def test_api_requires_token_and_rejects_cross_origin(client):
    assert client.get("/api/state", headers={"x-patch-token": "wrong"}).status_code == 403
    assert client.get("/api/state", headers={"origin": "https://evil.example"}).status_code == 403
    assert client.get("/api/state").status_code == 200
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400


def test_no_secrets_in_state_disk_or_validation(client):
    add(client)
    content = client.get("/api/state").text + (app.DATA / "servers.json").read_text()
    assert "SECRET" not in content
    r = client.post("/api/servers", json={"name": "x", "host": "example", "username": "root", "port": 70000, "passwords": ["SECRET-VALIDATION"]})
    assert r.status_code == 422 and "SECRET" not in r.text


def test_duplicate_endpoint_blocked(client):
    add(client)
    r = client.post("/api/servers", json={"name": "alias", "host": "192.0.2.1", "port": 2222, "username": "root", "passwords": ["x"]})
    assert r.status_code == 409


def test_host_identity_cannot_change():
    key = paramiko.RSAKey.generate(2048)
    with pytest.raises(RuntimeError):
        engine.PinnedKey("SHA256:different").missing_host_key(None, "host", key)
    engine.PinnedKey(engine.fingerprint(key)).missing_host_key(None, "host", key)


def test_trust_requires_observed_fingerprint(client, monkeypatch):
    sid = add(client)
    app.SERVERS[sid]["trusted"] = None
    assert app.credential(app.SERVERS[sid]) is app.CREDS[sid]
    observed = {"type": "ssh-ed25519", "key": "fake-key", "fingerprint": "SHA256:actual"}
    monkeypatch.setattr(engine, "probe", lambda *a: observed)
    assert client.post(f"/api/servers/{sid}/probe").status_code == 200
    assert client.post(f"/api/servers/{sid}/trust", json={"fingerprint": "SHA256:wrong"}).status_code == 409
    assert client.post(f"/api/servers/{sid}/trust", json={"fingerprint": "SHA256:actual"}).status_code == 200


@pytest.mark.parametrize("distro,version,codename", [("ubuntu", "24.04", "noble"), ("debian", "13", "trixie"), ("almalinux", "9.6", "")])
def test_plans_preserve_security_and_original_repos(distro, version, codename):
    p = engine.make_plan({}, inventory(distro, version, codename), {"mode": "php", "official_fallback": True})
    command = "\n".join(s["command"] for s in p["steps"] + p["fallback"])
    assert p["fallback"]
    for unsafe in ("--allow-unauthenticated", "--nogpgcheck", "--allowerasing", "dist-upgrade", "sed -i", "rm -rf", "reboot"):
        assert unsafe not in command
    if distro == "almalinux":
        assert "gpgcheck=1" in command and "'$" not in command
        assert "repo.almalinux.org/almalinux/$releasever" in command
    else:
        assert "--no-remove" in command and "signed-by=" in command


def test_custom_alma_parallel_php_has_no_official_fallback():
    i = inventory("almalinux", "9", "")
    i["packages"] = [{"name": "php83-php-cli", "version": "8.3.20"}]
    assert not engine.make_plan({}, i, {"mode": "php", "official_fallback": True})["fallback"]


def test_debian_candidate_patch_check_triggers_reviewed_official_path():
    i = inventory("debian", "13", "trixie")
    i["packages"] = [{"name": "php8.4-cli", "version": "8.4.24-1~deb13u1"}]
    p = engine.make_plan({}, i, {"mode": "php", "official_fallback": True})
    assert any("8.4.27-1~deb13u1" in s["command"] and "PATCH_MISSING" in s["command"] for s in p["steps"])
    assert "security.debian.org" in p["fallback"][0]["command"]


@pytest.mark.parametrize("raw,kind", [("NO_PUBKEY", "signature"), ("Could not get lock", "lock"), ("No space left on device", "disk"), ("Temporary failure resolving", "dns"), ("SSL certificate verify failed", "tls"), ("PATCH_MISSING", "mirror"), ("Unmet dependencies", "dependency")])
def test_error_diagnosis(raw, kind):
    assert engine.classify(raw)["kind"] == kind


def test_compose_validation_and_shell_quoting():
    with pytest.raises(ValueError):
        engine.make_plan({}, inventory(), {"mode": "compose", "compose_dir": "/opt/app", "compose_service": "app;reboot"})
    p = engine.make_plan({}, inventory(), {"mode": "compose", "compose_dir": "/opt/app'; touch /tmp/oops #", "compose_service": "app"})
    assert "--no-deps --no-build --wait" in p["steps"][1]["command"]
    assert engine.q("/opt/app'; touch /tmp/oops #") in p["steps"][0]["command"]


@pytest.mark.parametrize("version,status", [("8.3.36", "fixed-upstream"), ("8.3.35", "needs-vendor-evidence"), ("8.1.2", "unknown"), ("junk", "unknown")])
def test_version_evidence(version, status):
    assert engine.upstream_status(version) == status


class FakeRemote:
    commands = []
    fail_mirror = False
    def __init__(self, *args): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def run(self, command, *args, **kwargs):
        self.commands.append(command)
        if self.fail_mirror and "APT::Update::Error-Mode=any update" in command and "PATCHDIR" not in command:
            return engine.Result(100, "Failed to fetch: 404")
        return engine.Result(0, "ok")


def wait_job(job):
    deadline = time.time() + 5
    while job["status"] != "finished" and time.time() < deadline:
        time.sleep(.01)
    assert job["status"] == "finished"


def test_job_single_use_busy_guard_fallback_and_redaction(client, monkeypatch):
    sid = add(client)
    FakeRemote.commands = []
    FakeRemote.fail_mirror = True
    monkeypatch.setattr(engine, "Remote", FakeRemote)
    monkeypatch.setattr(engine, "inspect", lambda remote: inventory())
    p = client.post(f"/api/servers/{sid}/plan", json={"mode": "php", "official_fallback": True}).json()
    assert client.post("/api/jobs", json={"plans": {sid: p["id"]}}).status_code == 400
    r = client.post("/api/jobs", json={"plans": {sid: p["id"]}, "backup_confirmed": True})
    assert r.status_code == 200
    job = app.JOBS[r.json()["id"]]
    wait_job(job)
    assert job["servers"][sid]["status"] == "updated"
    assert any("PATCHDIR" in c for c in FakeRemote.commands)
    # No normal-repository install after the isolated fallback already installed.
    assert not any("--only-upgrade -y install" in c and "PATCHDIR" not in c for c in FakeRemote.commands)
    assert client.post("/api/jobs", json={"plans": {sid: p["id"]}, "backup_confirmed": True}).status_code == 409
    assert "SECRET" not in client.get("/api/state").text
    assert not app.ACTIVE


def test_stale_inventory_prevents_all_mutations(client, monkeypatch):
    sid = add(client)
    FakeRemote.commands = []
    monkeypatch.setattr(engine, "Remote", FakeRemote)
    altered = inventory()
    altered["packages"][0]["version"] = "changed"
    monkeypatch.setattr(engine, "inspect", lambda r: altered)
    p = client.post(f"/api/servers/{sid}/plan", json={}).json()
    r = client.post("/api/jobs", json={"plans": {sid: p["id"]}, "backup_confirmed": True})
    job = app.JOBS[r.json()["id"]]
    wait_job(job)
    assert job["servers"][sid]["status"] == "failed"
    assert not FakeRemote.commands


def test_parallel_limit_and_one_job_per_endpoint(client, monkeypatch):
    active, peak = 0, 0
    lock = threading.Lock()
    def work(job, sid, plan, server, creds):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(.08)
        with lock:
            active -= 1
        app.ACTIVE.discard(sid)
        job["servers"][sid]["status"] = "updated-needs-verification"
    monkeypatch.setattr(app, "execute_one", work)
    plans = {}
    for n in range(5):
        sid = client.post("/api/servers", json={"name": str(n), "host": f"192.0.2.{n+10}", "username": "root", "passwords": ["x"]}).json()["id"]
        app.SERVERS[sid]["trusted"] = {"fingerprint": "test"}
        app.SERVERS[sid]["inventory"] = inventory()
        plans[sid] = client.post(f"/api/servers/{sid}/plan", json={}).json()["id"]
    r = client.post("/api/jobs", json={"plans": plans, "parallel": 2, "backup_confirmed": True})
    assert r.status_code == 200
    sid = next(iter(plans))
    assert client.delete(f"/api/servers/{sid}").status_code == 409
    wait_job(app.JOBS[r.json()["id"]])
    assert peak == 2


def test_successful_password_is_tried_first_next_time(monkeypatch):
    attempts = []
    class FakeClient:
        def set_missing_host_key_policy(self, policy): pass
        def close(self): pass
        def connect(self, *a, **kw):
            attempts.append(kw["password"])
            if kw["password"] != "correct": raise paramiko.AuthenticationException()
    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    server = {"host": "example", "port": 2222, "username": "ops", "trusted": {"fingerprint": "fake"}}
    creds = {"passwords": ["wrong", "correct"], "sudo_password": ""}
    with engine.Remote(server, creds): pass
    with engine.Remote(server, creds): pass
    assert attempts == ["wrong", "correct", "correct"]


def test_health_failure_blocks_mutation(client, monkeypatch):
    sid = add(client)
    app.SERVERS[sid]["health_url"] = "https://example.com/health"
    class BadHealth(FakeRemote):
        def run(self, command, *a, **kw):
            assert command.startswith("curl ")
            return engine.Result(22, "unhealthy")
    monkeypatch.setattr(engine, "Remote", BadHealth)
    monkeypatch.setattr(engine, "inspect", lambda r: inventory())
    p = client.post(f"/api/servers/{sid}/plan", json={}).json()
    r = client.post("/api/jobs", json={"plans": {sid:p["id"]}, "backup_confirmed": True})
    job = app.JOBS[r.json()["id"]]
    wait_job(job)
    assert job["servers"][sid]["status"] == "failed"
