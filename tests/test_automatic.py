import copy

import paramiko

import app
import engine
from test_engine import client, isolated, inventory, wait_job


def test_auto_key_accepts_changed_fingerprint():
    server = {"trusted": {"fingerprint": "old"}}
    key = paramiko.RSAKey.generate(2048)
    engine.AutomaticKey(server).missing_host_key(None, "fixture", key)
    assert server["trusted"]["fingerprint"] == engine.fingerprint(key)


def test_second_username_and_password_are_promoted(monkeypatch):
    attempts = []
    class FakeClient:
        def set_missing_host_key_policy(self, p): pass
        def close(self): pass
        def connect(self, *a, **kw):
            attempts.append((kw["username"], kw["password"]))
            if attempts[-1] != ("rooot", "right"):
                raise paramiko.AuthenticationException()
    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    server = {"host": "fixture", "port": 22, "username": "root", "username2": "rooot"}
    creds = {"passwords": ["wrong", "right"], "sudo_password": ""}
    with engine.Remote(server, creds): pass
    with engine.Remote(server, creds): pass
    assert attempts == [("root", "wrong"), ("root", "right"), ("rooot", "wrong"), ("rooot", "right"), ("rooot", "right")]
    assert server["authenticated_username"] == "rooot"


def test_plain_yes_no_summary_handles_vendor_backport_and_remi():
    remi = {"packages": [{"name": "php-cli", "version": "8.4.12-1.el9.remi", "status": "needs-vendor-evidence"}], "runtime_versions": ["8.4.12"], "containers": []}
    result = engine.assessment_summary(remi)
    assert result["update_required"] is True
    assert result["title"] == "آپدیت لازم است" and result["targets"] == ["8.4.27"]
    remi["packages"][0].update(version="8.4.27-1.el9.remi", status="fixed-upstream")
    remi["runtime_versions"] = ["8.4.27"]
    assert engine.assessment_summary(remi)["update_required"] is False
    ubuntu = {"packages": [{"name": "php8.3-cli", "version": "8.3.6-0ubuntu0.24.04.13", "status": "fixed-ubuntu-baseline"}], "runtime_versions": ["8.3.6"], "containers": []}
    assert engine.assessment_summary(ubuntu)["update_required"] is False


class Remote:
    commands = []
    def __init__(self, server, credentials):
        self.server = server
        self.updated = False
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def run(self, command, *args, **kwargs):
        self.commands.append(command)
        if "dnf " in command and "-y upgrade" in command:
            self.updated = True
        return engine.Result(0, "ok")


def config(host):
    return {"name": host, "host": host, "port": 2222, "username": "root", "username2": "rooot", "passwords": ["fake-password"]}


def remi_inventory(version):
    data = inventory("almalinux", "9", "")
    data["packages"] = [{"name": "php-cli", "version": version + "-1.el9.remi"}]
    data["runtime"] = "PHP " + version + " (cli)"
    data["services"] = ["php-fpm.service"]
    return data


def test_batch_registers_checks_updates_only_needed_and_continues_after_error(client, monkeypatch):
    Remote.commands = []
    monkeypatch.setattr(engine, "Remote", Remote)
    def inspect(remote):
        if remote.server["host"] == "192.0.2.3":
            raise RuntimeError("fixture connection failed")
        if remote.server["host"] == "192.0.2.2" and not remote.updated:
            return remi_inventory("8.4.12")
        return remi_inventory("8.4.27")
    monkeypatch.setattr(engine, "inspect", inspect)
    r = client.post("/api/batch", json={"servers": [config(f"192.0.2.{n}") for n in (1, 2, 3, 4)]})
    assert r.status_code == 200
    job = app.JOBS[r.json()["id"]]
    wait_job(job)
    assert [s["status"] for s in job["servers"].values()] == ["up-to-date", "updated", "failed", "up-to-date"]
    assert sum("-y upgrade" in c for c in Remote.commands) == 1
    assert len(app.SERVERS) == 4 and not app.ACTIVE
    assert "fake-password" not in client.get("/api/state").text


def test_duplicate_batch_rejected_before_registration(client):
    r = client.post("/api/batch", json={"servers": [config("192.0.2.1"), config("192.0.2.1")]})
    assert r.status_code == 400 and not app.SERVERS


def test_failed_docker_discovery_never_yields_ok():
    a = {"packages": [{"name": "php-cli", "version": "8.4.27", "status": "fixed-upstream"}], "runtime_versions": ["8.4.27"], "containers": [], "discovery_errors": ["Docker access denied"]}
    assert engine.assessment_summary(a)["update_required"] is True


def test_batch_keeps_distinct_per_endpoint_passwords_and_replaces_explicit_credentials(client, monkeypatch):
    monkeypatch.setattr(app, "run_batch", lambda job, items: None)
    first, second = config("192.0.2.1"), config("192.0.2.2")
    first["passwords"], second["passwords"] = ["first-only"], ["second-only"]
    r = client.post("/api/batch", json={"servers": [first, second]})
    assert r.status_code == 200
    ids = r.json()["server_ids"]
    assert app.CREDS[ids[0]]["passwords"] == ["first-only"]
    assert app.CREDS[ids[1]]["passwords"] == ["second-only"]
    app.ACTIVE.clear()
    first["passwords"] = ["changed-only"]
    r = client.post("/api/batch", json={"servers": [first]})
    assert r.status_code == 200 and len(app.SERVERS) == 2
    assert app.CREDS[ids[0]]["passwords"] == ["changed-only"]


def test_auto_compose_uses_original_project_and_reports_pinned_old_image(client, monkeypatch):
    Remote.commands = []
    monkeypatch.setattr(engine, "Remote", Remote)
    data = remi_inventory("8.4.27")
    data["containers"] = [{"name": "app", "php": "8.4.12", "status": "needs-vendor-evidence", "compose_dir": "/srv/project", "compose_service": "web", "compose_project": "original-project", "compose_files": ["/srv/project/production.yaml"]}]
    monkeypatch.setattr(engine, "inspect", lambda r: copy.deepcopy(data))
    r = client.post("/api/batch", json={"servers": [config("192.0.2.1")]})
    job = app.JOBS[r.json()["id"]]
    wait_job(job)
    item = next(iter(job["servers"].values()))
    assert item["status"] == "updated-needs-verification"
    assert any("-p original-project -f /srv/project/production.yaml up -d --no-deps" in c for c in Remote.commands)
    assert not any("-y upgrade" in c for c in Remote.commands)
