import copy
import socket

import paramiko
import pytest
from pydantic import ValidationError

import app
import engine
import reporting
from test_engine import client, isolated


@pytest.mark.parametrize("message,phase,kind", [("[Errno None] Unable to connect to port 22 on 192.0.2.1", "connection", "ssh-unreachable"), ("timed out", "connection", "ssh-unreachable"), ("rooot is not in the sudoers file.", "backup", "sudo"), ("SSH_AUTH_FAILED", "connection", "ssh-auth"), ("مهلت SSH تمام شد", "install", "command-timeout")])
def test_actionable_failure_classification(message, phase, kind):
    result = engine.classify(message, phase)
    assert result["kind"] == kind
    assert result["title"] and result["advice"] and result["phase"]


def test_ubuntu_meta_package_does_not_override_real_fixed_core():
    assessment = {"packages": [{"name": "php-common", "version": "2:92ubuntu1", "status": "unknown"}, {"name": "php8.1-cli", "version": "8.1.2-1ubuntu2.28", "status": "fixed-ubuntu-baseline"}], "runtime_versions": ["8.1.2"], "containers": []}
    assert engine.assessment_summary(assessment)["update_required"] is False
    assessment["packages"] = [{"name": "php-common", "version": "8.4.12-1.el9.remi", "status": "needs-vendor-evidence"}]
    assert engine.assessment_summary(assessment)["update_required"] is True


def test_no_php_does_not_claim_update_needed_or_safe():
    summary = engine.assessment_summary({"packages": [], "runtime_versions": [], "containers": []})
    assert summary["update_required"] is None
    assert "PHP" in summary["title"] and "شناسایی نشد" in summary["title"]


def test_historical_review_preserves_original_status_and_input():
    state = {"servers": [{"id": "a", "host": "192.0.2.1", "port": 22}], "jobs": [{"status": "finished", "servers": {"a": {"name": "fixture", "status": "needs-configuration", "assessment": {"packages": [], "runtime_versions": [], "containers": []}, "events": []}, "b": {"name": "fixture-error", "status": "failed", "events": [{"code": 1, "output": "timed out"}]}}}]}
    original = copy.deepcopy(state)
    result = reporting.review_state(state)
    entries = result["jobs"][0]["servers"]
    assert entries["a"]["status"] == "php-not-detected"
    assert entries["a"]["reported_status"] == "needs-configuration"
    assert entries["b"]["diagnosis"]["kind"] == "ssh-unreachable"
    assert state == original


def test_four_ports_fallback_and_cached_success(monkeypatch):
    attempts = []
    class FakeClient:
        def set_missing_host_key_policy(self, p): pass
        def close(self): pass
        def connect(self, host, **kwargs):
            port, user, password = kwargs["port"], kwargs["username"], kwargs["password"]
            attempts.append((port, user, password))
            if port == 22: raise ConnectionRefusedError("refused")
            if port == 2200: raise socket.timeout("timed out")
            if (user, password) != ("rooot", "right"): raise paramiko.AuthenticationException()
    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    server = {"host": "192.0.2.1", "port": 22, "ports": [22, 2200, 2222, 2022], "username": "root", "username2": "rooot"}
    creds = {"passwords": ["wrong", "right"]}
    with engine.Remote(server, creds): pass
    first_count = len(attempts)
    assert sum(x[0] == 22 for x in attempts) == 1
    assert sum(x[0] == 2200 for x in attempts) == 1
    assert not any(x[0] == 2022 for x in attempts)
    assert server["connected_port"] == 2222
    with engine.Remote(server, creds): pass
    assert len(attempts) == first_count + 1 and attempts[-1] == (2222, "rooot", "right")


def test_ports_validation():
    config = {"name": "fixture", "host": "192.0.2.1", "username": "root", "passwords": ["fake"]}
    assert app.ServerInput(**config, ports=[2022, 22]).port == 2022
    for ports in ([1, 2, 3, 4, 5], [0], [65536]):
        with pytest.raises(ValidationError): app.ServerInput(**config, ports=ports)


def test_can_correct_existing_port_without_duplicate_server(client):
    body = {"name": "fixture", "host": "192.0.2.1", "username": "root", "passwords": ["fake"]}
    sid = client.post("/api/servers", json=body).json()["id"]
    r = client.put(f"/api/servers/{sid}/credentials", json={**body, "ports": [2222, 2200]})
    assert r.status_code == 200
    assert len(app.SERVERS) == 1 and app.SERVERS[sid]["ports"] == [2222, 2200]


def test_bulk_reuses_record_and_applies_new_candidate_ports(client, monkeypatch):
    monkeypatch.setattr(app, "run_batch", lambda *args: None)
    body = {"name": "fixture", "host": "192.0.2.1", "username": "root", "passwords": ["fake"]}
    sid = client.post("/api/servers", json=body).json()["id"]
    result = client.post("/api/batch", json={"servers": [{**body, "ports": [2222, 22, 2200, 2022]}]})
    assert result.status_code == 200
    assert result.json()["server_ids"] == [sid]
    assert app.SERVERS[sid]["ports"] == [2222, 22, 2200, 2022]
