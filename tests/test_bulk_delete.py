import copy

import app
from test_engine import client, isolated


def create(client, address):
    return client.post('/api/servers', json={'name': address, 'host': address, 'username': 'root', 'passwords': ['fixture-only']}).json()['id']


def test_bulk_delete_removes_only_selected_profiles_and_preserves_history(client):
    a, b, c = [create(client, f'192.0.2.{n}') for n in (1, 2, 3)]
    app.PLANS[a] = {'id': 'fixture-plan'}
    app.PROBES[a] = {'fixture': True}
    app.JOBS['history'] = {'id': 'history', 'status': 'finished', 'servers': {a: {'name': 'fixture', 'status': 'updated'}}}
    history = copy.deepcopy(app.JOBS)
    response = client.post('/api/servers/delete-selected', json={'ids': [a, b, a]})
    assert response.status_code == 200 and response.json()['deleted'] == 2
    assert set(app.SERVERS) == {c} and set(app.CREDS) == {c}
    assert a not in app.PLANS and a not in app.PROBES
    assert app.JOBS == history


def test_busy_or_invalid_selection_never_partially_deletes(client):
    a, b = create(client, '192.0.2.1'), create(client, '192.0.2.2')
    app.ACTIVE.add(b)
    assert client.post('/api/servers/delete-selected', json={'ids': [a, b]}).status_code == 409
    assert set(app.SERVERS) == {a, b}
    app.ACTIVE.clear()
    assert client.post('/api/servers/delete-selected', json={'ids': [a, 'missing']}).status_code == 404
    assert set(app.SERVERS) == {a, b}


def test_bulk_delete_restores_memory_if_persistence_fails(client, monkeypatch):
    sid = create(client, '192.0.2.1')
    def fail(): raise OSError('fixture write failure')
    monkeypatch.setattr(app, 'save', fail)
    try:
        client.post('/api/servers/delete-selected', json={'ids': [sid]})
    except OSError:
        pass  # TestClient may propagate the failure after the safe HTTP handler.
    assert sid in app.SERVERS and sid in app.CREDS


def test_help_and_manual_guide_available(client):
    response = client.get('/help')
    assert response.status_code == 200 and 'پچ دستی' in response.text
    manual = client.get('/guides/manual-patching.md')
    assert manual.status_code == 200 and 'CVE-2026-109618' in manual.text and 'AlmaLinux' in manual.text
