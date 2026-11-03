import asyncio
import hashlib
import importlib
import io
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from server.app import create_app
from server.backup import build_backup, inspect_backup


def test_archive_restores_complete_database_and_includes_app_files(tmp_path):
    root, data, output = (tmp_path / name for name in ('app', 'data', 'output'))
    for directory in (root, data, output, root / 'src', root / 'dist', root / 'server'):
        directory.mkdir(parents=True, exist_ok=True)
    (root / 'src/App.jsx').write_text('application source')
    (root / 'dist/index.html').write_text('built application')
    (root / 'package-lock.json').write_text('{}')
    (root / 'server/__pycache__').mkdir()
    (root / 'server/__pycache__/cached.pyc').write_bytes(b'cache')
    external = tmp_path / 'external-secret'
    external.write_text('not project data')
    (root / 'src/unrelated').symlink_to(external)
    users = root / 'users.txt'
    users.write_text('sohee\nalex\n')
    config = root / 'config.toml'
    config.write_text('admin_username = "sohee"\n')
    create_app(data, users, config)
    with sqlite3.connect(data / 'kiss.sqlite3') as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        for kind in ('hosts', 'findings', 'credentials', 'activity', 'networks', 'scans', 'automation'):
            conn.execute('INSERT INTO records VALUES (?, ?, ?)', (kind, kind, json.dumps({'id': kind, 'secret': 'full contents'})))
        conn.execute('INSERT INTO blobs VALUES (?, ?, ?, ?)', ('image', 'image', 'image/png', b'image bytes'))
        conn.execute('INSERT INTO blobs VALUES (?, ?, ?, ?)', ('scan', 'scan', 'application/xml', b'<nmaprun/>'))
        conn.execute('INSERT INTO blobs VALUES (?, ?, ?, ?)', ('automation', 'automation', 'application/zip', b'automation evidence'))
        conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', ('session', 'sohee', 9999999999))
        conn.commit()
        archive = build_backup(root, data, users.read_text(), config.read_text(), {'session': {'kiss:sohee:finding:new': 'draft'}, 'local': {'kiss:theme': 'dark'}}, output, '2026-11-01T00:00:00Z')
    restored = tmp_path / 'restored'
    with zipfile.ZipFile(archive) as zip:
        names = zip.namelist()
        assert 'src/App.jsx' in names and 'dist/index.html' in names
        assert 'src/unrelated' not in names
        assert not any('__pycache__' in name or name.endswith(('-wal', '-shm')) for name in names)
        manifest = json.loads(zip.read('manifest.json'))
        for name, digest in manifest['files'].items():
            assert hashlib.sha256(zip.read(name)).hexdigest() == digest
        assert json.loads(zip.read('browser-state.json'))['session']['kiss:sohee:finding:new'] == 'draft'
        assert 'pip install' in zip.read('RESTORE.md').decode()
        zip.extractall(restored)
    with sqlite3.connect(restored / 'data/kiss.sqlite3') as conn:
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert conn.execute('SELECT count(*) FROM records').fetchone()[0] == 7
        assert conn.execute('SELECT count(*) FROM blobs').fetchone()[0] == 3
        assert conn.execute("SELECT data FROM blobs WHERE id='automation'").fetchone()[0] == b'automation evidence'
        assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 1
    app = create_app(restored / 'data', restored / 'users.txt', restored / 'config.toml')
    state = next(r.endpoint for r in app.routes if r.path == '/api/state')('sohee')
    assert state['is_admin'] and state['credentials'][0]['secret'] == 'full contents'


def test_backup_endpoint_checks_admin_and_cleans_up(tmp_path, monkeypatch):
    users, config = tmp_path / 'users.txt', tmp_path / 'config.toml'
    users.write_text('alex\n')
    config.write_text('admin_username = "sohee"')
    app = create_app(tmp_path / 'data', users, config)
    endpoint = next(r.endpoint for r in app.routes if r.path == '/api/admin/backup')
    def request(value):
        async def receive():
            return {'type': 'http.request', 'body': json.dumps(value).encode(), 'more_body': False}
        return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []}, receive)
    # Test without thread signaling, which this environment restricts.
    async def inline(function):
        return function()
    monkeypatch.setattr(importlib.import_module('server.app').asyncio, 'to_thread', inline)
    with pytest.raises(HTTPException) as denied:
        asyncio.run(endpoint(request({}), 'alex'))
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as invalid:
        asyncio.run(endpoint(request({'session': {'unrelated': 'value'}}), 'sohee'))
    assert invalid.value.status_code == 422
    response = asyncio.run(endpoint(request({'session': {}, 'local': {}}), 'sohee'))
    assert response.media_type == 'application/zip'
    path = Path(response.path)
    assert path.exists()
    with zipfile.ZipFile(path) as zip:
        assert 'server/app.py' in zip.namelist()
        assert 'RESTORE.md' in zip.namelist()
    response.background.func()
    assert not path.exists()


@pytest.fixture
def workspace_zip(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'users.txt').write_text('alex\n')
    (root / 'config.toml').write_text('admin_username = "oldadmin"')
    create_app(root / 'data', root / 'users.txt', root / 'config.toml')
    with sqlite3.connect(root / 'data/kiss.sqlite3') as conn:
        conn.execute('INSERT INTO records VALUES (?,?,?)', ('automation', 'run', json.dumps({'id': 'run', 'status': 'Running'})))
        conn.execute('INSERT INTO blobs VALUES (?,?,?,?)', ('evidence', 'automation', 'application/zip', b'retained evidence'))
        conn.execute('INSERT INTO sessions VALUES (?,?,?)', ('old-session', 'alex', 9999999999))
    return build_backup(root, root / 'data', 'alex\n', (root / 'config.toml').read_text(), {}, root, '2026-11-02T00:00:00Z').read_bytes()


def test_restore_preview_confirmation_and_recovery(tmp_path, workspace_zip, monkeypatch):
    root = tmp_path / 'destination'
    root.mkdir()
    users, config = root / 'users.txt', root / 'config.toml'
    users.write_text('currentuser\n')
    config.write_text('admin_username = "currentadmin"')
    app = create_app(root / 'data', users, config)
    with sqlite3.connect(root / 'data/kiss.sqlite3') as conn:
        conn.execute('INSERT INTO records VALUES (?,?,?)', ('hosts', 'existing', '{"id":"existing"}'))
    endpoint = next(r.endpoint for r in app.routes if r.path == '/api/admin/restore')
    def request(confirm=None):
        async def receive():
            return {'type': 'http.request', 'body': workspace_zip, 'more_body': False}
        headers = [(b'x-kiss-restore-confirm', confirm.encode())] if confirm else []
        return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': headers}, receive)
    with pytest.raises(HTTPException) as denied:
        asyncio.run(endpoint(request(), 'currentuser'))
    assert denied.value.status_code == 403
    preview = asyncio.run(endpoint(request(), 'currentadmin'))
    assert preview['counts'] == {'automation': 1}
    assert users.read_text() == 'currentuser\n'
    with pytest.raises(HTTPException) as mismatch:
        asyncio.run(endpoint(request('wrong-digest'), 'currentadmin'))
    assert mismatch.value.status_code == 409
    # A failed import rolls back all shared records and keeps the old allowlist.
    module = importlib.import_module('server.app')
    actual_restore = module.restore_records
    def fail_after_delete(conn, snapshot):
        conn.execute('DELETE FROM records')
        raise sqlite3.OperationalError('simulated failure')
    monkeypatch.setattr(module, 'restore_records', fail_after_delete)
    with pytest.raises(HTTPException) as failure:
        asyncio.run(endpoint(request(preview['sha256']), 'currentadmin'))
    assert failure.value.status_code == 503
    assert users.read_text() == 'currentuser\n'
    with sqlite3.connect(root / 'data/kiss.sqlite3') as conn:
        assert conn.execute('SELECT id FROM records').fetchone()[0] == 'existing'
    monkeypatch.setattr(module, 'restore_records', actual_restore)
    result = asyncio.run(endpoint(request(preview['sha256']), 'currentadmin'))
    assert set(users.read_text().splitlines()) == {'alex', 'oldadmin', 'currentadmin'}
    assert config.read_text() == 'admin_username = "currentadmin"'
    with sqlite3.connect(root / 'data/kiss.sqlite3') as conn:
        assert json.loads(conn.execute('SELECT body FROM records').fetchone()[0])['status'] == 'Interrupted'
        assert conn.execute('SELECT data FROM blobs').fetchone()[0] == b'retained evidence'
        assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0
    with zipfile.ZipFile(root / 'data' / result['recovery_file']) as archive:
        assert archive.read('users.txt') == b'currentuser\n'


def test_restore_rejects_corrupted_archive(tmp_path, workspace_zip):
    target = tmp_path / 'validation'
    target.mkdir()
    with pytest.raises(zipfile.BadZipFile):
        inspect_backup(b'not a zip', target)
    corrupted = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(workspace_zip)) as source, zipfile.ZipFile(corrupted, 'w') as output:
        for name in source.namelist():
            output.writestr(name, b'changed' if name == 'users.txt' else source.read(name))
    with pytest.raises(ValueError, match='checksum'):
        inspect_backup(corrupted.getvalue(), target)
