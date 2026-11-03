import sqlite3

import pytest
from fastapi import HTTPException, Response

from server.app import Login, create_app


def setup(tmp_path, admin='sohee'):
    config = tmp_path / 'config.toml'
    config.write_text(f'admin_username = "{admin}"\n')
    users = tmp_path / 'users.txt'
    users.write_text('# Team\nalex\n')
    def routes():
        app = create_app(tmp_path / 'data', users, config)
        return {(route.path, method): route.endpoint for route in app.routes for method in getattr(route, 'methods', [])}
    return routes, users


def test_admin_add_remove_persists_and_revokes_sessions(tmp_path):
    routes, users = setup(tmp_path)
    endpoints = routes()
    assert endpoints['/api/state', 'GET']('sohee')['is_admin']
    assert not endpoints['/api/state', 'GET']('alex')['is_admin']
    endpoints['/api/admin/users', 'POST'](Login(username='jane'), 'sohee')
    assert '# Team' in users.read_text()
    assert 'jane' in routes()['/api/state', 'GET']('sohee')['users']
    response = Response()
    endpoints['/api/login', 'POST'](Login(username='jane'), response)
    with sqlite3.connect(tmp_path / 'data/kiss.sqlite3') as conn:
        assert conn.execute("SELECT count(*) FROM sessions WHERE username='jane'").fetchone()[0] == 1
    endpoints['/api/admin/users/{name}', 'DELETE']('jane', 'sohee')
    with sqlite3.connect(tmp_path / 'data/kiss.sqlite3') as conn:
        assert conn.execute("SELECT count(*) FROM sessions WHERE username='jane'").fetchone()[0] == 0
    with pytest.raises(HTTPException) as denied:
        endpoints['/api/login', 'POST'](Login(username='jane'), Response())
    assert denied.value.status_code == 403
    assert 'jane' not in routes()['/api/state', 'GET']('sohee')['users']


def test_nonadmin_and_protected_admin(tmp_path):
    routes, users = setup(tmp_path)
    endpoints = routes()
    original = users.read_text()
    with pytest.raises(HTTPException) as denied:
        endpoints['/api/admin/users', 'POST'](Login(username='jane'), 'alex')
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as denied:
        endpoints['/api/admin/users/{name}', 'DELETE']('alex', 'alex')
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as protected:
        endpoints['/api/admin/users/{name}', 'DELETE']('sohee', 'sohee')
    assert protected.value.status_code == 409
    assert users.read_text() == original


def test_duplicate_and_invalid_usernames_leave_file_unchanged(tmp_path):
    routes, users = setup(tmp_path)
    endpoints = routes()
    original = users.read_text()
    for name in ('alex', 'sohee', 'jane\nadmin', '../admin', '#comment'):
        with pytest.raises(HTTPException):
            endpoints['/api/admin/users', 'POST'](Login(username=name), 'sohee')
    assert users.read_text() == original


def test_disabled_admin_has_no_management_access(tmp_path):
    routes, _ = setup(tmp_path, '')
    endpoints = routes()
    assert not endpoints['/api/state', 'GET']('alex')['is_admin']
    with pytest.raises(HTTPException):
        endpoints['/api/admin/users', 'POST'](Login(username='jane'), 'alex')
