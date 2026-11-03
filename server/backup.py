"""Portable workspace archives with a consistent live SQLite snapshot."""
import hashlib
import io
from contextlib import closing
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import zipfile

RESTORE_UPLOAD_LIMIT = 256 * 1024 * 1024
RESTORE_EXPANDED_LIMIT = 512 * 1024 * 1024


def inspect_backup(payload, directory):
    """Validate the archive, extracting only data, never uploaded application code."""
    directory = Path(directory)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) > 20000 or len(names) != len(set(names)):
            raise ValueError('Backup contains duplicate or too many files.')
        if sum(entry.file_size for entry in entries) > RESTORE_EXPANDED_LIMIT:
            raise ValueError('Expanded backup exceeds 512 MB.')
        required = {'manifest.json', 'data/kiss.sqlite3', 'users.txt', 'config.toml'}
        if not required.issubset(names):
            raise ValueError('Choose a full KISS workspace backup ZIP.')
        if archive.getinfo('manifest.json').file_size > 4 * 1024 * 1024:
            raise ValueError('Backup manifest is too large.')
        manifest = json.loads(archive.read('manifest.json'))
        if not isinstance(manifest, dict) or manifest.get('format') != 1 or not isinstance(manifest.get('files'), dict):
            raise ValueError('Unsupported backup format.')
        if set(names) != set(manifest['files']) | {'manifest.json'}:
            raise ValueError('Backup file list does not match its manifest.')
        for name, expected in manifest['files'].items():
            digest = hashlib.sha256()
            with archive.open(name) as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError('Backup checksum failed. The archive is damaged or modified.')
        (directory / 'restore.sqlite3').write_bytes(archive.read('data/kiss.sqlite3'))
        users = archive.read('users.txt').decode().splitlines()
        import tomllib
        config = tomllib.loads(archive.read('config.toml').decode())
        names = {name.strip() for name in users if name.strip() and not name.lstrip().startswith('#')}
        if config.get('admin_username'):
            names.add(config['admin_username'])
        if any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) for name in names):
            raise ValueError('Backup contains invalid usernames.')
    path = directory / 'restore.sqlite3'
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as conn:
        conn.execute('PRAGMA trusted_schema=OFF')
        objects = conn.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if set(objects) != {('table', name) for name in ('records', 'blobs', 'sessions')}:
            raise ValueError('Backup has an unsupported database schema.')
        for table, columns in {'records': ['kind', 'id', 'body'], 'blobs': ['id', 'kind', 'mime', 'data'], 'sessions': ['token', 'username', 'expires']}.items():
            if [row[1] for row in conn.execute(f'PRAGMA table_info({table})')] != columns:
                raise ValueError('Backup has an unsupported database schema.')
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Backup database is damaged.')
        for id, body in conn.execute('SELECT id,body FROM records'):
            value = json.loads(body)
            if not isinstance(value, dict) or value.get('id') != id:
                raise ValueError('Backup contains invalid records.')
        counts = dict(conn.execute('SELECT kind,count(*) FROM records GROUP BY kind'))
        evidence = conn.execute('SELECT count(*) FROM blobs').fetchone()[0]
    return {'sha256': hashlib.sha256(payload).hexdigest(), 'created_at': manifest.get('created_at'),
            'counts': counts, 'evidence': evidence, 'users': sorted(names)}


def restore_records(conn, snapshot):
    """Copy validated data into the existing schema in the caller's transaction."""
    with closing(sqlite3.connect(Path(snapshot).as_uri() + '?mode=ro', uri=True)) as source:
        source.execute('PRAGMA trusted_schema=OFF')
        conn.execute('DELETE FROM records')
        conn.execute('DELETE FROM blobs')
        conn.execute('DELETE FROM sessions')
        for kind, id, body in source.execute('SELECT kind,id,body FROM records'):
            value = json.loads(body)
            status = value if kind == 'automation' else value.get('port_scan' if kind == 'hosts' else 'discovery', {})
            if status.get('status') in {'Queued', 'Running'}:
                status.update(status='Interrupted', message='Restored from backup. Run this job again.')
            conn.execute('INSERT INTO records VALUES (?,?,?)', (kind, id, json.dumps(value)))
        conn.executemany('INSERT INTO blobs VALUES (?,?,?,?)', source.execute('SELECT id,kind,mime,data FROM blobs'))

SOURCE_DIRS = ('src', 'server', 'scripts', 'tests', 'docs', 'dist')
SOURCE_FILES = ('package.json', 'package-lock.json', 'requirements.txt', 'requirements-dev.txt',
                'vite.config.js', 'playwright.config.js', 'index.html', 'README.md',
                'PRODUCT.md', 'DESIGN.md', 'config.example.toml', 'users.example.txt', '.gitignore')
RESTORE = '''# Restore KISS

This ZIP contains a live SQLite snapshot, application source, built frontend (if present),
users.txt, config.toml, dependency manifests, runtime settings, and the exporting browser's local state.
All shared hosts, findings, plaintext credentials, activity, sessions, images and scan evidence are inside data/kiss.sqlite3.

1. Extract into a NEW directory. Do not extract over a running workspace.
2. Install Python 3.11+ and Nmap. Automation presets also require NetExec (nxc);
   optional AD CS checks require Certipy. See scripts/dc_checks/README.md for tool setup.
   These external tools are not installed by requirements-backup.txt.
3. From this directory:

   unset KISS_DATA_DIR KISS_USERS_FILE KISS_CONFIG_FILE
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements-backup.txt

   If a pinned dependency is unavailable on your platform, use requirements.txt instead.
   If dist/index.html is absent, install Node 20.19+ or 22.12+, then run npm ci and npm run build.
   Start the restored app:

   .venv/bin/python -m uvicorn server.app:app --host 127.0.0.1 --port 8000
4. Open http://127.0.0.1:8000 and sign in with a username from users.txt or the configured admin.
   For team access, bind to your LAN/VPN IP. Review runtime-settings.json for the original overrides;
   apply suitable values to the new server. Data/users/config paths were normalized to this directory.
5. Running scans cannot be resumed from this archive. Restarted jobs become Interrupted; rerun them.

Browser drafts/theme/layout preferences are in browser-state.json. To restore those optional values,
open the restored app in the browser tab you want to use, open developer tools, and run:

   const picker = document.createElement('input');
   picker.type = 'file'; picker.accept = '.json';
   picker.onchange = async () => {
     const state = JSON.parse(await picker.files[0].text());
     for (const [key, value] of Object.entries(state.session || {}))
       if (key.startsWith('kiss:')) sessionStorage.setItem(key, value);
     for (const [key, value] of Object.entries(state.local || {}))
       if (key.startsWith('kiss:')) localStorage.setItem(key, value);
     location.reload();
   };
   picker.click();

Select browser-state.json. Draft keys are tied to usernames. This restores only the exporting
browser tab's drafts; other tabs or teammates' unsaved drafts were never available to the server.

The archive contains plaintext credentials and session data. Machine-specific virtual environments,
node_modules, Git/agent/cloud configuration, old backup copies, and unrelated external files are not included.
Dependencies are reinstalled using the included manifests. Network routes, VPNs, system packages and
external services must be configured on the new machine. Nothing is sent to an external backup service.

manifest.json lists SHA-256 checksums for each included file (except the manifest itself).
'''


def build_backup(root, data_dir, users_text, config_text, browser_state, directory, created_at):
    root, directory = Path(root), Path(directory)
    snapshot = directory / 'snapshot.sqlite3'
    with closing(sqlite3.connect((Path(data_dir) / "kiss.sqlite3").resolve().as_uri() + "?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination)
            if destination.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Backup database failed its integrity check.')
    archive = directory / 'kiss-backup.zip'
    manifest = {'format': 1, 'created_at': created_at, 'python': platform.python_version(), 'files': {}}
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zip:
        def add_bytes(name, data):
            zip.writestr(name, data)
            manifest['files'][name] = hashlib.sha256(data).hexdigest()
        def add_file(name, path):
            digest = hashlib.sha256()
            with path.open('rb') as source, zip.open(name, 'w', force_zip64=True) as target:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    target.write(chunk)
            manifest['files'][name] = digest.hexdigest()
        for name in SOURCE_FILES:
            path = root / name
            if path.is_file() and not path.is_symlink():
                add_file(name, path)
        for name in SOURCE_DIRS:
            folder = root / name
            if not folder.is_dir() or folder.is_symlink():
                continue
            for base, directories, files in os.walk(folder, followlinks=False):
                directories[:] = sorted(d for d in directories if d not in {'__pycache__', '.pytest_cache'} and not (Path(base) / d).is_symlink())
                for filename in sorted(files):
                    path = Path(base) / filename
                    if path.is_symlink() or path.suffix == '.pyc':
                        continue
                    add_file(path.relative_to(root).as_posix(), path)
        add_file('data/kiss.sqlite3', snapshot)
        add_bytes('users.txt', users_text.encode())
        add_bytes('config.toml', config_text.encode())
        add_bytes('browser-state.json', json.dumps(browser_state, indent=2).encode())
        settings = {key: os.environ[key] for key in ('KISS_SECURE_COOKIE', 'KISS_DISCOVERY_MAX_HOSTS', 'KISS_PORT_SCAN_TIMEOUT') if key in os.environ}
        add_bytes('runtime-settings.json', json.dumps(settings, indent=2).encode())
        # Runtime and transitive versions make a fresh install repeatable without bundling a platform-specific venv.
        pinned = sorted({f"{dist.metadata['Name']}=={dist.version}" for dist in importlib.metadata.distributions() if dist.metadata['Name']})
        add_bytes('requirements-backup.txt', ('\n'.join(pinned) + '\n').encode())
        add_bytes('RESTORE.md', RESTORE.encode())
        zip.writestr('manifest.json', json.dumps(manifest, indent=2))
    snapshot.unlink()
    return archive
