"""DC collector jobs and retained evidence. All commands are fixed by the collector."""
import argparse
from dataclasses import asdict
import re
import asyncio
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tempfile
import time
import zipfile
from typing import Literal

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from scripts.dc_checks.dc_checks import host as validate_host
from scripts.evidence import scan_text
from scripts.dc_checks.lab_catalog import CHECKS as LAB_CHECKS

ROOT = Path(__file__).resolve().parent.parent
TOOLS = {'dns': ['dig'], 'services': ['nmap'], 'smb': ['nmap', 'smbclient', 'rpcclient'],
         'ldap': ['ldapsearch'], 'tls': ['nmap']}
ACTIVE = {'Queued', 'Running'}


class RunChecks(BaseModel):
    host_id: str
    collector: Literal['directory', 'lab'] = 'directory'
    preset: Literal['anonymous', 'domain'] | None = None
    checks: list[str] = Field(default_factory=list, max_length=40)
    listener: str = Field(default='', max_length=253)
    adcs: bool = False
    adcs_ca_endpoints: bool = False
    domain: str = Field(min_length=3, max_length=253)
    modules: list[Literal['dns', 'services', 'smb', 'ldap', 'tls']] = Field(default_factory=list, max_length=5)
    ldap_host: str = Field(default='', max_length=253)
    ldap_transport: Literal['both', 'ldaps', 'ldap'] = 'both'
    bind_user: str = Field(default='', max_length=500)
    password: str = Field(default='', max_length=10000, repr=False)
    guest: bool = False
    ms17_010: bool = False
    plan: bool = False
    timeout: int = Field(default=180, ge=10, le=600)


def apply_preset(payload):
    if not payload.preset:
        return payload
    authenticated = payload.preset == 'domain'
    if authenticated and not payload.bind_user.strip():
        raise HTTPException(422, 'Enter a domain account for this preset.')
    return payload.model_copy(update={
        'collector': 'lab',
        'checks': [check.name for check in LAB_CHECKS if check.authenticated == authenticated] + ([] if authenticated else ['ms17-010']),
        'modules': [],
        'bind_user': payload.bind_user.strip() if authenticated else '',
        'password': payload.password if authenticated else '',
        'adcs': payload.adcs if authenticated else False,
        'adcs_ca_endpoints': payload.adcs_ca_endpoints if authenticated and payload.adcs else False,
        'guest': False, 'ms17_010': False,
    })


def validate_report(report):
    if not isinstance(report, dict) or report.get('schema_version') != 1:
        raise ValueError('Choose a dc-checks results.json (schema version 1).')
    results = report.get('results')
    if not isinstance(results, list) or len(results) > 10000:
        raise ValueError('Expected up to 10,000 check results.')
    if not isinstance(report.get('target', report.get('root')), str):
        raise ValueError('Report is missing its target or SYSVOL root.')
    for key in ('target', 'root', 'domain', 'identity', 'collector_host'):
        if key in report and not isinstance(report[key], str):
            raise ValueError(f'Invalid report {key}.')
    for row in results:
        if not isinstance(row, dict) or not isinstance(row.get('id', row.get('path')), str) or not isinstance(row.get('status'), str):
            raise ValueError('Invalid check result.')
        for key in ('id', 'path', 'note', 'reason', 'error', 'parse_error', 'target', 'identity', 'stdout', 'stderr', 'stdout_text', 'stderr_text'):
            if key in row and row[key] is not None and not isinstance(row[key], str):
                raise ValueError(f'Invalid check {key}.')
        if 'command' in row and (not isinstance(row['command'], list) or not all(isinstance(arg, str) for arg in row['command'])):
            raise ValueError('Invalid command arguments.')
    return report


def read_report(directory):
    path = directory / 'results.json'
    if not path.exists():
        return None
    report = validate_report(json.loads(path.read_text()))
    # Only the runner's own files, never paths from an imported JSON report.
    for row in report['results']:
        for stream in ('stdout', 'stderr'):
            name = row.get(stream)
            if isinstance(name, str) and Path(name).name == name:
                evidence = directory / name
                if evidence.is_file() and not evidence.is_symlink():
                    with evidence.open('rb') as file:
                        raw = file.read(100001)
                    row[stream + '_text'] = raw[:100000].decode(errors='replace')
                    row[stream + '_truncated'] = len(raw) > 100000
                    if stream == 'stdout' and isinstance(row.get('data'), dict) and 'hosts' in row['data'] and len(raw) <= 100000:
                        try:
                            row[stream + '_text'] = scan_text(raw)
                        except Exception as exc:
                            # Retain the original preview if readable rendering is unavailable.
                            row['render_note'] = str(exc)[:100]
    return report


def install_automation(app, db, records, get, put, auth, activity, jobs, body):
    slot = asyncio.Semaphore(1)
    tasks = {}

    def save(run, report=None):
        if report is not None:
            run['report'] = report
        with db() as conn:
            put(conn, 'automation', run)

    async def execute(run, config):
        process = None
        with tempfile.TemporaryDirectory(prefix='kiss-dc-') as temporary:
            directory = Path(temporary) / 'output'
            try:
                async with slot:
                    run.update(status='Running', started_at=time.time())
                    save(run)
                    config['out'] = str(directory)
                    with (Path(temporary) / 'collector.log').open('wb') as log:
                        process = await asyncio.create_subprocess_exec(
                            sys.executable, '-m', 'scripts.dc_checks.worker', cwd=ROOT,
                            stdin=asyncio.subprocess.PIPE, stdout=log, stderr=log, start_new_session=True)
                        process.stdin.write(json.dumps(config).encode())
                        await process.stdin.drain()
                        process.stdin.close()
                        config.clear()
                        deadline = time.monotonic() + 3600
                        while process.returncode is None:
                            if time.monotonic() > deadline:
                                raise TimeoutError('Collection exceeded the one-hour limit.')
                            total = sum(p.stat().st_size for p in Path(temporary).rglob('*') if p.is_file())
                            if total > 64 * 1024 * 1024:
                                raise ValueError('Collection exceeded the 64 MB evidence limit.')
                            save(run, read_report(directory))
                            await asyncio.sleep(1)
                        run['status'] = 'Planned' if run['plan'] and process.returncode == 0 else 'Complete' if process.returncode == 0 else 'Needs review'
                        run['returncode'] = process.returncode
            except asyncio.CancelledError:
                run['status'] = 'Cancelled'
            except Exception as exc:
                run.update(status='Failed', error=str(exc)[:500])
            finally:
                config.clear()
                if process is not None:
                    # Stop the whole collector process group, including a current nmap/LDAP child.
                    try:
                        os.killpg(process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(process.wait(), 3)
                    except TimeoutError:
                        pass
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await process.wait()
                try:
                    report = read_report(directory)
                    if report:
                        run['report'] = report
                    log_path = Path(temporary) / 'collector.log'
                    if log_path.exists():
                        with log_path.open('rb') as file:
                            run['log'] = file.read(20000).decode(errors='replace')
                    archive = io.BytesIO()
                    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip:
                        if directory.exists():
                            for path in directory.iterdir():
                                if path.is_file() and not path.is_symlink():
                                    zip.write(path, path.name)
                        if log_path.exists():
                            zip.write(log_path, 'collector.log')
                    with db() as conn:
                        conn.execute('INSERT OR REPLACE INTO blobs VALUES (?, ?, ?, ?)',
                                     (run['id'], 'automation', 'application/zip', archive.getvalue()))
                    run['download'] = True
                except Exception as exc:
                    run.update(status='Failed', error=f'Could not retain evidence: {str(exc)[:300]}')
                run['finished_at'] = time.time()
                save(run)
                with db() as conn:
                    activity(conn, run['actor'], 'finished DC checks', 'automation', run['id'], run['target'], run['status'])

    @app.get('/api/automation')
    def list_runs(username=Depends(auth)):
        with db() as conn:
            runs = records(conn, 'automation')
        summaries = [{key: value for key, value in run.items() if key not in {'report', 'log'}} | {
            'checks': len(run.get('report', {}).get('results', []))} for run in reversed(runs)]
        return {'runs': summaries, 'catalog': [asdict(check) for check in LAB_CHECKS] + [{'name': 'ms17-010', 'profile': 'vulns', 'authenticated': False, 'note': 'Nmap MS17-010 detection; no exploit payload.'}], 'dependencies': {**{tool: bool(shutil.which(tool)) for tools in TOOLS.values() for tool in tools}, 'nxc': bool(shutil.which('nxc')), 'certipy': bool(shutil.which('certipy-ad') or shutil.which('certipy'))}}

    @app.post('/api/automation')
    async def start(payload: RunChecks, username=Depends(auth)):
        payload = apply_preset(payload)
        with db() as conn:
            host = get(conn, 'hosts', payload.host_id)
            running = [row for row in records(conn, 'automation') if row['status'] in ACTIVE]
        if len(running) >= 6:
            raise HTTPException(409, 'Six collections are already queued or running.')
        if any(row['host_id'] == host['id'] for row in running):
            raise HTTPException(409, 'This host already has a collection queued or running.')
        try:
            target = validate_host(host['address'])
            domain = validate_host(payload.domain.strip())
            if '.' not in domain or all(c in '0123456789.' for c in domain):
                raise ValueError('Enter a DNS domain such as corp.local.')
            ldap_host = validate_host(payload.ldap_host) if payload.ldap_host else None
        except (ValueError, argparse.ArgumentTypeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        if payload.collector == 'directory' and not payload.modules:
            raise HTTPException(422, 'Choose at least one collection module.')
        if payload.collector == 'directory' and payload.bind_user and 'ldap' not in payload.modules:
            raise HTTPException(422, 'Select LDAP to use a domain account.')
        if payload.bind_user and not payload.password and not payload.plan:
            raise HTTPException(422, 'Enter the LDAP password; empty authenticated binds are not supported.')
        if payload.collector == 'lab':
            names = {check.name for check in LAB_CHECKS} | {'ms17-010'}
            if not set(payload.checks) <= names or not (payload.checks or payload.adcs):
                raise HTTPException(422, 'Select known lab checks or AD CS analysis.')
            if payload.bind_user and (not re.fullmatch(r'[\w.@$-]+', payload.bind_user) or Path(payload.bind_user).is_file()):
                raise HTTPException(422, 'Use one account name or UPN, not a file or domain\\user expression.')
            if any(char in payload.password for char in '\r\n\x00'):
                raise HTTPException(422, 'NetExec passwords must be a single line.')
            coercion = any(check.profile == 'coercion' and check.name in payload.checks for check in LAB_CHECKS)
            if payload.listener:
                try:
                    validate_host(payload.listener)
                except argparse.ArgumentTypeError as exc:
                    raise HTTPException(422, str(exc)) from exc
                if not coercion:
                    raise HTTPException(422, 'A receiver requires a selected coercion check.')
            if payload.adcs_ca_endpoints and not payload.adcs:
                raise HTTPException(422, 'Select AD CS analysis before enabling CA endpoint checks.')
            required = {'nxc'} if set(payload.checks) - {'ms17-010'} else set()
            if 'ms17-010' in payload.checks:
                required.add('nmap')
            if payload.adcs:
                required.add('certipy-ad' if shutil.which('certipy-ad') else 'certipy')
        else:
            required = {tool for module in payload.modules for tool in TOOLS[module]}
            if payload.ms17_010:
                required.add('nmap')
        missing = sorted(tool for tool in required if not shutil.which(tool))
        if missing and not payload.plan:
            raise HTTPException(422, 'Missing server tools: ' + ', '.join(missing))
        config = {'dc': target, 'domain': domain, 'modules': ','.join(dict.fromkeys(payload.modules)),
                  'ldap_host': ldap_host, 'ldap_transport': payload.ldap_transport, 'base_dn': None,
                  'bind_user': payload.bind_user or None, 'password': payload.password if payload.bind_user and not payload.plan else '',
                  'guest': payload.guest, 'ms17_010': payload.ms17_010, 'plan': payload.plan, 'timeout': payload.timeout}
        if payload.collector == 'lab':
            config = {'collector': payload.collector, 'checks': payload.checks, 'dc': target, 'domain': domain,
                      'username': payload.bind_user or None, 'password': payload.password if payload.bind_user and not payload.plan else '',
                      'listener': payload.listener or None, 'nxc': 'nxc',
                      'adcs': payload.adcs, 'adcs_dc_only': not payload.adcs_ca_endpoints,
                      'certipy': 'certipy-ad' if shutil.which('certipy-ad') else 'certipy',
                      'plan': payload.plan, 'timeout': payload.timeout}
        run = {'id': secrets.token_hex(12), 'preset': payload.preset, 'collector': payload.collector, 'checks_selected': payload.checks, 'host_id': host['id'], 'target': target, 'domain': domain,
               'actor': username, 'created_at': time.time(), 'status': 'Queued', 'plan': payload.plan,
               'modules': payload.modules, 'identity': payload.bind_user or 'anonymous', 'report': {'results': []}}
        save(run)
        with db() as conn:
            activity(conn, username, 'planned DC checks' if payload.plan else 'started DC checks', 'automation', run['id'], target)
        task = asyncio.create_task(execute(run, config))
        tasks[run['id']] = task
        jobs.add(task)
        task.add_done_callback(lambda done: (jobs.discard(done), tasks.pop(run['id'], None)))
        return {'id': run['id']}

    @app.post('/api/automation/import')
    async def import_report(request: Request, username=Depends(auth)):
        raw = await body(request)
        try:
            report = validate_report(json.loads(raw))
        except (ValueError, TypeError, RecursionError) as exc:
            raise HTTPException(422, str(exc)[:300]) from exc
        # Imported paths are only metadata. Never open referenced local files.
        run = {'id': secrets.token_hex(12), 'actor': username, 'target': report.get('target', report.get('root')),
               'domain': report.get('domain', ''), 'created_at': time.time(), 'status': 'Imported',
               'identity': report.get('identity', 'See check results'), 'report': report, 'download': True}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip:
            zip.writestr('results.json', raw)
        with db() as conn:
            conn.execute('INSERT INTO blobs VALUES (?, ?, ?, ?)', (run['id'], 'automation', 'application/zip', archive.getvalue()))
            put(conn, 'automation', run)
            activity(conn, username, 'imported DC checks', 'automation', run['id'], run['target'])
        return {'id': run['id']}

    @app.get('/api/automation/collectors')
    def collectors(username=Depends(auth)):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip:
            for name in ('README.md', 'JEWEL-README.md', 'dc_checks.py', 'ldap_checks.py', 'lab_checks.py', 'lab_catalog.py', 'check_sysvol.py', 'Collect-DomainChecks.ps1'):
                zip.write(ROOT / 'scripts' / 'dc_checks' / name, name)
        return Response(archive.getvalue(), media_type='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="dc-checks.zip"'})

    @app.get('/api/automation/report-template')
    def report_template(username=Depends(auth)):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zip:
            for name in ('report.tex', 'README.txt'):
                zip.write(ROOT / 'docs' / 'temp' / name, name)
        return Response(archive.getvalue(), media_type='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="report-template.zip"'})

    @app.get('/api/automation/{id}')
    def detail(id: str, username=Depends(auth)):
        with db() as conn:
            return get(conn, 'automation', id)

    @app.post('/api/automation/{id}/cancel')
    async def cancel(id: str, username=Depends(auth)):
        with db() as conn:
            get(conn, 'automation', id)
        task = tasks.get(id)
        if not task:
            raise HTTPException(409, 'This collection is no longer running.')
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        # A task cancelled before its first turn never enters execute's finally block.
        with db() as conn:
            run = get(conn, 'automation', id)
            if run['status'] in ACTIVE:
                run.update(status='Cancelled', finished_at=time.time())
                put(conn, 'automation', run)
        return {'ok': True}

    @app.get('/api/automation/{id}/download')
    def download(id: str, username=Depends(auth)):
        with db() as conn:
            row = conn.execute("SELECT data FROM blobs WHERE id=? AND kind='automation'", (id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'Evidence is not available yet.')
        return Response(row['data'], media_type='application/zip',
                        headers={'Content-Disposition': f'attachment; filename="dc-checks-{id}.zip"'})
