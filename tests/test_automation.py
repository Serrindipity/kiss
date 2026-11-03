import asyncio
import io
import json
from unittest.mock import patch
import zipfile

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from server.app import create_app, Batch
from server.automation import RunChecks, validate_report


@pytest.fixture
def endpoints(tmp_path):
    users = tmp_path / 'users.txt'
    users.write_text('sohee\n')
    app = create_app(tmp_path / 'data', users, tmp_path / 'config.toml')
    return {(route.path, method): route.endpoint for route in app.routes for method in getattr(route, 'methods', [])}


def request(data):
    async def receive():
        return {'type': 'http.request', 'body': data, 'more_body': False}
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []}, receive)


async def add_host(endpoints):
    await endpoints['/api/scope', 'POST'](Batch(kind='host', text='192.0.2.10 dc.example.test', discover=False), 'sohee')
    return endpoints['/api/state', 'GET']('sohee')['hosts'][0]['id']


def test_preview_worker_and_archive_without_network(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        result = await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test', modules=['dns', 'ldap'], bind_user='reader@example.test', password='DO-NOT-RETAIN', plan=True), 'sohee')
        for _ in range(80):
            run = endpoints['/api/automation/{id}', 'GET'](result['id'], 'sohee')
            if run['status'] not in {'Queued', 'Running'}:
                break
            await asyncio.sleep(.1)
        assert run['status'] == 'Planned', run
        assert len(run['report']['results']) > 20
        assert all(row['status'] == 'not_tested' for row in run['report']['results'])
        assert 'DO-NOT-RETAIN' not in json.dumps(run)
        response = endpoints['/api/automation/{id}/download', 'GET'](result['id'], 'sohee')
        with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
            assert 'results.json' in archive.namelist()
            assert all('password' not in name for name in archive.namelist())
            assert b'DO-NOT-RETAIN' not in archive.read('results.json')
    asyncio.run(exercise())


def test_missing_dependencies_and_invalid_domain(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        with patch('server.automation.shutil.which', return_value=None):
            with pytest.raises(HTTPException, match='Missing server tools'):
                await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test', modules=['dns']), 'sohee')
        with pytest.raises(HTTPException):
            await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='--bad', modules=['dns'], plan=True), 'sohee')
    asyncio.run(exercise())


def test_import_does_not_read_paths(endpoints):
    report = {'schema_version': 1, 'target': 'dc.test', 'results': [{'id': 'check', 'status': 'completed', 'stdout': '/etc/passwd', 'data': ['example']}]}
    response = asyncio.run(endpoints['/api/automation/import', 'POST'](request(json.dumps(report).encode()), 'sohee'))
    run = endpoints['/api/automation/{id}', 'GET'](response['id'], 'sohee')
    assert run['report'] == report
    assert run['status'] == 'Imported'
    summaries = endpoints['/api/automation', 'GET']('sohee')['runs']
    assert summaries[0]['checks'] == 1 and 'report' not in summaries[0]


def test_reject_bad_imports():
    for report in [[], {}, {'schema_version': 1, 'target': 'dc', 'results': ['bad']},
                   {'schema_version': 1, 'target': 'dc', 'results': [{'id': 'check', 'status': 'completed', 'error': {}}]}]:
        with pytest.raises(ValueError):
            validate_report(report)


def test_immediate_cancel_does_not_leave_queued_run(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        result = await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test', modules=['dns'], plan=True), 'sohee')
        await endpoints['/api/automation/{id}/cancel', 'POST'](result['id'], 'sohee')
        assert endpoints['/api/automation/{id}', 'GET'](result['id'], 'sohee')['status'] == 'Cancelled'
    asyncio.run(exercise())


def test_windows_and_sysvol_imports(endpoints):
    for report in [
        {'schema_version': 1, 'target': 'dc01', 'collector_host': 'WIN01', 'identity': 'CORP\\reader',
         'results': [{'id': 'domain', 'status': 'completed', 'data': [{'Name': 'corp.local'}]}]},
        {'schema_version': 1, 'root': '/copied/SYSVOL', 'limited': False,
         'results': [{'path': 'policy.xml', 'status': 'completed', 'indicators': [{'indicator': 'gpp-cpassword', 'line': 3}]}]},
    ]:
        response = asyncio.run(endpoints['/api/automation/import', 'POST'](request(json.dumps(report).encode()), 'sohee'))
        assert endpoints['/api/automation/{id}', 'GET'](response['id'], 'sohee')['report'] == report


def test_running_cancel_reaps_worker(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        create = asyncio.create_subprocess_exec
        processes = []
        async def fake_worker(*args, **kwargs):
            import sys
            process = await create(sys.executable, '-c', 'import sys,time; sys.stdin.read(); time.sleep(60)', **kwargs)
            processes.append(process)
            return process
        with patch('server.automation.asyncio.create_subprocess_exec', side_effect=fake_worker):
            result = await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test', modules=['dns'], plan=True), 'sohee')
            for _ in range(50):
                if processes:
                    break
                await asyncio.sleep(.02)
            assert processes
            await asyncio.sleep(.05)
            await endpoints['/api/automation/{id}/cancel', 'POST'](result['id'], 'sohee')
            assert processes[0].returncode is not None
            run = endpoints['/api/automation/{id}', 'GET'](result['id'], 'sohee')
            assert run['status'] == 'Cancelled'
    asyncio.run(exercise())


def test_lab_preview_with_receiver_and_certipy(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        response = await endpoints['/api/automation', 'POST'](RunChecks(
            host_id=host_id, domain='example.test', collector='lab',
            checks=['petitpotam', 'kerberoast', 'zerologon', 'ms17-010'],
            listener='192.0.2.20', adcs=True, bind_user='reader', password='NOT-SAVED', plan=True), 'sohee')
        for _ in range(80):
            run = endpoints['/api/automation/{id}', 'GET'](response['id'], 'sohee')
            if run['status'] not in {'Queued', 'Running'}:
                break
            await asyncio.sleep(.1)
        assert run['status'] == 'Planned', run
        assert 'NOT-SAVED' not in json.dumps(run)
        results = {row['id']: row for row in run['report']['results']}
        assert {'petitpotam', 'kerberoast', 'zerologon', 'ms17-010', 'certipy-adcs'} <= results.keys()
        assert 'LISTENER=192.0.2.20' in results['petitpotam']['command']
        assert results['petitpotam']['callback_confirmed'] is None
        assert '-dc-only' in results['certipy-adcs']['command']
        assert all(row['status'] == 'not_tested' for row in results.values())
    asyncio.run(exercise())


def test_lab_selection_rejected_before_start(endpoints):
    async def exercise():
        host_id = await add_host(endpoints)
        for extra in [dict(checks=['made-up']), dict(checks=['zerologon'], listener='192.0.2.20'),
                      dict(checks=['zerologon'], bind_user='domain\\user'),
                      dict(checks=['zerologon'], adcs_ca_endpoints=True)]:
            with pytest.raises(HTTPException):
                await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test', collector='lab', plan=True, **extra), 'sohee')
    asyncio.run(exercise())


def test_downloads_include_new_deliverables(endpoints):
    response = endpoints['/api/automation/collectors', 'GET']('sohee')
    with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
        assert {'lab_checks.py', 'lab_catalog.py', 'check_sysvol.py'} <= set(archive.namelist())
    response = endpoints['/api/automation/report-template', 'GET']('sohee')
    with zipfile.ZipFile(io.BytesIO(response.body)) as archive:
        assert set(archive.namelist()) == {'report.tex', 'README.txt'}


def test_presets_select_disjoint_lab_checks_and_strip_anonymous_credentials():
    from server.automation import apply_preset, LAB_CHECKS
    anon = apply_preset(RunChecks(host_id='h', domain='corp.test', preset='anonymous', bind_user='ignored', password='ignored', adcs=True))
    domain = apply_preset(RunChecks(host_id='h', domain='corp.test', preset='domain', bind_user='reader', password='known'))
    assert anon.bind_user == anon.password == '' and not anon.adcs
    assert set(anon.checks) == {c.name for c in LAB_CHECKS if not c.authenticated} | {'ms17-010'}
    assert set(domain.checks) == {c.name for c in LAB_CHECKS if c.authenticated}
    assert not set(anon.checks) & set(domain.checks)
    assert anon.modules == domain.modules == []
    assert anon.collector == domain.collector == 'lab'


@pytest.mark.parametrize('preset', ['anonymous', 'domain'])
def test_combined_preset_preview(endpoints, preset):
    async def exercise():
        host_id = await add_host(endpoints)
        response = await endpoints['/api/automation', 'POST'](RunChecks(host_id=host_id, domain='example.test',
            preset=preset, bind_user='reader', password='NEVER-SAVED', plan=True), 'sohee')
        for _ in range(80):
            run = endpoints['/api/automation/{id}', 'GET'](response['id'], 'sohee')
            if run['status'] not in {'Queued', 'Running'}:
                break
            await asyncio.sleep(.1)
        assert run['status'] == 'Planned', run
        assert run['preset'] == preset
        results = {row['id']: row for row in run['report']['results']}
        assert f'ldap-{"anonymous" if preset == "anonymous" else "account"}-389' in results
        assert f'ldap-{"anonymous" if preset == "anonymous" else "account"}-636' in results
        assert 'NEVER-SAVED' not in json.dumps(run)
        if preset == 'anonymous':
            assert 'zerologon' in results and 'ms17-010' in results and 'ftp-anonymous' in results
            assert 'kerberoast' not in results
            assert all(row.get('reason') == 'plan_only' for row in results.values())
        else:
            assert 'kerberoast' in results and 'ldap-account-389' in results
            assert 'zerologon' not in results
    asyncio.run(exercise())
