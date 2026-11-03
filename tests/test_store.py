"""Exercise persistence and jobs directly, without a network or test-client threads.

HTTP routing, cookies, and request guards are covered in test_app.py.
"""
import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from server.app import Batch, Finding, HostEdit, create_app


@pytest.fixture
def endpoints(tmp_path):
    users = tmp_path / 'users.txt'
    users.write_text('sohee\nalex\n')
    app = create_app(tmp_path / 'data', users, tmp_path / 'config.toml')
    return {(route.path, method): route.endpoint for route in app.routes for method in getattr(route, 'methods', [])}


def request(data):
    async def receive():
        return {'type': 'http.request', 'body': data, 'more_body': False}
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': []}, receive)


def scan_bytes():
    return Path('tests/fixtures/scan.xml').read_bytes()


def test_import_edit_findings_and_conflicts(endpoints):
    async def exercise():
        await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24 Corporate', discover=False), 'sohee')
        await endpoints['/api/import', 'POST'](request(scan_bytes()), 'sohee')
        state = endpoints['/api/state', 'GET']('sohee')
        host = state['hosts'][0]
        assert host['network_id'] == state['networks'][0]['id']
        updated = endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes='**Evidence**', status='Investigating'), 'sohee')
        with pytest.raises(HTTPException) as conflict:
            endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes='Stale', status='Reviewed'), 'alex')
        assert conflict.value.status_code == 409
        finding = Finding(title='SMB signing', description='Evidence', finders=['sohee'], scope=[{'host_id': host['id'], 'ports': ['445/tcp']}])
        saved = endpoints['/api/findings', 'POST'](finding, 'sohee')
        assert saved['revision'] == 1
        invalid = finding.model_copy(update={'finders': ['stranger']})
        with pytest.raises(HTTPException) as invalid_finder:
            endpoints['/api/findings', 'POST'](invalid, 'sohee')
        assert invalid_finder.value.status_code == 422
        duplicate = await endpoints['/api/import', 'POST'](request(scan_bytes()), 'alex')
        assert duplicate['duplicate']
        assert endpoints['/api/state', 'GET']('alex')['hosts'][0]['notes'] == updated['notes']
    asyncio.run(exercise())


def test_batch_validation_is_atomic(endpoints):
    async def exercise():
        with pytest.raises(HTTPException):
            await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24\nbad', discover=False), 'sohee')
        assert endpoints['/api/state', 'GET']('sohee')['networks'] == []
    asyncio.run(exercise())


def test_older_scan_does_not_replace_newer_port_evidence(endpoints):
    async def exercise():
        await endpoints['/api/import', 'POST'](request(scan_bytes()), 'sohee')
        older = scan_bytes().replace(b'1793516460', b'1693516460').replace(b'state="open"', b'state="closed"')
        await endpoints['/api/import', 'POST'](request(older), 'alex')
        assert all(port['state'] == 'open' for host in endpoints['/api/state', 'GET']('sohee')['hosts'] for port in host['ports'])
    asyncio.run(exercise())


def test_auto_discovery_persists_hosts_and_status(endpoints):
    async def fake_discovery(cidr):
        assert cidr == '10.20.0.0/24'
        return scan_bytes()

    async def exercise():
        with patch('server.app.discovery_command', return_value=['nmap']), patch('server.app.run_discovery', fake_discovery):
            await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24 Corporate'), 'sohee')
            for _ in range(10):
                await asyncio.sleep(0)
                state = endpoints['/api/state', 'GET']('sohee')
                if state['networks'][0]['discovery']['status'] == 'Complete':
                    break
            assert state['networks'][0]['discovery']['status'] == 'Complete'
            assert len(state['hosts']) == 3
            assert state['scans'][0]['finder'] == 'sohee'
    asyncio.run(exercise())


def test_image_upload_is_decoded_and_stored(endpoints):
    import io
    from PIL import Image

    async def exercise():
        image = io.BytesIO()
        Image.new('RGB', (5, 5), 'blue').save(image, 'JPEG')
        saved = await endpoints['/api/attachments', 'POST'](request(image.getvalue()), 'sohee')
        response = endpoints['/api/attachments/{id}', 'GET'](saved['path'].rsplit('/', 1)[1], 'alex')
        assert response.media_type == 'image/png'
        assert Image.open(io.BytesIO(response.body)).size == (5, 5)
        with pytest.raises(HTTPException) as invalid:
            await endpoints['/api/attachments', 'POST'](request(b'<svg onload="alert(1)"/>'), 'sohee')
        assert invalid.value.status_code == 415
    asyncio.run(exercise())


def test_refused_transfer_falls_back_to_selected_dns(endpoints):
    async def failed_transfer(cidr, server, zone):
        assert (server, zone) == ('10.20.0.10', 'corp.local')
        raise ValueError('refused')

    calls = []

    async def reverse_discovery(cidr, server):
        calls.append((cidr, server))
        return scan_bytes()

    async def exercise():
        with patch('server.app.discovery_command', return_value=['nmap']), patch('server.app.run_zone_transfer', failed_transfer), patch('server.app.run_discovery', reverse_discovery):
            await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24', dns_server='10.20.0.10', dns_zone='corp.local'), 'sohee')
            for _ in range(10):
                await asyncio.sleep(0)
                state = endpoints['/api/state', 'GET']('sohee')
                if state['networks'][0]['discovery']['status'] == 'Complete':
                    break
            assert calls == [('10.20.0.0/24', '10.20.0.10')]
            assert 'reverse DNS' in state['networks'][0]['discovery']['message']
            assert state['hosts'][0]['hostname'] == 'dc01.corp.local'
    asyncio.run(exercise())


def test_zone_only_hosts_and_manual_names_are_preserved(endpoints):
    async def transfer(*args):
        return [
            {'address': '10.20.0.10', 'hostname': 'dc01.corp.local', 'aliases': ['ns.corp.local']},
            {'address': '10.20.0.40', 'hostname': 'quiet.corp.local', 'aliases': []},
        ], b'<nmaprun><prescript/></nmaprun>'

    async def sweep(cidr):
        return scan_bytes()

    async def exercise():
        await endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.10 team-label'), 'sohee')
        with patch('server.app.discovery_command', return_value=['nmap']), patch('server.app.run_zone_transfer', transfer), patch('server.app.run_discovery', sweep):
            await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24', dns_server='10.20.0.10', dns_zone='corp.local'), 'sohee')
            for _ in range(10):
                await asyncio.sleep(0)
                state = endpoints['/api/state', 'GET']('sohee')
                if state['networks'][0]['discovery']['status'] == 'Complete':
                    break
            hosts = {h['address']: h for h in state['hosts']}
            assert hosts['10.20.0.10']['hostname'] == 'team-label'
            assert hosts['10.20.0.10']['aliases'] == ['dc01.corp.local', 'ns.corp.local']
            assert hosts['10.20.0.40']['reachability'] == 'unknown'
            assert len(hosts) == 4
            assert state['scans'][0]['source'] == 'DNS zone transfer'
    asyncio.run(exercise())


def test_invalid_dns_is_rejected_before_scope_is_added(endpoints):
    async def exercise():
        with pytest.raises(HTTPException) as error:
            await endpoints['/api/scope', 'POST'](Batch(kind='network', text='10.20.0.0/24', dns_server='10.20.0.10', dns_zone='corp.local,newtargets'), 'sohee')
        assert error.value.status_code == 422
        assert endpoints['/api/state', 'GET']('sohee')['networks'] == []
    asyncio.run(exercise())


PORT_SCAN = b'''<nmaprun><host><status state="up"/><address addr="10.20.0.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" method="probed" product="nginx"/></port></ports></host><runstats><finished time="1793516460" exit="success"/></runstats></nmaprun>'''


def test_port_scan_is_per_host_deduplicated_and_preserves_notes(endpoints):
    async def exercise():
        await endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.10 dc01'), 'sohee')
        host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
        endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes='Keep this evidence', status='Investigating'), 'sohee')
        gate = asyncio.Event()
        calls = []
        async def scan(address, on_progress=None):
            calls.append(address)
            await gate.wait()
            return PORT_SCAN, address
        with patch('server.app.run_port_scan', scan):
            await endpoints['/api/hosts/{id}/scan', 'POST'](host['id'], 'sohee')
            duplicate = await endpoints['/api/hosts/{id}/scan', 'POST'](host['id'], 'alex')
            assert duplicate['already_running']
            await asyncio.sleep(0)
            assert endpoints['/api/state', 'GET']('sohee')['hosts'][0]['port_scan']['status'] == 'Running'
            gate.set()
            for _ in range(10):
                await asyncio.sleep(0)
                saved = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
                if saved['port_scan']['status'] == 'Complete':
                    break
            assert calls == ['10.20.0.10']
            assert saved['port_scan']['status'] == 'Complete'
            assert saved['ports'][0]['port'] == 443
            assert saved['notes'] == 'Keep this evidence'
            assert saved['hostname'] == 'dc01'
            events = endpoints['/api/state', 'GET']('sohee')['activity']
            scans = [event for event in events if event['action'].startswith('port scan')]
            assert [event['action'] for event in scans] == ['port scan complete', 'port scan running', 'port scan queued']
            assert all(event['actor'] == 'sohee' for event in scans)
    asyncio.run(exercise())


def test_cancel_port_scan_keeps_existing_evidence(endpoints):
    async def exercise():
        await endpoints['/api/import', 'POST'](request(PORT_SCAN), 'sohee')
        host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
        async def scan(address, on_progress=None):
            await asyncio.Event().wait()
        with patch('server.app.run_port_scan', scan):
            await endpoints['/api/hosts/{id}/scan', 'POST'](host['id'], 'sohee')
            await asyncio.sleep(0)
            await endpoints['/api/hosts/{id}/scan/cancel', 'POST'](host['id'], 'sohee')
            saved = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
            assert saved['port_scan']['status'] == 'Cancelled'
            assert saved['ports'] == host['ports']
    asyncio.run(exercise())


def test_scan_output_cannot_populate_other_hosts(endpoints):
    async def exercise():
        await endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.10'), 'sohee')
        host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
        async def scan(address, on_progress=None):
            return scan_bytes(), address  # Three hosts is invalid for this per-host job.
        with patch('server.app.run_port_scan', scan):
            await endpoints['/api/hosts/{id}/scan', 'POST'](host['id'], 'sohee')
            for _ in range(10):
                await asyncio.sleep(0)
                state = endpoints['/api/state', 'GET']('sohee')
                if state['hosts'][0]['port_scan']['status'] == 'Failed':
                    break
            assert state['hosts'][0]['port_scan']['status'] == 'Failed'
            assert len(state['hosts']) == 1
            assert not state['hosts'][0]['ports']
    asyncio.run(exercise())


def test_credentials_require_context_and_preserve_exact_secrets(endpoints):
    from server.app import Credential
    for kind in ['domain', 'local', 'service', 'api', 'ssh', 'other']:
        with pytest.raises(HTTPException) as error:
            endpoints['/api/credentials', 'POST'](Credential(kind=kind, username='alice', secret='example'), 'sohee')
        assert error.value.status_code == 422
    payload = Credential(kind='service', service='PostgreSQL', system='db01:5432 / app database', username='app_user', secret='  sample secret\n', notes='**Read-only** access')
    saved = endpoints['/api/credentials', 'POST'](payload, 'sohee')
    assert saved['secret'] == '  sample secret\n'
    assert saved['added_by'] == 'sohee'
    assert endpoints['/api/state', 'GET']('alex')['credentials'][0]['id'] == saved['id']
    updated = payload.model_copy(update={'revision': 1, 'status': 'Invalid'})
    assert endpoints['/api/credentials/{id}', 'PUT'](saved['id'], updated, 'alex')['revision'] == 2
    with pytest.raises(HTTPException) as conflict:
        endpoints['/api/credentials/{id}', 'PUT'](saved['id'], updated, 'sohee')
    assert conflict.value.status_code == 409


def test_local_credential_can_use_inventory_host(endpoints):
    from server.app import Credential
    asyncio.run(endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.10 dc01'), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    saved = endpoints['/api/credentials', 'POST'](Credential(kind='local', host_id=host['id'], username='administrator', secret='example'), 'sohee')
    assert saved['host_id'] == host['id']
    with pytest.raises(HTTPException):
        endpoints['/api/credentials', 'POST'](Credential(kind='local', host_id='missing', username='administrator', secret='example'), 'sohee')


def test_host_owner_is_a_team_member_and_survives_scans(endpoints):
    async def exercise():
        await endpoints['/api/import', 'POST'](request(PORT_SCAN), 'sohee')
        host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
        saved = endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes='Assigned work', status='Investigating', owner='alex'), 'sohee')
        assert saved['owner'] == 'alex'
        with pytest.raises(HTTPException) as invalid:
            endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=saved['revision'], notes='', status='Unreviewed', owner='stranger'), 'sohee')
        assert invalid.value.status_code == 422
        newer = PORT_SCAN.replace(b'1793516460', b'1793516461')
        await endpoints['/api/import', 'POST'](request(newer), 'sohee')
        assert endpoints['/api/state', 'GET']('sohee')['hosts'][0]['owner'] == 'alex'
    asyncio.run(exercise())


def test_scan_text_evidence_includes_existing_imports(endpoints):
    asyncio.run(endpoints['/api/import', 'POST'](request(scan_bytes()), 'sohee'))
    scan = endpoints['/api/state', 'GET']('sohee')['scans'][0]
    response = endpoints['/api/scans/{id}/text', 'GET'](scan['id'], 'sohee')
    assert response.headers['content-type'].startswith('text/plain')
    assert '.txt' in response.headers['content-disposition']
    assert b'Nmap scan evidence' in response.body
    assert b'<nmaprun' not in response.body
    assert endpoints['/api/scans/{id}', 'GET'](scan['id'], 'sohee').body == scan_bytes()


def test_activity_tracks_actor_and_rejects_conflicting_edits(endpoints):
    from server.app import Credential
    asyncio.run(endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.5', discover=False), 'sohee'))
    state = endpoints['/api/state', 'GET']('sohee')
    host = state['hosts'][0]
    saved = endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], owner='alex', notes='', status='Investigating'), 'sohee')
    finding = endpoints['/api/findings', 'POST'](Finding(title='Test evidence', scope=[{'host_id': host['id'], 'ports': []}], finders=['alex']), 'sohee')
    endpoints['/api/credentials', 'POST'](Credential(kind='domain', username='lab-user', domain='LAB', secret='plaintext', finder='alex'), 'sohee')
    events = endpoints['/api/state', 'GET']('alex')['activity']
    assert [event['action'] for event in events] == ['added credential', 'added finding', 'changed owner', 'added scope']
    assert all(event['actor'] == 'sohee' for event in events)
    assert events[1]['target_id'] == finding['id']
    assert events[2]['detail'] == 'Owner: alex'
    with pytest.raises(HTTPException):
        endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes='stale', status='Reviewed'), 'alex')
    assert endpoints['/api/state', 'GET']('alex')['activity'] == events
    assert saved['owner'] == 'alex'


def test_activity_survives_reopening_and_is_bounded(tmp_path):
    users = tmp_path / 'users.txt'
    users.write_text('sohee\n')
    def routes():
        return {(route.path, method): route.endpoint for route in create_app(tmp_path / 'data', users, tmp_path / 'config.toml').routes for method in getattr(route, 'methods', [])}
    endpoints = routes()
    asyncio.run(endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.0.0.1', discover=False), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    for i in range(205):
        host = endpoints['/api/hosts/{id}', 'PUT'](host['id'], HostEdit(revision=host['revision'], notes=str(i), status='Investigating'), 'sohee')
    events = routes()['/api/state', 'GET']('sohee')['activity']
    assert len(events) == 200
    assert events[0]['at'] >= events[-1]['at']


def test_page_urls_serve_frontend(endpoints):
    for page in ('/', '/home', '/scope', '/findings', '/credentials', '/users', '/cheatsheet', '/automation'):
        assert endpoints[page, 'GET']().path.name == 'index.html'


def test_scan_progress_updates_without_activity_spam(endpoints):
    async def exercise():
        await endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.20.0.10', discover=False), 'sohee')
        host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
        gate = asyncio.Event()
        async def scan(address, on_progress):
            on_progress({'phase': 'Connect Scan', 'percent': 37.5})
            await gate.wait()
            return PORT_SCAN, address
        with patch('server.app.run_port_scan', scan):
            await endpoints['/api/hosts/{id}/scan', 'POST'](host['id'], 'sohee')
            await asyncio.sleep(0)
            state = endpoints['/api/state', 'GET']('sohee')
            progress = state['hosts'][0]['port_scan']
            assert progress['phase'] == 'Connect Scan'
            assert progress['percent'] == 37.5
            assert progress['started_at'] > 0
            assert len([e for e in state['activity'] if e['kind'] == 'host']) == 2
            gate.set()
            for _ in range(10):
                await asyncio.sleep(0)
            final = endpoints['/api/state', 'GET']('sohee')['hosts'][0]['port_scan']
            assert final['status'] == 'Complete'
            assert 'percent' not in final
    asyncio.run(exercise())


def test_scan_evidence_link_retained_without_individual_ports(endpoints):
    import hashlib
    raw = b'<nmaprun><host><status state="up"/><address addr="10.20.0.10" addrtype="ipv4"/><ports><extraports state="closed" count="65535"/></ports></host><runstats><finished time="1793516460" exit="success"/></runstats></nmaprun>'
    asyncio.run(endpoints['/api/import', 'POST'](request(raw), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    assert host['ports'] == []
    assert host['port_scan_id'] == hashlib.sha256(raw).hexdigest()
    response = endpoints['/api/scans/{id}/text', 'GET'](host['port_scan_id'], 'sohee')
    assert b'closed' in response.body


def test_rename_host_and_delete_without_losing_scan_evidence(endpoints):
    from server.app import HostRename
    asyncio.run(endpoints['/api/import', 'POST'](request(PORT_SCAN), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    renamed = endpoints['/api/hosts/{id}/hostname', 'PUT'](host['id'], HostRename(hostname='webhost.lab', revision=host['revision']), 'sohee')
    assert renamed['hostname'] == 'webhost.lab'
    assert renamed['ports'] == host['ports']
    with pytest.raises(HTTPException) as stale:
        endpoints['/api/hosts/{id}', 'DELETE'](host['id'], host['revision'], 'sohee')
    assert stale.value.status_code == 409
    endpoints['/api/hosts/{id}', 'DELETE'](host['id'], renamed['revision'], 'sohee')
    state = endpoints['/api/state', 'GET']('sohee')
    assert state['hosts'] == []
    assert endpoints['/api/scans/{id}', 'GET'](state['scans'][0]['id'], 'sohee').body == PORT_SCAN
    assert state['activity'][0]['action'] == 'deleted host'


def test_delete_protects_finding_and_credential_references(endpoints):
    from server.app import Credential
    asyncio.run(endpoints['/api/scope', 'POST'](Batch(kind='host', text='10.0.0.1', discover=False), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    endpoints['/api/findings', 'POST'](Finding(title='Keep this finding', scope=[{'host_id': host['id'], 'ports': []}], finders=['sohee']), 'sohee')
    endpoints['/api/credentials', 'POST'](Credential(kind='local', username='user', host_id=host['id']), 'sohee')
    with pytest.raises(HTTPException) as linked:
        endpoints['/api/hosts/{id}', 'DELETE'](host['id'], host['revision'], 'sohee')
    assert linked.value.status_code == 409
    assert '1 findings and 1 credentials' in linked.value.detail
    assert endpoints['/api/state', 'GET']('sohee')['hosts'][0]['id'] == host['id']


def test_cleared_hostname_is_not_replaced_by_later_scan(endpoints):
    from server.app import HostRename
    asyncio.run(endpoints['/api/import', 'POST'](request(PORT_SCAN), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    endpoints['/api/hosts/{id}/hostname', 'PUT'](host['id'], HostRename(hostname='', revision=host['revision']), 'sohee')
    newer = PORT_SCAN.replace(b'<ports>', b'<hostnames><hostname name="detected.lab"/></hostnames><ports>').replace(b'1793516460', b'1793516461')
    asyncio.run(endpoints['/api/import', 'POST'](request(newer), 'sohee'))
    assert endpoints['/api/state', 'GET']('sohee')['hosts'][0]['hostname'] == ''


def test_scan_os_summary_is_persisted(endpoints):
    raw = b'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><hostscript><script id="rdp-ntlm-info" output="Product_Version: 10.0.17763"/></hostscript></host><runstats><finished time="1"/></runstats></nmaprun>'
    asyncio.run(endpoints['/api/import', 'POST'](request(raw), 'sohee'))
    host = endpoints['/api/state', 'GET']('sohee')['hosts'][0]
    assert host['os']['method'] == 'inferred'
    assert 'Server 2019' in host['os']['name']
    assert host['os']['scan_id']
