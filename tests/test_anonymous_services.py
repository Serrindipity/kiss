from argparse import Namespace
from unittest.mock import patch
from scripts.dc_checks.dc_checks import Runner
from scripts.dc_checks.anonymous_services import collect_anonymous_services


def runner(tmp_path, plan=False):
    return Runner(Namespace(out=str(tmp_path / 'results'), plan=plan, dc='dc.test', domain='test', timeout=1))


def test_preview_no_network_or_subprocess(tmp_path):
    r = runner(tmp_path, True)
    with patch('scripts.dc_checks.anonymous_services.socket.gethostbyname') as dns, patch('scripts.dc_checks.dc_checks.subprocess.run') as process:
        collect_anonymous_services(r)
    dns.assert_not_called()
    process.assert_not_called()
    assert r.results[0]['reason'] == 'plan_only'


def test_preserves_access_evidence_and_port_coverage(tmp_path):
    r = runner(tmp_path)
    async def fake_checks(address):
        assert address == '192.0.2.10'
        return {'open_ports': [21], 'checks': [{'service': 'FTP', 'port': 21, 'outcome': 'exposure', 'title': 'Anonymous FTP login allowed', 'evidence': 'FTP code 230', 'source': 'nmap'}]}, b'<nmaprun/>'
    with patch('scripts.dc_checks.anonymous_services.socket.gethostbyname', return_value='192.0.2.10'), patch('scripts.dc_checks.anonymous_services.run_checks', fake_checks):
        collect_anonymous_services(r)
    assert r.results[0]['outcome'] == 'exposure'
    assert r.results[0]['stdout_text'] == 'FTP code 230'
    assert any(row['port'] == 3389 and row['outcome'] == 'observation' for row in r.results)
    assert (r.out / 'anonymous-services.xml').exists()


def test_failure_not_reported_as_clean(tmp_path):
    r = runner(tmp_path)
    with patch('scripts.dc_checks.anonymous_services.socket.gethostbyname', side_effect=OSError('DNS failed')):
        collect_anonymous_services(r)
    assert r.results[0]['status'] == 'error'
