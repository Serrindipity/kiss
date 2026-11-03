import asyncio
from unittest.mock import Mock, patch

import pytest

from scripts import common_checks as checks


@pytest.mark.parametrize('script,output,outcome', [
    ('ftp-anon', 'Anonymous FTP login allowed (FTP code 230)', 'exposure'),
    ('ldap-rootdse', 'defaultNamingContext: DC=lab,DC=local', 'observation'),
    ('ldap-search', 'dn: CN=Alice,DC=lab,DC=local', 'exposure'),
    ('ldap-search', 'ERROR: Search failed', 'inconclusive'),
    ('rdp-enum-encryption', 'CredSSP (NLA): SUCCESS', 'observation'),
    ('rdp-enum-encryption', 'SSL: SUCCESS', 'review'),
    ('mongodb-databases', 'databases: unauthorized', 'inconclusive'),
    ('mongodb-databases', 'databases:\n  name: test', 'exposure'),
    ('mongodb-databases', 'ok = 1\n  databases\n    0\n      name = test', 'exposure'),
    ('redis-info', 'Version: 7.0', 'inconclusive'),
    ('redis-info', 'Version 7.0', 'exposure'),
    ('smb2-security-mode', 'Message signing enabled but not required', 'review'),
])
def test_classification(script, output, outcome):
    assert checks.classify(script, output, 389)['outcome'] == outcome


def test_script_observation_is_per_port():
    raw = b'<nmaprun><host><ports><port portid="389"><state state="open"/><script id="ldap-search" output="dn: CN=Alice"/></port><port portid="636"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
    async def fake_scan(*args):
        return raw
    with patch.object(checks, 'run_nmap', fake_scan), patch.object(checks.shutil, 'which', return_value='/usr/bin/nmap'):
        report, _ = asyncio.run(checks.run_checks('127.0.0.1'))
    assert any(item['port'] == 636 and item['outcome'] == 'inconclusive' for item in report['checks'])


def test_fixed_scripts_and_single_ip():
    with patch.object(checks.shutil, 'which', return_value='/usr/bin/nmap'):
        command = checks.check_command('127.0.0.1', [445])
        assert 'smb-enum-shares' not in ','.join(command)
        assert 'brute' not in ','.join(command)
        with pytest.raises(ValueError):
            checks.check_command('127.0.0.0/24', [445])


def test_missing_smbclient_is_skipped():
    with patch.object(checks.shutil, 'which', return_value=None):
        assert asyncio.run(checks.smb_anonymous('127.0.0.1'))[0]['outcome'] == 'skipped'


@pytest.mark.parametrize('status,body,challenge,outcome', [
    (200, b'<IdentifyResponse/>', '', 'observation'),
    (200, b'ordinary webpage', '', 'inconclusive'),
    (401, b'', 'Negotiate', 'observation'),
    (401, b'', 'Basic realm="test"', 'review'),
])
def test_winrm_never_claims_anonymous_shell(status, body, challenge, outcome):
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = status
    response.read.return_value = body
    response.getheader.return_value = challenge
    with patch.object(checks.http.client, 'HTTPConnection', return_value=connection):
        result = checks.winrm_identify('127.0.0.1', 5985)
    assert result['outcome'] == outcome
    assert connection.request.call_args.args == ('POST', '/wsman')
    assert connection.request.call_args.kwargs['body'] == checks.IDENTIFY
    connection.close.assert_called_once()
