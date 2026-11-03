from argparse import Namespace
from unittest.mock import patch
from scripts.dc_checks.lab_catalog import CHECKS
from scripts.dc_checks.lab_checks import command, collect
from scripts.dc_checks.dc_checks import Runner


def args(tmp_path):
    return Namespace(dc='192.0.2.10', domain='corp.test', username=None, nxc='nxc', listener=None,
                     out=str(tmp_path / 'evidence'), timeout=1, plan=False, adcs=False)


def test_protocol_specific_commands(tmp_path):
    a = args(tmp_path)
    ftp = command(next(check for check in CHECKS if check.name == 'ftp-anonymous'), a, None)
    assert '-d' not in ftp
    assert ftp[ftp.index('-u') + 1] == 'anonymous'
    assert '--ls' in ftp
    for port in (389, 636):
        ldap = command(next(check for check in CHECKS if check.name == f'ldap-anonymous-{port}'), a, None)
        assert ldap[ldap.index('--port') + 1] == str(port)
        assert '--query' in ldap
        assert ldap[ldap.index('-u') + 1] == ldap[ldap.index('-p') + 1] == ''


def test_connection_failure_does_not_skip_other_protocols(tmp_path):
    a = args(tmp_path)
    a.username = 'reader'
    r = Runner(a)
    r.secret = '/temporary/password'
    seen = []
    def fake_run(name, argv, *args, **kwargs):
        seen.append(name)
        path = name + '.txt'
        (r.out / path).write_text('Connection refused' if name == 'rdp-account' else '')
        row = {'id': name, 'status': 'error' if name == 'rdp-account' else 'completed', 'stdout': path}
        r.results.append(row)
        return row
    with patch.object(r, 'run', side_effect=fake_run):
        collect(r, [check for check in CHECKS if check.name in {'rdp-account', 'winrm-account'}], False)
    assert 'rdp-account' in seen and 'winrm-account' in seen
    assert not any(name.startswith('authentication-') for name in seen)
    assert not any('modules' in name for name in seen)


def test_anonymous_denial_does_not_cancel_other_checks(tmp_path):
    r = Runner(args(tmp_path))
    seen = []
    def fake_run(name, argv, *args, **kwargs):
        seen.append(name)
        path = name + '.txt'
        (r.out / path).write_text('STATUS_LOGON_FAILURE' if name == 'rdp-anonymous' else '')
        row = {'id': name, 'status': 'completed', 'stdout': path}
        r.results.append(row)
        return row
    with patch.object(r, 'run', side_effect=fake_run):
        collect(r, [check for check in CHECKS if check.name in {'rdp-anonymous', 'winrm-anonymous'}], False)
    assert 'rdp-anonymous' in seen and 'winrm-anonymous' in seen
