from argparse import Namespace
from unittest.mock import patch
import subprocess
from scripts.dc_checks.dc_checks import Runner, collect_ldap_connections, ldap_command


def args(tmp_path, **updates):
    return Namespace(**(dict(out=str(tmp_path / 'out'), dc='192.0.2.10', domain='corp.test',
        ldap_host='dc.corp.test', ldap_transport='both', base_dn=None, bind_user=None,
        plan=True, timeout=1, modules='ldap', guest=False, ms17_010=False) | updates))


def test_both_ports_and_separate_evidence(tmp_path):
    runner = Runner(args(tmp_path))
    with patch('scripts.dc_checks.dc_checks.subprocess.run') as process:
        collect_ldap_connections(runner)
        process.assert_not_called()
    commands = [row['command'] for row in runner.results if 'command' in row]
    assert {cmd[cmd.index('-H') + 1] for cmd in commands} == {'ldap://dc.corp.test:389', 'ldaps://dc.corp.test:636'}
    assert all('-ZZ' not in cmd for cmd in commands)
    assert len({row['id'] for row in runner.results}) == len(runner.results)


def test_authenticated_389_requires_starttls(tmp_path):
    command = ldap_command(args(tmp_path, ldap_transport='ldap'), '', 'base', '(objectClass=*)', [], authenticated=True, secret='/private/password')
    assert '-ZZ' in command
    assert 'ldap://dc.corp.test:389' in command


def test_credential_rejection_stops_binds_on_other_port(tmp_path):
    runner = Runner(args(tmp_path, bind_user='reader@corp.test', plan=False))
    runner.secret = '/private/password'
    def reply(command, **kwargs):
        return subprocess.CompletedProcess(command, 49 if '-D' in command else 0, '', 'invalid credentials' if '-D' in command else '')
    with patch('scripts.dc_checks.dc_checks.shutil.which', return_value='/tool'), patch('scripts.dc_checks.dc_checks.subprocess.run', side_effect=reply) as process:
        collect_ldap_connections(runner)
    commands = [call.args[0] for call in process.call_args_list]
    assert len([cmd for cmd in commands if '-D' in cmd]) == 1
    assert any('ldaps://dc.corp.test:636' in cmd for cmd in commands)
