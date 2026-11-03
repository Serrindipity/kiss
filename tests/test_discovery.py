import asyncio

import pytest

from scripts import nmap_runner as discovery
from scripts.nmap_xml import parse_scan


def test_command_is_fixed_and_target_is_validated(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: '/usr/bin/nmap')
    assert discovery.discovery_command('10.20.0.0/24') == [
        '/usr/bin/nmap', '-sn', '-n', '--max-retries', '1', '--host-timeout', '15s', '-oX', '-', '10.20.0.0/24'
    ]
    for target in ['10.20.0.0/24;id', '--script=bad', '10.0.0.0/8', '2001:db8::/64']:
        with pytest.raises(ValueError):
            discovery.discovery_command(target)


def test_missing_nmap_has_actionable_message(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: None)
    with pytest.raises(ValueError, match='Install nmap'):
        discovery.discovery_command('10.20.0.0/24')


def test_zero_responding_hosts_is_a_valid_discovery():
    data = b'<nmaprun><runstats><finished exit="success" time="1700000000"/><hosts up="0" down="256" total="256"/></runstats></nmaprun>'
    hosts, _ = parse_scan(data, allow_empty=True)
    assert hosts == []
    with pytest.raises(ValueError, match='No IP hosts'):
        parse_scan(data)


def test_process_failure_is_reported(monkeypatch):
    class FailedProcess:
        returncode = 1

        async def communicate(self):
            return b'', b'route unavailable'

    async def launch(*args, **kwargs):
        return FailedProcess()

    monkeypatch.setattr(discovery, 'discovery_command', lambda _: ['nmap', '-sn', '10.20.0.0/24'])
    monkeypatch.setattr(discovery.asyncio, 'create_subprocess_exec', launch)
    with pytest.raises(ValueError, match='route unavailable'):
        asyncio.run(discovery.run_discovery('10.20.0.0/24'))


def test_timeout_terminates_process(monkeypatch):
    class SlowProcess:
        returncode = None
        killed = False

        async def communicate(self):
            if not self.killed:
                await asyncio.sleep(60)
            return b'', b''

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = SlowProcess()

    async def launch(*args, **kwargs):
        return process

    monkeypatch.setattr(discovery, 'discovery_command', lambda _: ['nmap', '-sn', '10.20.0.0/24'])
    monkeypatch.setattr(discovery.asyncio, 'create_subprocess_exec', launch)
    monkeypatch.setattr(discovery, 'TIMEOUT', 0.001)
    with pytest.raises(ValueError, match='exceeded'):
        asyncio.run(discovery.run_discovery('10.20.0.0/24'))
    assert process.killed


def test_dns_settings_and_commands(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: '/usr/bin/nmap')
    assert discovery.validate_dns('10.20.0.10', 'Corp.Local.') == ('10.20.0.10', 'corp.local')
    for server, zone in [('dns.example.test', 'corp.local'), ('10.20.0.10', 'x,newtargets'), ('', 'corp.local')]:
        with pytest.raises(ValueError):
            discovery.validate_dns(server, zone)
    command = discovery.discovery_command('10.20.0.0/24', '10.20.0.10')
    assert '-n' not in command
    assert command[command.index('--dns-servers') + 1] == '10.20.0.10'
    transfer = discovery.zone_command('10.20.0.10', 'corp.local')
    assert 'newtargets' not in ' '.join(transfer)
    assert '--script' in transfer


def test_zone_parser_keeps_aliases_and_filters_scope():
    data = b'''<nmaprun><prescript><script id="dns-zone-transfer" output="corp.local. SOA ns.corp.local. admin.corp.local.&#10;dc01.corp.local. A 10.20.0.10&#10;ns.corp.local. A 10.20.0.10&#10;web.corp.local. CNAME dc01.corp.local.&#10;outside.corp.local. A 203.0.113.4&#10;corp.local. SOA ns.corp.local. admin.corp.local."/></prescript></nmaprun>'''
    hosts = discovery.parse_zone(data, '10.20.0.0/24', 'corp.local')
    assert len(hosts) == 1
    assert hosts[0]['address'] == '10.20.0.10'
    assert hosts[0]['hostname'] == 'dc01.corp.local'
    assert hosts[0]['aliases'] == ['ns.corp.local', 'web.corp.local']


def test_refused_or_partial_zone_is_not_success():
    for data in [b'<nmaprun/>', b'<nmaprun><script id="dns-zone-transfer" output="ERROR: refused"/></nmaprun>', b'<nmaprun><script id="dns-zone-transfer" output="corp.local. SOA ns.corp.local.&#10;dc01.corp.local. A 10.20.0.10"/></nmaprun>']:
        with pytest.raises(ValueError):
            discovery.parse_zone(data, '10.20.0.0/24', 'corp.local')


def test_port_scan_targets_exactly_one_host(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: '/usr/bin/nmap')
    command = discovery.port_scan_command('10.20.0.10')
    assert command[-1] == '10.20.0.10'
    assert all(flag in command for flag in ['-p-', '-sT', '-sCV', '-Pn', '-n', '-oX'])
    assert command[command.index('--script') + 1] == 'default,smb-os-discovery,rdp-ntlm-info'
    assert '-6' in discovery.port_scan_command('2001:db8::1')
    for target in ['10.20.0.0/24', '10.20.0.1-5', '--script=bad', 'host;id', 'host.example.test']:
        with pytest.raises(ValueError):
            discovery.port_scan_command(target)


@pytest.mark.parametrize('code,output,expected', [
    (-9, b'', 'SIGKILL'),
    (2, b'', 'exit code 2'),
    (1, b'<nmaprun><runstats><finished exit="error" errormsg="Test failure"/></runstats></nmaprun>', 'Test failure'),
])
def test_nmap_failure_without_stderr_keeps_exit_reason(monkeypatch, code, output, expected):
    class Process:
        returncode = code
        async def communicate(self):
            return output, b''
    async def spawn(*args, **kwargs):
        return Process()
    monkeypatch.setattr(discovery.asyncio, 'create_subprocess_exec', spawn)
    with pytest.raises(ValueError, match=expected):
        asyncio.run(discovery.run_nmap(['nmap'], 1))


def test_streamed_progress_handles_split_xml_and_preserves_evidence():
    async def exercise():
        updates = []
        class Process:
            stdout = asyncio.StreamReader()
            stderr = asyncio.StreamReader()
            async def wait(self):
                return 0
        process = Process()
        raw = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><taskbegin task="Connect Scan"/><taskprogress task="Connect Scan" percent="63.20"/><taskend task="Connect Scan"/><taskbegin task="Service scan"/><taskprogress task="Service scan" percent="nan"/><runstats><finished exit="success"/></runstats></nmaprun>'''
        consumer = asyncio.create_task(discovery.read_scan_stream(process, updates.append))
        for i in range(0, len(raw), 17):
            process.stdout.feed_data(raw[i:i+17])
            await asyncio.sleep(0)
        process.stdout.feed_eof()
        process.stderr.feed_data(b'warning')
        process.stderr.feed_eof()
        output, error = await consumer
        assert output == raw
        assert error == b'warning'
        assert updates[1] == {'phase': 'Connect Scan', 'percent': 63.2}
        assert updates[3] == {'phase': 'Service scan', 'percent': None}
        assert updates[4]['percent'] is None
    asyncio.run(exercise())


def test_streamed_scan_cancellation_kills_process(monkeypatch):
    async def exercise():
        class Process:
            returncode = None
            stdout = asyncio.StreamReader()
            stderr = asyncio.StreamReader()
            def kill(self):
                self.returncode = -9
            async def communicate(self):
                return b'', b''
        process = Process()
        async def spawn(*args, **kwargs):
            return process
        monkeypatch.setattr(discovery.asyncio, 'create_subprocess_exec', spawn)
        task = asyncio.create_task(discovery.run_nmap(['nmap'], 30, on_progress=lambda value: None))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert process.returncode == -9
    asyncio.run(exercise())
