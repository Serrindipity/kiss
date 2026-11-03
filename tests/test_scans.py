import pytest
from defusedxml.common import DefusedXmlException

from scripts.nmap_xml import parse_scan, service_group


def xml(ports='', extra='', finished='exit="success" time="1700000010"'):
    return f'<nmaprun><host><status state="up"/><address addr="10.20.0.10" addrtype="ipv4"/><ports>{ports}</ports>{extra}</host><runstats><finished {finished}/></runstats></nmaprun>'.encode()


def test_only_probed_services_are_grouped():
    assert service_group('msrpc', 'probed') == 'Microsoft RPC'
    assert service_group('msrpc', 'table') == 'Other / unidentified'
    assert service_group('unknown', 'probed') == 'Other / unidentified'
    assert service_group('ldap', 'probed') == 'Directory services'
    assert service_group('microsoft-ds', 'probed') == 'SMB'
    assert service_group('smtp', 'probed') == 'Mail'


def test_discovery_scan_does_not_invent_ports():
    hosts, timestamp = parse_scan(xml())
    assert hosts[0]['ports'] == []
    assert hosts[0]['reachability'] == 'up'
    assert timestamp == '2023-11-14T22:13:30+00:00'


def test_closed_and_uncertain_ports_retain_states():
    hosts, _ = parse_scan(xml('''
    <port protocol="tcp" portid="445"><state state="closed"/></port>
    <port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain" method="table"/></port>
    '''))
    assert [p['state'] for p in hosts[0]['ports']] == ['closed', 'open|filtered']
    assert hosts[0]['ports'][1]['group'] == 'Other / unidentified'


def test_scripts_and_versions_remain_evidence():
    hosts, _ = parse_scan(xml('''<port protocol="tcp" portid="443"><state state="open"/>
    <service name="http" method="probed" product="nginx" version="1.25"/>
    <script id="http-title" output="&lt;script&gt;alert(1)&lt;/script&gt;"/></port>''',
    '<hostscript><script id="msrpc-enum" output="tcp_port: 49664"/></hostscript>'))
    assert hosts[0]['ports'][0]['version'] == '1.25'
    assert hosts[0]['ports'][0]['scripts'][0]['output'] == '<script>alert(1)</script>'
    assert hosts[0]['scripts'][0]['id'] == 'msrpc-enum'


@pytest.mark.parametrize('port,protocol', [('0', 'tcp'), ('65536', 'tcp'), ('443', 'bad')])
def test_invalid_ports_rejected(port, protocol):
    with pytest.raises(ValueError):
        parse_scan(xml(f'<port protocol="{protocol}" portid="{port}"><state state="open"/></port>'))


def test_failed_scan_rejected():
    with pytest.raises(ValueError, match='failed scan'):
        parse_scan(xml(finished='exit="error"'))


def test_external_entities_rejected():
    with pytest.raises(DefusedXmlException):
        parse_scan(b'<!DOCTYPE nmaprun [<!ENTITY bad SYSTEM "file:///etc/passwd">]><nmaprun>&bad;</nmaprun>')
