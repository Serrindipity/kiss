"""Parse Nmap evidence without inferring services solely from port numbers."""
import ipaddress
from datetime import datetime, timezone
from defusedxml import ElementTree
from .os_inference import infer_os


def service_group(name, method):
    if method != 'probed':
        return 'Other / unidentified'
    name = name.lower()
    if name in {'msrpc', 'ncacn_http'}:
        return 'Microsoft RPC'
    if name in {'microsoft-ds', 'netbios-ssn'}:
        return 'SMB'
    if name in {'ldap', 'ldaps', 'kerberos-sec', 'kpasswd5', 'kerberos'}:
        return 'Directory services'
    if 'http' in name:
        return 'Web'
    if name in {'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s'}:
        return 'Mail'
    return {'ssh': 'SSH', 'domain': 'DNS', 'ms-wbt-server': 'Remote desktop'}.get(name, 'Other / unidentified')


def parse_scan(data, allow_empty=False):
    root = ElementTree.fromstring(data)
    if root.tag != 'nmaprun' or root.find('runstats/finished') is None:
        raise ValueError('Upload a completed Nmap XML scan (use -oX).')
    finished = root.find('runstats/finished')
    if finished.get('exit', 'success') != 'success':
        raise ValueError('Nmap reported a failed scan. Import a completed scan.')
    timestamp = int(finished.get('time', root.get('start', '0')))
    scanned_at = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    hosts = []
    for node in root.findall('host'):
        address = next((a.get('addr') for a in node.findall('address') if a.get('addrtype') in {'ipv4', 'ipv6'}), None)
        if not address:
            continue
        address = str(ipaddress.ip_address(address))
        hostname = node.find('hostnames/hostname')
        ports = []
        for port in node.findall('ports/port'):
            state = port.find('state')
            if state is None:
                continue
            number = int(port.get('portid', '0'))
            protocol = port.get('protocol')
            if not 1 <= number <= 65535 or protocol not in {'tcp', 'udp', 'sctp'}:
                raise ValueError('Invalid port in scan.')
            service = port.find('service')
            attrs = dict(service.attrib) if service is not None else {}
            name = attrs.get('name', 'unknown')
            ports.append({'port': number, 'protocol': protocol, 'state': state.get('state'), 'service': name,
                          'method': attrs.get('method', 'unknown'), 'tunnel': attrs.get('tunnel', ''), 'product': attrs.get('product', ''),
                          'version': attrs.get('version', ''), 'group': service_group(name, attrs.get('method')),
                          'scripts': [{'id': s.get('id'), 'output': s.get('output', '')} for s in port.findall('script')],
                          'scanned_at': scanned_at})
        status = node.find('status')
        hosts.append({'port_scanned': node.find('ports') is not None, 'address': address, 'hostname': hostname.get('name', '') if hostname is not None else '',
                      'os': infer_os(node),
                      'reachability': status.get('state', 'unknown') if status is not None else 'unknown',
                      'ports': ports, 'scripts': [{'id': s.get('id'), 'output': s.get('output', '')} for s in node.findall('hostscript/script')]})
    if not hosts and not allow_empty:
        raise ValueError('No IP hosts found in this scan.')
    return hosts, scanned_at
