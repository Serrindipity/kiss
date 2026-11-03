"""Bounded, read-only common exposure checks; no credentials or exploits."""
import argparse
import asyncio
from datetime import datetime, timezone
import http.client
import ipaddress
import json
from pathlib import Path
import re
import shutil
import ssl
import sys

from defusedxml import ElementTree
from .nmap_runner import run_nmap
from .evidence import scan_text

DEFAULT_PORTS = (21, 389, 445, 636, 3389, 5985, 5986, 6379, 27017)
NSE_SCRIPTS = ('ftp-anon', 'smb-protocols', 'smb2-security-mode', 'ldap-rootdse', 'ldap-search',
               'rdp-enum-encryption', 'redis-info', 'mongodb-databases')
MAX_EVIDENCE = 16000


def result(service, port, outcome, title, evidence='', source='nmap'):
    return {'service': service, 'port': port, 'outcome': outcome, 'title': title,
            'evidence': evidence[:MAX_EVIDENCE], 'source': source}


def parse_ports(value):
    try:
        ports = sorted(set(int(part.strip()) for part in value.split(',')))
        if not ports or len(ports) > 100 or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError()
        return ports
    except ValueError:
        raise argparse.ArgumentTypeError('Use up to 100 comma-separated TCP port numbers (1–65535).')


def check_command(target, ports):
    address = ipaddress.ip_address(target)
    executable = shutil.which('nmap')
    if not executable:
        raise ValueError('Install Nmap to run common checks.')
    return [executable, *(['-6'] if address.version == 6 else []), '-sT', '-Pn', '-n', '-sV', '--version-light',
            '-p', ','.join(map(str, ports)), '--script', ','.join(NSE_SCRIPTS),
            '--script-args', 'ldap.maxobjects=5,ldap.qfilter=users,ldap.attrib=sAMAccountName,ftp-anon.maxlist=5',
            '--script-timeout', '30s', '-oX', '-', str(address)]


def classify(script, output, port):
    """Positive evidence only. Silence and script errors never mean secure."""
    text = output.lower()
    if re.search(r'(^|\n)\s*(error|failed|could not)\b', text):
        return result(script, port, 'inconclusive', 'Script did not complete successfully', output)
    if script == 'ftp-anon':
        positive = 'anonymous ftp login allowed' in text
        return result('FTP', port, 'exposure' if positive else 'inconclusive', 'Anonymous FTP login allowed' if positive else 'Anonymous FTP access not established', output)
    if script == 'smb-protocols':
        positive = 'nt lm 0.12' in text or 'smbv1' in text
        return result('SMB', port, 'review' if positive else 'observation', 'SMBv1 supported' if positive else 'SMB dialects observed', output)
    if script == 'smb2-security-mode':
        positive = 'not required' in text or 'disabled' in text
        return result('SMB', port, 'review' if positive else 'observation', 'SMB signing is not required' if positive else 'SMB signing configuration observed', output)
    if script == 'ldap-rootdse':
        return result('LDAP', port, 'observation', 'RootDSE metadata returned; not proof of directory access', output)
    if script == 'ldap-search':
        positive = bool(re.search(r'(^|\n)\s*dn:\s*\S+', output, re.I))
        return result('LDAP', port, 'exposure' if positive else 'inconclusive', 'Directory entries returned without credentials' if positive else 'Anonymous directory access not established', output)
    if script == 'rdp-enum-encryption':
        positive = bool(re.search(r'(^|\n)\s*(native rdp|ssl):\s*success', text))
        return result('RDP', port, 'review' if positive else 'observation', 'RDP accepts a non-NLA security layer' if positive else 'RDP security layers observed; no login attempted', output)
    if script == 'redis-info':
        positive = bool(re.search(r'\bversion\s+\d', text))
        return result('Redis', port, 'exposure' if positive else 'inconclusive', 'Redis INFO returned without credentials' if positive else 'Unauthenticated Redis INFO not established', output)
    if script == 'mongodb-databases':
        positive = bool(re.search(r'(^|\n)[ \t]*databases[ \t]*:?[ \t]*(?:\n|$)', text)) and not any(word in text for word in ['unauthorized', 'requires authentication', 'not authorized'])
        return result('MongoDB', port, 'exposure' if positive else 'inconclusive', 'MongoDB database list returned without credentials' if positive else 'Unauthenticated database listing not established', output)
    return result(script, port, 'observation', 'Script output', output)


def parse_checks(raw):
    root = ElementTree.fromstring(raw)
    finished = root.find('runstats/finished')
    if root.tag != 'nmaprun' or finished is None or finished.get('exit', 'success') != 'success':
        raise ValueError('Nmap did not return a completed scan.')
    checks, open_ports, observed = [], set(), set()
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            number = int(port.get('portid'))
            open_ports.add(number)
            for script in port.findall('script'):
                name = script.get('id')
                observed.add((number, name))
                checks.append(classify(name, script.get('output', ''), number))
        for script in host.findall('hostscript/script'):
            name = script.get('id')
            observed.add((445 if name.startswith('smb') else None, name))
            checks.append(classify(name, script.get('output', ''), 445 if name.startswith('smb') else None))
    return checks, open_ports, observed


async def smb_anonymous(target, port=445):
    executable = shutil.which('smbclient')
    if not executable:
        return [result('SMB', port, 'skipped', 'Install smbclient for read-only anonymous share checks', source='smbclient')]
    address = str(ipaddress.ip_address(target))
    options = ['-N', '-U', '%', '-p', str(port), '--option=client min protocol=SMB2']
    async def command(arguments):
        process = await asyncio.create_subprocess_exec(executable, *arguments, *options, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(process.communicate(), 20)
            return process.returncode, (out + err).decode(errors='replace')[:MAX_EVIDENCE]
        finally:
            if process.returncode is None:
                process.kill()
                await process.communicate()
    try:
        code, output = await command(['-g', '-L', address])
        if code:
            return [result('SMB', port, 'inconclusive', 'Unauthenticated share listing was denied or failed', output, 'smbclient')]
        shares = [line.split('|')[1] for line in output.splitlines() if line.startswith('Disk|') and len(line.split('|')) >= 2]
        checks = [result('SMB', port, 'exposure' if shares else 'observation', 'Share names listed without credentials' if shares else 'No disk shares listed without credentials', output, 'smbclient')]
        for share in shares[:5]:
            code, listing = await command([f'//{address}/{share}', '-c', 'ls'])
            readable = code == 0 and 'blocks of size' in listing
            checks.append(result('SMB', port, 'exposure' if readable else 'inconclusive', f'Unauthenticated root directory listing: {share}' if readable else f'Read access not established: {share}', listing, 'smbclient'))
        return checks
    except (OSError, TimeoutError) as exc:
        return [result('SMB', port, 'inconclusive', 'Anonymous SMB check failed', str(exc), 'smbclient')]


IDENTIFY = b'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><w:Identify/></s:Body></s:Envelope>'''


def winrm_identify(target, port):
    """Send only a WS-Man Identify request. Never create a shell or run commands."""
    address = str(ipaddress.ip_address(target))
    connection = http.client.HTTPSConnection(address, port, timeout=8, context=ssl.create_default_context()) if port == 5986 else http.client.HTTPConnection(address, port, timeout=8)
    try:
        connection.request('POST', '/wsman', body=IDENTIFY, headers={'Content-Type': 'application/soap+xml;charset=UTF-8'})
        response = connection.getresponse()
        body = response.read(MAX_EVIDENCE).decode(errors='replace')
        challenge = response.getheader('WWW-Authenticate', '')
        evidence = f'HTTP {response.status}\nWWW-Authenticate: {challenge}\n{body}'
        if response.status == 401:
            return result('WinRM', port, 'review' if port == 5985 and 'basic' in challenge.lower() else 'observation', 'Basic authentication advertised over HTTP' if port == 5985 and 'basic' in challenge.lower() else 'Authentication required by WS-Man endpoint', evidence, 'wsman-identify')
        if response.status == 200 and 'IdentifyResponse' in body:
            return result('WinRM', port, 'observation', 'Unauthenticated WS-Man identification; shell access not tested', evidence, 'wsman-identify')
        return result('WinRM', port, 'inconclusive', 'WS-Man authentication could not be determined', evidence, 'wsman-identify')
    except (OSError, http.client.HTTPException) as exc:
        return result('WinRM', port, 'inconclusive', 'WS-Man check failed (TLS certificates are verified)', str(exc), 'wsman-identify')
    finally:
        connection.close()


async def run_checks(target, ports=DEFAULT_PORTS):
    address = str(ipaddress.ip_address(target))
    raw = await run_nmap(check_command(address, ports), 600)
    checks, opened, observed = parse_checks(raw)
    expected = {21: ('ftp-anon',), 445: ('smb-protocols', 'smb2-security-mode'), 389: ('ldap-search',), 636: ('ldap-search',),
                3389: ('rdp-enum-encryption',), 6379: ('redis-info',), 27017: ('mongodb-databases',)}
    for port, scripts in expected.items():
        if port in opened:
            for script in scripts:
                if (port, script) not in observed:
                    checks.append(result(script, port, 'inconclusive', 'Open port, but no script result; not a clean bill of health'))
    if 445 in opened:
        checks.extend(await smb_anonymous(address))
    for port in (5985, 5986):
        if port in opened:
            checks.append(await asyncio.to_thread(winrm_identify, address, port))
    report = {'target': address, 'checked_at': datetime.now(timezone.utc).isoformat(), 'ports_checked': list(ports),
              'open_ports': sorted(opened), 'checks': checks,
              'limitations': ['No password guessing, credential reuse, exploitation, write tests, or remote command execution.',
                              'Missing/denied results are inconclusive, not proof that a service is secure.',
                              'SMB anonymous checks require smbclient and negotiate SMB2 or newer; guest mapping may occur.',
                              'LDAP RootDSE and successful anonymous bind alone do not prove directory data exposure.',
                              'RDP negotiation and WinRM Identify do not prove credential-free desktop or shell access.']}
    return report, raw


def main():
    parser = argparse.ArgumentParser(description='Read-only common exposure checks for one IP; save evidence for manual review.')
    parser.add_argument('target', help='One IPv4 or IPv6 address')
    parser.add_argument('--ports', type=parse_ports, default=DEFAULT_PORTS, help='Comma-separated TCP ports; default common service ports')
    parser.add_argument('--output', type=Path, required=True, help='New output directory')
    args = parser.parse_args()
    try:
        ipaddress.ip_address(args.target)
        args.output.mkdir(parents=True, exist_ok=False)
        report, raw = asyncio.run(run_checks(args.target, args.ports))
        (args.output / 'scan.xml').write_bytes(raw)
        (args.output / 'scan.txt').write_text(scan_text(raw))
        (args.output / 'checks.txt').write_text('\n\n'.join(
            f"{c['outcome'].upper()} {c['service']}:{c['port']} — {c['title']}\n{c['evidence']}"
            for c in report['checks']) + '\n')
        (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        for check in report['checks']:
            print(f"{check['outcome'].upper():12} {check['service']}:{check['port']}  {check['title']}")
        print(f'Evidence saved in {args.output}')
        return 0
    except (ValueError, OSError) as exc:
        print(f'Checks failed: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Checks cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
