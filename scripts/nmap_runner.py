"""Bounded Nmap jobs with fixed arguments, no shell, and no elevation."""
import asyncio
import ipaddress
import os
import shutil
import re
import socket
import signal
import math
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError


MAX_HOSTS = int(os.environ.get('KISS_DISCOVERY_MAX_HOSTS', '4096'))
TIMEOUT = 180


def discovery_command(cidr, dns_server=None):
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4:
        raise ValueError('Automatic discovery supports IPv4 subnets. Import an IPv6 discovery scan instead.')
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f'Automatic discovery is limited to {MAX_HOSTS:,} addresses per subnet. Add a smaller subnet or import a scan.')
    executable = shutil.which('nmap')
    if not executable:
        raise ValueError('Nmap is not installed on the server. Install nmap, then retry discovery.')
    dns_server, _ = validate_dns(dns_server, None)
    dns_flags = ['--dns-servers', dns_server] if dns_server else ['-n']
    return [executable, '-sn', *dns_flags, '--max-retries', '1', '--host-timeout', '15s', '-oX', '-', str(network)]


async def run_discovery(cidr, dns_server=None):
    command = discovery_command(cidr, dns_server) if dns_server else discovery_command(cidr)
    return await run_nmap(command, TIMEOUT)


class ProgressTarget:
    """Read Nmap task events without building an XML tree."""
    def __init__(self, callback):
        self.callback = callback

    def start(self, tag, attrs):
        if tag not in {'taskbegin', 'taskprogress', 'taskend'}:
            return
        phase = attrs.get('task', 'Scanning')[:100]
        percent = None
        if tag == 'taskprogress':
            try:
                candidate = float(attrs.get('percent', ''))
                if math.isfinite(candidate) and 0 <= candidate <= 100:
                    percent = round(candidate, 1)
            except ValueError:
                pass
        if tag == 'taskend':
            phase = 'Finishing ' + phase
        self.callback({'phase': phase, 'percent': percent})

    def end(self, tag):
        pass

    def data(self, data):
        pass

    def close(self):
        pass


async def read_scan_stream(process, on_progress):
    parser = ElementTree.DefusedXMLParser(target=ProgressTarget(on_progress))
    async def stdout():
        chunks, size = [], 0
        while chunk := await process.stdout.read(65536):
            size += len(chunk)
            if size > 20 * 1024 * 1024:
                raise ValueError('Nmap output exceeds the 20 MB import limit.')
            chunks.append(chunk)
            parser.feed(chunk)
        return b''.join(chunks)

    async def stderr():
        tail = b''
        while chunk := await process.stderr.read(65536):
            tail = (tail + chunk)[-65536:]
        return tail

    tasks = [asyncio.create_task(stdout()), asyncio.create_task(stderr())]
    try:
        output, error = await asyncio.gather(*tasks)
        await process.wait()
        return output, error
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_nmap(command, timeout, on_progress=None):
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        output, error = await asyncio.wait_for(read_scan_stream(process, on_progress) if on_progress else process.communicate(), timeout=timeout)
        if len(output) > 20 * 1024 * 1024:
            raise ValueError('Nmap output exceeds the 20 MB import limit.')
        if process.returncode:
            if process.returncode < 0:
                try:
                    reason = f'terminated by {signal.Signals(-process.returncode).name}'
                except ValueError:
                    reason = f'terminated by signal {-process.returncode}'
            else:
                reason = f'exit code {process.returncode}'
            detail = error.decode(errors='replace').strip()
            if not detail:
                try:
                    finished = ElementTree.fromstring(output).find('runstats/finished')
                    detail = finished.get('errormsg', '') if finished is not None else ''
                except (ParseError, DefusedXmlException):
                    pass
            raise ValueError(f'Nmap failed ({reason}): {detail[:280] or "No diagnostic output was returned."}')
        return output
    except TimeoutError:
        raise ValueError(f'Nmap exceeded {timeout} seconds. Retry or import a manual scan.')
    finally:
        if process.returncode is None:
            process.kill()
            await process.communicate()


def validate_dns(server, zone):
    server = (server or '').strip()
    zone = (zone or '').strip().rstrip('.').lower()
    if server:
        try:
            server = str(ipaddress.IPv4Address(server))
        except ValueError:
            raise ValueError('Enter an IPv4 address for the DNS server.')
    if zone:
        if not server:
            raise ValueError('A DNS server IP is required for a zone transfer.')
        if len(zone) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in zone.split('.')):
            raise ValueError('Enter a DNS zone such as corp.local.')
    return server, zone


def zone_command(server, zone):
    server, zone = validate_dns(server, zone)
    if not server or not zone:
        raise ValueError('Both DNS server IP and zone are required.')
    executable = shutil.which('nmap')
    if not executable:
        raise ValueError('Nmap is not installed on the server.')
    # Prerule performs only AXFR. No targets and no newtargets argument means
    # transferred addresses never become an implicit Nmap scan queue.
    return [executable, '-sn', '-n', '--script', 'dns-zone-transfer',
            '--script-args', f'dns-zone-transfer.server={server},dns-zone-transfer.domain={zone}',
            '--script-timeout', '25s', '-oX', '-']


def parse_zone(raw, cidr, zone):
    root = ElementTree.fromstring(raw)
    script = root.find(".//script[@id='dns-zone-transfer']")
    if script is None:
        raise ValueError('The server returned no zone transfer records.')
    rows = [line.split(maxsplit=2) for line in script.get('output', '').splitlines()]
    rows = [(row[0].rstrip('.').lower(), row[1], row[2].strip()) for row in rows if len(row) == 3]
    # A complete transfer is framed by opening and closing SOA records.
    if sum(name == zone and kind == 'SOA' for name, kind, _ in rows) < 2:
        raise ValueError('Zone transfer was refused, incomplete, or returned no records.')
    network = ipaddress.ip_network(cidr)
    names = {}
    aliases = {}
    for name, kind, value in rows:
        if name != zone and not name.endswith('.' + zone):
            continue
        if kind in {'A', 'AAAA'}:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address in network:
                names.setdefault(name, set()).add(str(address))
        elif kind == 'CNAME':
            aliases[name] = value.rstrip('.').lower()
    for alias, target in aliases.items():
        visited = {alias}
        while target in aliases and target not in visited:
            visited.add(target)
            target = aliases[target]
        if target in names:
            names.setdefault(alias, set()).update(names[target])
    by_address = {}
    for name, addresses in names.items():
        for address in addresses:
            by_address.setdefault(address, []).append(name)
    hosts = []
    for address, hostnames in by_address.items():
        hostnames.sort(key=lambda name: (name == zone, name in aliases, name))
        hosts.append({'address': address, 'hostname': hostnames[0], 'aliases': hostnames[1:]})
    return hosts


async def run_zone_transfer(cidr, server, zone):
    raw = await run_nmap(zone_command(server, zone), 30)
    try:
        return parse_zone(raw, cidr, zone), raw
    except (ParseError, DefusedXmlException) as exc:
        raise ValueError('Could not read zone transfer XML.') from exc


PORT_SCAN_TIMEOUT = int(os.environ.get('KISS_PORT_SCAN_TIMEOUT', '3600'))


def port_scan_command(address):
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        raise ValueError('Port scans require one resolved IP address.')
    executable = shutil.which('nmap')
    if not executable:
        raise ValueError('Nmap is not installed on the server.')
    return [executable, *(['-6'] if target.version == 6 else []), '-sT', '-Pn', '-n', '-p-', '-sCV', '--script', 'default,smb-os-discovery,rdp-ntlm-info', '--stats-every', '5s', '-oX', '-', str(target)]


async def run_port_scan(address, on_progress=None):
    try:
        target = str(ipaddress.ip_address(address))
    except ValueError:
        if len(address) > 253 or not any(c.isalpha() for c in address) or any(
            not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
            for label in address.rstrip('.').split('.')
        ):
            raise ValueError('Invalid host address.')
        # Resolve once, then pass exactly one literal IP to Nmap.
        try:
            results = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(address, None, type=socket.SOCK_STREAM), 10)
        except (OSError, TimeoutError) as exc:
            raise ValueError('The server could not resolve this hostname. Add its IP or import a scan first.') from exc
        results.sort(key=lambda result: result[0] != socket.AF_INET)
        if not results:
            raise ValueError('No IP address was returned for this hostname.')
        target = results[0][4][0]
    return await run_nmap(port_scan_command(target), PORT_SCAN_TIMEOUT, on_progress=on_progress), target
