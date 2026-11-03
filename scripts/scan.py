"""Standalone scan entry points: python -m scripts.scan --help."""
import argparse
import asyncio
import json
import sys
from pathlib import Path

from .nmap_runner import run_discovery, run_port_scan, run_zone_transfer, validate_dns, discovery_command
from .nmap_xml import parse_scan
from .evidence import scan_text


def write_report(directory, name, raw, result):
    (directory / name).write_bytes(raw)
    (directory / Path(name).with_suffix(".txt")).write_text(scan_text(raw))
    (directory / 'results.json').write_text(json.dumps(result, indent=2) + '\n')


async def execute(args):
    if args.command == 'ports':
        raw, address = await run_port_scan(args.target)
        hosts, timestamp = parse_scan(raw)
        return 'scan.xml', raw, {'method': 'port-scan', 'target': address, 'scanned_at': timestamp, 'hosts': hosts}
    server, zone = validate_dns(args.dns_server, getattr(args, 'zone', ''))
    discovery_command(args.target, server)  # Validate subnet and size before contacting DNS.
    fallback = None
    if args.command == 'dns':
        if not server or not zone:
            raise ValueError('DNS discovery requires --dns-server and --zone.')
        try:
            hosts, raw = await run_zone_transfer(args.target, server, zone)
            return 'zone-transfer.xml', raw, {'method': 'zone-transfer', 'network': args.target, 'dns_server': server, 'zone': zone, 'hosts': hosts}
        except (ValueError, OSError) as exc:
            fallback = str(exc)
    raw = await run_discovery(args.target, server)
    hosts, timestamp = parse_scan(raw, allow_empty=True)
    return 'scan.xml', raw, {'method': 'reverse-dns' if server else 'host-discovery', 'network': args.target,
                             'dns_server': server, 'fallback_reason': fallback, 'scanned_at': timestamp, 'hosts': hosts}


def main():
    parser = argparse.ArgumentParser(description='Standalone KISS network scripts. Results do not modify the web database.')
    commands = parser.add_subparsers(dest='command', required=True)
    for name, help_text in [('sweep', 'Discover responding hosts in a subnet'), ('ports', 'Scan all TCP ports and default scripts on one host'), ('dns', 'Try AXFR, then fall back to a sweep with reverse DNS')]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument('target', help='Single host for ports; IPv4 subnet for sweep/dns')
        command.add_argument('--output', type=Path, required=True, help='New output directory; existing directories are never overwritten')
        if name != 'ports':
            command.add_argument('--dns-server', default='')
        if name == 'dns':
            command.add_argument('--zone', required=True)
    args = parser.parse_args()
    try:
        args.output.mkdir(parents=True, exist_ok=False)
        name, raw, result = asyncio.run(execute(args))
        write_report(args.output, name, raw, result)
        print(f"Saved {name}, text evidence and results.json in {args.output}")
        return 0
    except (ValueError, OSError) as exc:
        print(f'Scan failed: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Scan cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
