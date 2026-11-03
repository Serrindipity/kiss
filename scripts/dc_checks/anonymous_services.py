"""Adapt KISS's bounded anonymous-service checks into automation evidence."""
import asyncio
import socket
import sys
from pathlib import Path

from scripts.common_checks import run_checks, DEFAULT_PORTS
from scripts.evidence import scan_text


def collect_anonymous_services(runner):
    if runner.args.plan:
        runner.run('anonymous-services', [sys.executable, '-m', 'scripts.common_checks', runner.args.dc,
                   '--output', str(runner.out / 'anonymous-services')],
                   note='FTP, SMB, LDAP/LDAPS, RDP, WinRM, Redis and MongoDB. Read-only checks on common ports.')
        return
    try:
        address = socket.gethostbyname(runner.args.dc)
        report, raw = asyncio.run(run_checks(address))
        (runner.out / 'anonymous-services.xml').write_bytes(raw)
        (runner.out / 'anonymous-services.txt').write_text(scan_text(raw))
        for index, check in enumerate(report['checks']):
            status = 'not_tested' if check['outcome'] == 'skipped' else 'partial' if check['outcome'] == 'inconclusive' else 'completed'
            runner.results.append({'id': f'anonymous-service-{index}', 'status': status,
                                   'target': address, 'identity': 'anonymous',
                                   'title': check['title'], 'service': check['service'], 'port': check['port'],
                                   'outcome': check['outcome'], 'source': check['source'],
                                   'stdout_text': check['evidence'], 'assessment': 'requires_review'})
        for port in DEFAULT_PORTS:
            if port not in report['open_ports']:
                runner.results.append({'id': f'anonymous-service-port-{port}', 'status': 'completed',
                                       'target': address, 'port': port, 'outcome': 'observation',
                                       'title': f'TCP {port}: not observed open', 'identity': 'anonymous'})
        runner.save()
    except (OSError, ValueError, TimeoutError) as exc:
        runner.results.append({'id': 'anonymous-services', 'status': 'error', 'error': str(exc),
                               'target': runner.args.dc, 'identity': 'anonymous'})
        runner.save()
