"""Conservative OS summaries from existing Nmap evidence; no port-only guesses."""
import re

# Server builds: https://learn.microsoft.com/windows/release-health/windows-server-release-info
# Shared desktop/server builds intentionally retain both possibilities.
WINDOWS_BUILDS = {
    '10.0.14393': 'Windows Server 2016 / Windows 10 1607',
    '10.0.17763': 'Windows Server 2019 / Windows 10 1809',
    '10.0.20348': 'Windows Server 2022',
    '10.0.26100': 'Windows Server 2025 / Windows 11 24H2',
}


def infer_os(host):
    scripts = host.findall('hostscript/script') + host.findall('ports/port/script')
    for script in scripts:
        if script.get('id') != 'smb-os-discovery':
            continue
        value = script.find("elem[@key='os']")
        match = re.search(r'^\s*OS:\s*([^\r\n]+)', script.get('output', ''), re.M)
        name = (value.text if value is not None else '') or (match.group(1) if match else '')
        if name.strip() and name.strip().lower() not in {'unknown', '<unknown>'}:
            return {'name': name.strip(), 'method': 'reported', 'source': 'smb-os-discovery'}

    matches = host.findall('os/osmatch')
    if matches:
        best = max(matches, key=lambda item: int(item.get('accuracy', '0')))
        if best.get('name'):
            return {'name': best.get('name'), 'method': 'fingerprint', 'source': 'Nmap OS detection',
                    'accuracy': int(best.get('accuracy', '0'))}

    versions = {}
    for script in scripts:
        if script.get('id') not in {'rdp-ntlm-info', 'http-ntlm-info', 'smb-os-discovery'}:
            continue
        match = re.search(r'\bProduct_Version:\s*(\d+\.\d+\.\d+)\b', script.get('output', ''))
        if match:
            versions[match.group(1)] = script.get('id')
    if len(versions) > 1:
        return {'name': 'Windows (conflicting build reports)', 'method': 'inferred',
                'source': ', '.join(sorted(set(versions.values()))), 'evidence': ', '.join(sorted(versions))}
    if versions:
        version, source = next(iter(versions.items()))
        return {'name': WINDOWS_BUILDS.get(version, f'Windows (build {version}; release unknown)'),
                'method': 'inferred', 'source': source, 'evidence': version}

    # Only trust a probed service's OS hint, not a name assigned from its port.
    families = {service.get('ostype') for service in host.findall('ports/port/service')
                if service.get('method') == 'probed' and service.get('ostype')}
    if families:
        return {'name': ' / '.join(sorted(families)), 'method': 'inferred', 'source': 'Service OS hints'}
    return None
