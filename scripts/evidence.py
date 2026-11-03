"""Readable evidence rendered from retained Nmap XML (not original stdout)."""
from defusedxml import ElementTree
from .os_inference import infer_os


def scan_text(raw):
    root = ElementTree.fromstring(raw)
    if root.tag != 'nmaprun':
        raise ValueError('Expected Nmap XML.')
    lines = ['Nmap scan evidence', 'Rendered from retained Nmap XML.', '']
    for key in ('args', 'version', 'startstr'):
        if root.get(key):
            lines.append(f'{key}: {root.get(key)}')

    def detail(node, indent=''):
        # Script output already contains the readable NSE representation.
        if node.tag == 'script' and node.get('output') is not None:
            lines.append(f"{indent}{node.get('id', 'script')}:")
            lines.extend(indent + '  ' + line for line in node.get('output').splitlines())
            return
        attributes = ', '.join(f'{key}={value}' for key, value in node.attrib.items())
        text = (node.text or '').strip()
        lines.append(f'{indent}{node.tag}' + (f': {attributes}' if attributes else '') + (f' {text}' if text else ''))
        for child in node:
            detail(child, indent + '  ')

    for node in root:
        lines.append('')
        if node.tag == 'host':
            addresses = [a.get('addr', '') for a in node.findall('address')]
            names = [n.get('name', '') for n in node.findall('hostnames/hostname')]
            lines.append('Host: ' + ', '.join(addresses + names))
            os_info = infer_os(node)
            if os_info:
                lines.append(f"OS ({os_info['method']}): {os_info['name']}")
                lines.append(f"  Source: {os_info['source']}" + (f"; build: {os_info['evidence']}" if os_info.get('evidence') else '') + (f"; Nmap accuracy: {os_info['accuracy']}%" if 'accuracy' in os_info else ''))
            for child in node:
                if child.tag == 'ports':
                    for port in child:
                        if port.tag != 'port':
                            detail(port)
                            continue
                        state = port.find('state')
                        service = port.find('service')
                        lines.append(f"{port.get('portid')}/{port.get('protocol')}  {state.get('state', 'unknown') if state is not None else 'unknown'}  {service.get('name', '') if service is not None else ''}")
                        for item in port:
                            detail(item, '  ')
                else:
                    detail(child)
        else:
            detail(node)
    return '\n'.join(lines) + '\n'
