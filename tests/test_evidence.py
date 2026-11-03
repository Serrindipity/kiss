from scripts.evidence import scan_text


def test_readable_ports_and_nested_evidence():
    raw = b'''<nmaprun args="nmap -sCV"><host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows"/><script id="smb-check" output="Signing enabled&#10;Not required"/></port></ports><hostscript><script id="structured"><table key="result"><elem key="name">example</elem></table></script></hostscript></host><runstats><finished exit="success"/></runstats></nmaprun>'''
    text = scan_text(raw)
    assert '445/tcp  open  microsoft-ds' in text
    assert 'product=Windows' in text
    assert 'Signing enabled\n    Not required' in text
    assert 'name example' in text
    assert '<nmaprun' not in text


def test_dns_script_evidence():
    text = scan_text(b'<nmaprun><prescript><script id="dns-zone-transfer" output="lab.local SOA example&#10;host.lab.local A 10.0.0.1"/></prescript></nmaprun>')
    assert 'host.lab.local A 10.0.0.1' in text


def test_discovery_is_not_a_port_scan():
    from scripts.nmap_xml import parse_scan
    base = '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>{}</host><runstats><finished time="1"/></runstats></nmaprun>'
    hosts, _ = parse_scan(base.format('').encode())
    assert not hosts[0]['port_scanned']
    hosts, _ = parse_scan(base.format('<ports><extraports state="closed" count="1000"/></ports>').encode())
    assert hosts[0]['port_scanned']
