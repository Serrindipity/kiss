from scripts.nmap_xml import parse_scan
from scripts.evidence import scan_text


def scan(content):
    return f'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/>{content}</host><runstats><finished time="1"/></runstats></nmaprun>'.encode()


def os_info(content):
    return parse_scan(scan(content))[0][0]['os']


def test_explicit_smb_os_preferred_to_build_guess():
    result = os_info('<hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019 Standard"/><script id="rdp-ntlm-info" output="Product_Version: 10.0.17763"/></hostscript>')
    assert result['name'] == 'Windows Server 2019 Standard'
    assert result['method'] == 'reported'


def test_shared_build_does_not_claim_server():
    result = os_info('<hostscript><script id="rdp-ntlm-info" output="Product_Version: 10.0.17763"/></hostscript>')
    assert result['method'] == 'inferred'
    assert 'Server 2019' in result['name'] and 'Windows 10' in result['name']
    assert result['evidence'] == '10.0.17763'


def test_unknown_build_preserved_without_guessing_release():
    result = os_info('<hostscript><script id="rdp-ntlm-info" output="Product_Version: 10.0.99999"/></hostscript>')
    assert result['name'] == 'Windows (build 10.0.99999; release unknown)'


def test_ports_alone_do_not_prove_windows():
    assert os_info('<ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" method="table"/></port></ports>') is None


def test_os_fingerprint_preserves_accuracy():
    result = os_info('<os><osmatch name="Linux 5.x" accuracy="95"/></os>')
    assert result['name'] == 'Linux 5.x' and result['method'] == 'fingerprint'
    assert result['accuracy'] == 95


def test_inference_in_text_evidence_and_port_scripts():
    raw = scan('<ports><port protocol="tcp" portid="3389"><state state="open"/><script id="rdp-ntlm-info" output="Product_Version: 10.0.20348"/></port></ports>')
    assert 'OS (inferred): Windows Server 2022' in scan_text(raw)
    assert 'rdp-ntlm-info' in scan_text(raw)
