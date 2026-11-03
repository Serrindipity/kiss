# Standalone server scripts

Run from the repository root, using the app's Python environment. Nmap must be installed. These commands save files without changing the web database; the web backend imports the same runners from this package.

```bash
# Discover responding hosts
.venv/bin/python -m scripts.scan sweep 10.20.0.0/24 --output /tmp/kiss-sweep

# AXFR first, then discovery with reverse DNS if unavailable
.venv/bin/python -m scripts.scan dns 10.20.0.0/24 \
  --dns-server 10.20.0.10 --zone lab.local --output /tmp/kiss-dns

# All TCP ports, service detection and Nmap default scripts on one box
.venv/bin/python -m scripts.scan ports 10.20.0.10 --output /tmp/kiss-ports

# Common exposure checks on one literal IP
.venv/bin/python -m scripts.common_checks 10.20.0.10 --output /tmp/kiss-checks
```

Each output directory must be new. Results include readable `scan.txt` (or `zone-transfer.txt`), retained Nmap XML, and `results.json`. Text evidence is rendered from XML, including service details and script output. Common checks also produce `checks.txt` with classifications and supplemental SMB/WinRM evidence. The web UI opens evidence as plain text, including for older scans. Ordinary `scan.xml` files can be imported through the existing UI; this imports hosts/services, not automatic vulnerability reports. AXFR XML is separate evidence. DNS only adds records within the supplied subnet. Discovery supports IPv4 subnets, capped at 4,096 addresses by default. Port scans also support IPv6 and resolve hostnames to one address.

## Common checks

Default TCP ports: 21, 389, 445, 636, 3389, 5985, 5986, 6379, 27017. Override with `--ports 21,445,3389`. Nmap service detection may recognize services on other selected ports; the supplemental SMB and WinRM checks use their standard ports.

| Service | Checks |
| --- | --- |
| FTP | Anonymous login and a bounded directory listing |
| SMB | SMBv1, signing requirement, unauthenticated share names and root directory listings |
| LDAP/LDAPS | RootDSE metadata and up to five user directory entries without credentials |
| RDP | Supported security layers, including negotiation without NLA |
| WinRM | Authentication challenge and WS-Man Identify only |
| Redis | INFO accessible without credentials |
| MongoDB | Database names accessible without credentials |

SMB share checks additionally require **smbclient** (Debian/Ubuntu: `sudo apt install smbclient`). Without it, those checks are explicitly skipped; Nmap SMB configuration checks still run. SMB directory checks negotiate SMB2 or newer and inspect at most five shares. Guest mapping may be responsible for unauthenticated access. Share names alone do not prove file access, and directory listings do not prove file contents are readable. No write tests are performed. In particular, this script avoids Nmap's `smb-enum-shares`, which can test write access by creating a file.

Outcomes are `exposure` (specific data returned without credentials), `review` (configuration worth investigating), `observation`, `inconclusive`, or `skipped`. They are evidence for manual reporting, not severity ratings. Denied requests, missing script output, TLS errors and timeouts do not certify a system as secure. A successful anonymous LDAP bind or RootDSE query alone is not classified as directory exposure. RDP negotiation and WinRM Identify do not establish desktop or shell access. HTTPS certificates are verified.

Common checks use an explicit script list, with no password guessing, supplied credentials, exploitation, writes, or remote command execution. They still make active network requests and may appear in service logs. The separate `ports` command retains the app's broader `-sCV` default-script behavior. Checks have a ten-minute Nmap limit and bounded supplemental request timeouts; Ctrl-C cancels the running job.

Implementation: `nmap_runner.py` runs discovery, AXFR and port scans; `nmap_xml.py` parses scan imports; `scan.py` provides the CLI; `common_checks.py` collects and classifies exposure evidence.

References: [Nmap SMB share script](https://nmap.org/nsedoc/scripts/smb-enum-shares.html), [LDAP search](https://nmap.org/nsedoc/scripts/ldap-search.html), [RDP encryption enumeration](https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html).

Port scans include SMB OS discovery and RDP NTLM information alongside the default NSE scripts. OS summaries appear in `results.json`, readable scan evidence, and the host details after import. Explicit SMB OS reports take priority, followed by imported Nmap OS fingerprints and then inferred NTLM builds/service OS hints. Shared Windows desktop/Server builds show both possibilities; unknown builds stay unknown. These probes do not require root or credentials, but services may refuse to disclose their OS. No OS inference is made from port numbers alone. Existing saved XML gains the summary in the scan viewer; host summaries populate on new scans/imports.
