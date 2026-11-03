export const checkTitles = {
  "ftp-anonymous": "Test FTP anonymous login and directory listing",
  "smb-anonymous": "Test SMB anonymous login and share access",
  "ldap-anonymous-389": "Test anonymous directory reads · LDAP 389",
  "ldap-anonymous-636": "Test anonymous directory reads · LDAPS 636",
  "rdp-anonymous": "Test Remote Desktop login with empty credentials · RDP",
  "winrm-anonymous": "Test Windows remote management login with empty credentials · WinRM",
  "rdp-account": "Test domain account login to Remote Desktop · RDP",
  "winrm-account": "Test domain account login to Windows remote management · WinRM",
  "ldap-account-389": "Test account access and list users · LDAP 389",
  "ldap-account-636": "Test account access and list users · LDAPS 636",
  "smb-shares": "List SMB shares and account permissions",
  "smb-password-policy": "Read domain password and lockout policy",
  "smb-users": "List domain users through SMB",
  "smb-rid-enumeration": "Enumerate account names by numeric ID · SMB RID lookup",
  "ldap-protections": "Check directory connection protections · LDAP signing and channel binding",
  "delegation": "Find accounts configured to impersonate other users · Kerberos delegation",
  "fine-grained-policy": "Read account-specific password policies",
  "adcs-discovery": "Find certificate authorities and certificate templates",
  "spooler": "Check whether Windows Print Spooler is available",
  "webdav": "Check for Windows WebClient / WebDAV service indicators",
  "endpoint-protection": "Look for antivirus and endpoint security product indicators",
  "zerologon": "Test domain controller authentication for Zerologon",
  "nopac": "Compare Kerberos ticket sizes for noPac indicators",
  "printnightmare": "Probe print driver RPC for PrintNightmare indicators",
  "smbghost": "Check SMB compression for SMBGhost indicators",
  "petitpotam": "Check file-encryption RPC authentication coercion · PetitPotam",
  "printerbug": "Check Print Spooler authentication coercion · PrinterBug",
  "dfscoerce": "Check distributed file service authentication coercion · DFSCoerce",
  "shadowcoerce": "Check shadow copy service authentication coercion · ShadowCoerce",
  "mseven": "Check Windows Event Log authentication coercion",
  "gpp-passwords": "Retrieve stored Group Policy passwords · GPP",
  "gpp-autologon": "Retrieve automatic-login credentials from Group Policy",
  "laps-passwords": "Retrieve readable local administrator passwords · LAPS",
  "gmsa-passwords": "Retrieve readable managed service-account secrets · gMSA",
  "asrep-roast": "Request tickets for accounts without preauthentication · AS-REP roasting",
  "kerberoast": "Request service-account tickets · Kerberoasting",
  "certipy-adcs": "Analyze certificate service misconfigurations · Certipy",
  "ms17-010": "Check for the SMB flaw used by EternalBlue · MS17-010",
  "dns-dc": "Look up domain controller DNS records",
  "dns-kerberos": "Look up Kerberos server DNS records",
  "dns-gc": "Look up global catalog server DNS records",
  "dns-axfr": "Attempt a DNS zone transfer",
  "services": "Scan common domain controller and management ports",
  "smb-protocols": "Check SMB versions and signing requirements",
  "smb-anonymous-shares": "Attempt anonymous SMB share listing",
  "rpc-anonymous": "Attempt anonymous account enumeration through Windows RPC",
  "smb-guest-shares": "Attempt SMB share listing as Guest with a blank password",
  "tls-rdp": "Inspect TLS certificates, ciphers and RDP encryption",
  "ldap-rootdse": "Read directory server metadata · LDAP RootDSE",
  "ldap-anonymous-directory": "Attempt anonymous LDAP directory reads",
  "ldap-authentication": "Test the supplied LDAP account",
  "domain-policy": "Read domain password and lockout policy",
  "fine-grained-policies": "Read account-specific password policies",
  "account-inventory": "List domain accounts and account settings",
  "account-notes": "Read account descriptions and notes",
  "kerberoast-candidates": "Find service accounts eligible for Kerberoasting",
  "asrep-candidates": "Find accounts with Kerberos preauthentication disabled",
  "password-not-required": "Find accounts marked password not required",
  "password-never-expires": "Find accounts with non-expiring passwords",
  "reversible-encryption": "Find accounts permitting reversible password storage",
  "des-only": "Find accounts restricted to legacy DES encryption",
  "kerberos-encryption": "Read configured Kerberos encryption types",
  "unconstrained-delegation": "Find accounts with unrestricted impersonation · Unconstrained delegation",
  "constrained-delegation": "Find accounts with service-specific impersonation · Constrained delegation",
  "rbcd": "Read resource-controlled impersonation permissions · RBCD",
  "key-credentials": "List account key-based authentication credentials",
  "groups": "List domain groups and membership",
  "trusts": "List trust relationships between domains",
  "gpos": "List Group Policy objects",
  "ou-policy-links": "List Group Policy links to organizational units",
  "computers": "List domain computers and password-management metadata",
  "gmsa-readers": "Read managed service-account password access permissions",
  "certificate-authorities": "List Active Directory certificate authorities",
  "certificate-templates": "Read certificate enrollment template settings",
  "sites-and-dcs": "Read domain controller directory topology",
  "ad-initialization": "Initialize the Windows Active Directory collector",
  "domain": "Read domain identity and configuration",
  "forest": "Read Active Directory forest configuration",
  "domain-controllers": "List domain controllers",
  "default-password-policy": "Read the default domain password policy",
  "effective-password-policies": "Read the password policy applied to each user",
  "accounts": "List domain accounts and account settings",
  "privileged-groups": "List privileged groups and their members",
  "domain-acl": "Read domain permissions, including replication rights",
  "sensitive-object-acls": "Read permissions on sensitive directory objects",
  "adcs-objects-and-acls": "Read certificate authority and template permissions",
  "sysvol-netlogon-acls": "Read SYSVOL and NETLOGON folder permissions",
  "local-host-identity": "Read the collector machine’s identity and Windows version",
  "local-hotfixes": "List updates installed on the collector machine",
  "local-smb-config": "Read the collector machine’s SMB configuration",
  "local-shares": "List the collector machine’s shares and permissions",
  "local-services": "List services on the collector machine",
  "local-security-settings": "Read security registry settings on the collector machine",
  "local-defender": "Read Microsoft Defender status on the collector machine",
  "local-firewall": "Read firewall profiles on the collector machine",
  "local-token-privileges": "List privileges of the collector’s Windows logon",
  "local-audit-policy": "Read audit policy on the collector machine",
  "anonymous-services": "Check common services without credentials",
  "interrupted": "Collection interrupted",
  "netexec-version": "Check the installed NetExec version"
};
export const humanLabel = value => String(value ?? '').replaceAll('-', ' ').replaceAll('_', ' ').replace(/\b(?:ldap|dns|smb|rpc|tls|rdp|gpo|spn|sysvol)\b/gi, word => word.toUpperCase()).replace(/^./, char => char.toUpperCase());
export function checkTitle(row) {
  const id = row.check_id || row.id || '';
  const coercion = { petitpotam: 'file-encryption RPC · PetitPotam', printerbug: 'Print Spooler · PrinterBug', dfscoerce: 'distributed file services · DFSCoerce', shadowcoerce: 'shadow copy services · ShadowCoerce', mseven: 'Windows Event Log' };
  if (coercion[id] && row.evidence_kind === 'rpc_interface_exposure') return `Check RPC interface exposure · ${coercion[id]}`;
  if (coercion[id] && row.evidence_kind === 'coercion_attempt') return `Attempt an authentication callback · ${coercion[id]}`;
  if (row.title || row.path) return row.title || row.path;
  const diagnostic = id.match(/^netexec-([a-z]+)-(modules|help)$/);
  if (diagnostic) return `Check installed NetExec ${diagnostic[1].toUpperCase()} ${diagnostic[2] === 'modules' ? 'modules' : 'command options'}`;
  const oldLdap = id.match(/^(ldap389|ldaps636)-(.+)$/);
  if (oldLdap) return `${checkTitles[oldLdap[2]] || humanLabel(oldLdap[2])} · ${oldLdap[1] === 'ldap389' ? 'LDAP 389' : 'LDAPS 636'}`;
  if (id.startsWith('authentication-')) return `Test supplied credentials · ${id.slice(15).toUpperCase()}`;
  return checkTitles[id] || humanLabel(id);
}
export function checkState(row) {
  if (row.reason === 'plan_only') return { label: 'Preview', tone: 'neutral' };
  return ({
    completed: { label: 'Finished', tone: 'neutral' },
    not_tested: { label: 'Skipped', tone: 'muted' },
    partial: { label: 'Partial results', tone: 'attention' },
    access_denied: { label: 'Access denied', tone: 'attention' },
    authentication_failed: { label: 'Sign-in failed', tone: 'attention' },
    error: { label: 'Error', tone: 'attention' }, timeout: { label: 'Timed out', tone: 'attention' },
  })[row.status] || { label: humanLabel(row.status) || 'Unknown', tone: 'neutral' };
}
export function checkSummary(row) {
  if (row.reason === 'plan_only') return 'Command preview; not executed';
  if (row.reason || row.error || row.parse_error) return row.reason || row.error || row.parse_error;
  if (row.status === 'not_tested') return 'Not run';
  if (row.status === 'authentication_failed') return 'The domain account could not sign in';
  if (row.status === 'access_denied') return 'The server denied this request';
  if (row.status === 'timeout') return 'The command reached its time limit';
  if (row.status === 'error') return 'The command failed; inspect the error output';
  if (row.evidence_kind === 'rpc_interface_exposure') return 'RPC exposure only; no callback attempted';
  if (row.evidence_kind === 'coercion_attempt') return 'Callback attempted; confirm with receiver evidence';
  if (typeof row.content === 'string' && !row.indicators) return 'Collected artifact available';
  if (Array.isArray(row.indicators)) return row.indicators.length ? `${row.indicators.length} secret indicators to review` : 'No indicators in this inspected file';
  if (Array.isArray(row.data)) return `${row.data.length} ${row.data.length === 1 ? 'record' : 'records'} returned${row.status === 'partial' ? ' (incomplete)' : ''}`;
  if (Array.isArray(row.data?.hosts)) {
    const ports = row.data.hosts.flatMap(host => Array.isArray(host?.ports) ? host.ports : []);
    const open = ports.filter(port => port?.state === 'open').length;
    const scripts = row.data.hosts.flatMap(host => Array.isArray(host?.scripts) ? host.scripts : []).length;
    return `${open} open ${open === 1 ? 'port' : 'ports'} · ${scripts} script ${scripts === 1 ? 'result' : 'results'}`;
  }
  return row.stdout_text ? `${row.tool || 'Tool'} output available` : row.status === 'partial' ? 'Incomplete collection' : 'No structured results';
}
export function cleanOutput(value) {
  return String(value ?? '').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r\n/g, '\n');
}
export const formatCommand = args => args.map(arg => /^[\w./:@=,+-]+$/.test(arg) ? arg : `'${arg.replaceAll("'", "'\\''")}'`).join(' ');

export function isToolSetup(row) {
  return /^netexec-(version|[a-z]+-(modules|help))$/.test(row.id || '');
}

