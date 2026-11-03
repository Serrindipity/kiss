"""NetExec-backed lab checks; each entry deliberately describes strength of evidence."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    name: str
    profile: str
    protocol: str
    args: tuple
    authenticated: bool
    note: str


CHECKS = [
    Check("ftp-anonymous", "access", "ftp", ("--ls",), False,
          "FTP anonymous account with a conventional email password; lists the root directory if accepted."),
    Check("smb-anonymous", "access", "smb", ("--shares",), False,
          "Empty-credential SMB share access. NetExec reports the authentication and share permissions."),
    Check("ldap-anonymous-389", "access", "ldap", ("--port", "389", "--query", "(objectClass=user)", "sAMAccountName"), False,
          "Anonymous LDAP on 389; inspect NetExec's returned directory entries, not just its connection banner."),
    Check("ldap-anonymous-636", "access", "ldap", ("--port", "636", "--query", "(objectClass=user)", "sAMAccountName"), False,
          "Anonymous LDAPS on 636; tool-managed TLS and authentication behavior is preserved."),
    Check("rdp-anonymous", "access", "rdp", (), False,
          "RDP empty-credential authentication attempt; negotiation or a login screen is not desktop access."),
    Check("winrm-anonymous", "access", "winrm", (), False,
          "WinRM empty-credential check over HTTP/HTTPS; no remote command is requested."),
    Check("rdp-account", "access", "rdp", (), True,
          "Check the supplied domain account with RDP; no commands or screenshots requested."),
    Check("winrm-account", "access", "winrm", (), True,
          "Check the supplied domain account with WinRM; no remote command requested."),
    Check("ldap-account-389", "access", "ldap", ("--port", "389", "--users"), True,
          "Domain account LDAP access and user enumeration on 389."),
    Check("ldap-account-636", "access", "ldap", ("--port", "636", "--users"), True,
          "Domain account LDAPS access and user enumeration on 636."),
    Check("smb-shares", "inventory", "smb", ("--shares",), True,
          "Share access as the supplied account; inspect individual permission results."),
    Check("smb-password-policy", "inventory", "smb", ("--pass-pol",), True, "Domain password and lockout policy."),
    Check("smb-users", "inventory", "smb", ("--users",), True, "SAMR user enumeration."),
    Check("smb-rid-enumeration", "inventory", "smb", ("--rid-brute", "4000"), False,
          "RID enumeration through 4000; anonymous access may be denied. This is not password guessing."),
    Check("ldap-protections", "inventory", "ldap", (), True,
          "Current NetExec LDAP connection banner probes signing/channel binding; older versions may not. Missing values are inconclusive."),
    Check("delegation", "inventory", "ldap", ("--find-delegation",), True, "Delegation relationships."),
    Check("fine-grained-policy", "inventory", "ldap", ("--pso",), True, "Fine-grained password policies."),
    Check("adcs-discovery", "inventory", "ldap", ("-M", "adcs"), True,
          "CA/template discovery, not a complete ESC classifier."),
    Check("spooler", "inventory", "smb", ("-M", "spooler"), False, "Spooler availability, not proof of PrintNightmare."),
    Check("webdav", "inventory", "smb", ("-M", "webdav"), False, "WebClient/WebDAV service indicator."),
    Check("endpoint-protection", "inventory", "smb", ("-M", "enum_av"), True, "Named-pipe indicators of endpoint products."),
    Check("zerologon", "vulns", "smb", ("-M", "zerologon"), False,
          "CVE-2020-1472 zero-credential Netlogon authentication test, up to 2000 attempts. No machine-password reset. Negative result is probabilistic."),
    Check("nopac", "vulns", "smb", ("-M", "nopac"), True,
          "Requests TGTs with/without PAC and compares sizes: prerequisite indicator, not proof of the full CVE-2021-42278/42287 chain. No account creation or rename."),
    Check("printnightmare", "vulns", "smb", ("-M", "printnightmare"), True,
          "RpcAddPrinterDriverEx parameter/error probe; no DLL payload. Use an ordinary user: an administrator result does not establish low-privilege exploitability."),
    Check("smbghost", "vulns", "smb", ("-M", "smbghost"), False,
          "SMB 3.1.1 compression indicator for CVE-2020-0796, not proof of missing patches."),
    Check("petitpotam", "coercion", "smb", ("-M", "coerce_plus", "-o", "METHOD=Petitpotam"), False,
          "EFSRPC interfaces. Without LISTENER, NetExec's VULNERABLE message only establishes RPC bind exposure."),
    Check("printerbug", "coercion", "smb", ("-M", "coerce_plus", "-o", "METHOD=Printerbug"), True,
          "MS-RPRN coercion path. Listener-backed test still requires receiver evidence."),
    Check("dfscoerce", "coercion", "smb", ("-M", "coerce_plus", "-o", "METHOD=DFSCoerce"), True,
          "MS-DFSNM coercion path; bind alone does not establish callback."),
    Check("shadowcoerce", "coercion", "smb", ("-M", "coerce_plus", "-o", "METHOD=ShadowCoerce"), True,
          "MS-FSRVP coercion path; service may not exist on a DC."),
    Check("mseven", "coercion", "smb", ("-M", "coerce_plus", "-o", "METHOD=MSEven"), True,
          "Event-log RPC coercion path; bind alone does not establish callback."),
    Check("gpp-passwords", "secrets", "smb", ("-M", "gpp_password"), True,
          "Read SYSVOL GPP files and retain decrypted credentials in tool output."),
    Check("gpp-autologon", "secrets", "smb", ("-M", "gpp_autologin"), True,
          "Read SYSVOL Registry.xml autologon credentials."),
    Check("laps-passwords", "secrets", "ldap", ("-M", "laps"), True,
          "Retrieve readable legacy/Windows LAPS secrets; decryption depends on caller rights."),
    Check("gmsa-passwords", "secrets", "ldap", ("--gmsa",), True,
          "Retrieve accessible managed service-account passwords/hashes."),
    Check("asrep-roast", "secrets", "ldap", ("--asreproast", "{out}/asrep.txt"), True,
          "Request AS-REP material for eligible accounts; retain complete cracking-format output."),
    Check("kerberoast", "secrets", "ldap", ("--kerberoasting", "{out}/kerberoast.txt"), True,
          "Request service tickets for existing SPNs; retains hashes. Does not add SPNs or run cracking."),
]
