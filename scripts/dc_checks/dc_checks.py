#!/usr/bin/env python3
"""Evidence-first, single-target DC reconnaissance. Python standard library only."""
import argparse
import copy
import base64
from datetime import datetime, timezone
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

if __package__:
    from .ldap_checks import CHECKS
else:
    from ldap_checks import CHECKS


def now():
    return datetime.now(timezone.utc).isoformat()


def host(value):
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        if (len(value) <= 253 and not value.startswith("-") and
                all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
                    for x in value.rstrip(".").split("."))):
            return value.rstrip(".")
    raise argparse.ArgumentTypeError("Use one IPv4 address or DNS hostname, not a URL, range or CIDR")


def parse_ldif(text):
    """Unfold LDIF, preserve multi-values and binary attributes without fetching URLs."""
    lines = []
    for line in text.splitlines():
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    entries, entry = [], {}
    for line in lines + [""]:
        if not line:
            if "dn" in entry:
                entries.append(entry)
            entry = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if value.startswith(":"):
            encoded = value[1:].strip()
            try:
                raw = base64.b64decode(encoded, validate=True)
                value = raw.decode("utf-8")
                if any(ord(c) < 32 and c not in "\t\r\n" for c in value):
                    value = {"base64": encoded}
            except UnicodeDecodeError:
                value = {"base64": encoded}
            except ValueError as exc:
                raise ValueError(f"Malformed LDIF base64 for {key}") from exc
        elif value.startswith("<"):
            value = {"external_url_not_fetched": value[1:].strip()}
        else:
            value = value.lstrip(" ")
        entry.setdefault(key.lower(), []).append(value)
    return entries


def parse_nmap(text):
    root = ET.fromstring(text)
    return {
        "hosts": [{"addresses": [a.attrib for a in h.findall("address")],
                   "status": h.find("status").attrib if h.find("status") is not None else {},
                   "ports": [{"port": p.get("portid"), "protocol": p.get("protocol"),
                              "state": p.find("state").get("state"),
                              "service": p.find("service").attrib if p.find("service") is not None else {}}
                             for p in h.findall("ports/port")],
                   "scripts": [{"id": s.get("id"), "output": s.get("output"),
                                "xml": ET.tostring(s, encoding="unicode")}
                               for s in h.findall(".//script")]}
                  for h in root.findall("host")],
        "finished": root.find("runstats/finished").attrib
        if root.find("runstats/finished") is not None else {},
    }


class Runner:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out)
        self.out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.results = []
        self.secret = None

    def save(self):
        body = {"schema_version": 1, "target": self.args.dc, "domain": self.args.domain,
                "updated_at": now(), "results": self.results}
        tmp = self.out / ".results.json.tmp"
        tmp.write_text(json.dumps(body, indent=2) + "\n")
        tmp.replace(self.out / "results.json")

    def skip(self, name, reason, identity="anonymous"):
        self.results.append({"id": name, "target": self.args.dc, "identity": identity,
                             "time": now(), "status": "not_tested", "reason": reason})
        self.save()

    def run(self, name, argv, identity="anonymous", parser=None, note="", redact_values=()):
        displayed = ["<temporary-password-file>" if self.secret and x == self.secret else "<supplied-password>" if x in redact_values else x for x in argv]
        result = {"id": name, "time": now(), "target": self.args.dc, "identity": identity,
                  "command": displayed, "note": note, "assessment": "requires_review"}
        self.results.append(result)
        if self.args.plan:
            result["status"] = "not_tested"
            result["reason"] = "plan_only"
            self.save()
            return result
        if not shutil.which(argv[0]):
            result.update(status="not_tested", reason=f"Missing executable: {argv[0]}")
            self.save()
            return result
        stdout, stderr = "", ""
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                  timeout=self.args.timeout, stdin=subprocess.DEVNULL,
                                  env={**os.environ, "LC_ALL": "C"})
            stdout, stderr = proc.stdout, proc.stderr
            result["returncode"] = proc.returncode
            result["status"] = "completed" if proc.returncode == 0 else "error"
            if argv[0] == "ldapsearch":
                if proc.returncode == 50:
                    result["status"] = "access_denied"
                elif proc.returncode == 49:
                    result["status"] = "authentication_failed"
                elif proc.returncode in (3, 4):
                    result["status"] = "partial"
            if parser and stdout:
                try:
                    result["data"] = parser(stdout)
                    if parser is parse_ldif:
                        result["returned_entries"] = len(result["data"])
                        result["range_attributes_present"] = any(
                            ";range=" in k for e in result["data"] for k in e)
                        if result["range_attributes_present"] and result["status"] == "completed":
                            result["status"] = "partial"
                            result["reason"] = "AD returned ranged attributes; values may be incomplete"
                except (ValueError, ET.ParseError, AttributeError) as exc:
                    result.update(status="error", parse_error=str(exc))
        except subprocess.TimeoutExpired as exc:
            result.update(status="timeout", reason="Partial output is retained; no negative conclusion")
            stdout = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        except OSError as exc:
            result.update(status="error", reason=str(exc))
        for suffix, content in (("stdout", stdout), ("stderr", stderr)):
            filename = f"{name}.{suffix}.txt"
            (self.out / filename).write_text(content)
            result[suffix] = filename
        self.save()
        print(f"{name}: {result['status']}", flush=True)
        return result


def ldap_command(args, base, scope, query, attrs, authenticated=False, secret=None, limit=0):
    port = 636 if args.ldap_transport == "ldaps" else 389
    uri = f"{args.ldap_transport}://{args.ldap_host or args.dc}:{port}"
    cmd = ["ldapsearch", "-LLL", "-o", "nettimeout=10", "-x", "-H", uri]
    if args.ldap_transport == "ldap" and authenticated:
        cmd += ["-ZZ"]  # StartTLS required, no cleartext credential fallback
    if authenticated:
        cmd += ["-D", args.bind_user, "-y", secret or "<temporary-password-file>"]
    return cmd + ["-E", "!pr=500/noprompt", "-l", "60", "-z", str(limit),
                  "-b", base, "-s", scope, query] + attrs


def collect_ldap(r):
    a = r.args
    base = a.base_dn or ",".join("DC=" + label for label in a.domain.split("."))
    config = "CN=Configuration," + base
    root = r.run("ldap-rootdse", ldap_command(a, "", "base", "(objectClass=*)",
                 ["defaultNamingContext", "configurationNamingContext", "dnsHostName", "supportedCapabilities"]),
                 parser=parse_ldif, note="RootDSE readability is normal and is not anonymous directory exposure.")
    if root.get("status") == "completed" and root.get("data"):
        entry = root["data"][0]
        base = a.base_dn or entry.get("defaultnamingcontext", [base])[0]
        config = entry.get("configurationnamingcontext", [config])[0]
    r.run("ldap-anonymous-directory", ldap_command(a, base, "sub", "(objectClass=user)",
          ["sAMAccountName"], limit=10), parser=parse_ldif,
          note="Up to 10 anonymous entries; size-limit output is partial evidence, not failure of all reads.")
    if not a.bind_user:
        if getattr(a, "anonymous_only", False):
            return
        for name, *_ in CHECKS:
            r.skip(name, "Supply --bind-user for authenticated LDAP inventory")
        return
    identity = a.bind_user
    if getattr(r, "authentication_failed", False):
        for name, *_ in CHECKS:
            r.skip(name, "Credentials were rejected on the other connection; no further authenticated binds", identity)
        return
    probe = r.run("ldap-authentication", ldap_command(a, "", "base", "(objectClass=*)",
                  ["defaultNamingContext", "configurationNamingContext"], True, r.secret), identity, parse_ldif)
    if not a.plan and probe["status"] != "completed":
        for name, *_ in CHECKS:
            r.skip(name, "Initial authenticated bind failed; no further credential attempts", identity)
        return
    if probe.get("data"):
        entry = probe["data"][0]
        base = a.base_dn or entry.get("defaultnamingcontext", [base])[0]
        config = entry.get("configurationnamingcontext", [config])[0]
    auth_failed = False
    for name, context, scope, query, attrs, note in CHECKS:
        if auth_failed:
            r.skip(name, "Authentication failed during collection; remaining binds cancelled", identity)
            continue
        result = r.run(name, ldap_command(a, config if context == "config" else base, scope,
                       query, attrs, True, r.secret), identity, parse_ldif, note)
        auth_failed = result["status"] == "authentication_failed"


class LdapConnection:
    """Separate evidence per transport; stop credential attempts after a rejection."""
    def __init__(self, runner, transport):
        self.runner = runner
        self.args = copy.copy(runner.args)
        self.args.ldap_transport = transport
        self.secret = runner.secret
        self.prefix = 'ldap389' if transport == 'ldap' else 'ldaps636'

    @property
    def authentication_failed(self):
        return getattr(self.runner, 'ldap_authentication_failed', False)

    def run(self, name, *args, **kwargs):
        result = self.runner.run(f'{self.prefix}-{name}', *args, **kwargs)
        result['check_id'] = name
        result['connection'] = 'LDAP :389' if self.args.ldap_transport == 'ldap' else 'LDAPS :636'
        if result['status'] == 'authentication_failed':
            self.runner.ldap_authentication_failed = True
        self.runner.save()
        return result

    def skip(self, name, reason, identity='anonymous'):
        self.runner.skip(f'{self.prefix}-{name}', reason, identity)
        self.runner.results[-1].update(check_id=name, connection='LDAP :389' if self.args.ldap_transport == 'ldap' else 'LDAPS :636')
        self.runner.save()


def collect_ldap_connections(runner):
    transports = ('ldap', 'ldaps') if runner.args.ldap_transport == 'both' else (runner.args.ldap_transport,)
    for transport in transports:
        collect_ldap(LdapConnection(runner, transport))


def collect(r):
    a = r.args
    modules = set(a.modules.split(","))
    if "dns" in modules:
        for name, prefix in (("dc", "_ldap._tcp.dc._msdcs"), ("kerberos", "_kerberos._tcp"),
                             ("gc", "_ldap._tcp.gc._msdcs")):
            r.run("dns-" + name, ["dig", "@" + a.dc, prefix + "." + a.domain, "SRV", "+time=3", "+tries=1"],
                  note="Inspect DNS response status; process exit zero does not mean a record exists.")
        r.run("dns-axfr", ["dig", "@" + a.dc, a.domain, "AXFR", "+time=5", "+tries=1"],
              note="Inspect answer/transfer status; denied transfer is not a tool failure.")
    if "services" in modules:
        r.run("services", ["nmap", "-n", "-Pn", "-sT", "--host-timeout", "90s", "-p",
              "53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,80,443", "-oX", "-", a.dc], parser=parse_nmap)
    if "smb" in modules:
        r.run("smb-protocols", ["nmap", "-n", "-Pn", "-sT", "-p445", "--script",
              "smb-protocols,smb2-security-mode,smb2-time", "--script-timeout", "30s", "-oX", "-", a.dc],
              parser=parse_nmap, note="Absent NSE output is inconclusive; inspect each returned script.")
        r.run("smb-anonymous-shares", ["smbclient", "-L", a.dc, "-N", "-U", "%", "-g", "-t", "15"],
              note="Share listing does not prove file access. Server guest mapping may affect identity.")
        r.run("rpc-anonymous", ["rpcclient", "-N", "-U", "%", a.dc, "-c", "getdompwinfo;enumdomusers;enumdomgroups"],
              note="Review individual RPC responses; command exit alone does not establish enumeration success.")
        if a.guest:
            r.run("smb-guest-shares", ["smbclient", "-L", a.dc, "-N", "-U", "Guest%", "-g", "-t", "15"],
                  "Guest (empty password)", note="One explicit authentication attempt; no password spraying.")
    if "tls" in modules:
        r.run("tls-rdp", ["nmap", "-n", "-Pn", "-sT", "-p443,636,3269,3389,5986", "--script",
              "ssl-cert,ssl-enum-ciphers,rdp-enum-encryption", "--script-timeout", "45s", "-oX", "-", a.dc],
              parser=parse_nmap, note="Cipher enumeration makes repeated connections; no output is inconclusive.")
    if "ldap" in modules:
        collect_ldap_connections(r)
    if a.ms17_010:
        r.run("ms17-010", ["nmap", "-n", "-Pn", "-sT", "-p445", "--script", "smb-vuln-ms17-010",
              "--script-timeout", "45s", "-oX", "-", a.dc], parser=parse_nmap,
              note="Targeted detection only. Missing script output does not establish patch status.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dc", required=True, type=host)
    p.add_argument("--domain", required=True, type=host)
    p.add_argument("--ldap-host", type=host, help="Certificate-matching DC hostname when --dc is an IP")
    p.add_argument("--ldap-transport", choices=["both", "ldaps", "ldap"], default="both", help="Both ports by default; authenticated LDAP on 389 requires StartTLS")
    p.add_argument("--base-dn")
    p.add_argument("--bind-user", help="UPN or distinguished name; password prompted without echo")
    p.add_argument("--modules", default="dns,services,smb,ldap", help="Comma-separated dns,services,smb,ldap,tls")
    p.add_argument("--guest", action="store_true", help="Try Guest with an empty password once")
    p.add_argument("--ms17-010", action="store_true", help="Run dedicated Nmap MS17-010 detection")
    p.add_argument("--timeout", type=int, default=180, help="Timeout per external command in seconds")
    p.add_argument("--out", required=True, help="NEW private output directory")
    p.add_argument("--plan", action="store_true", help="Save planned commands without running any network tools")
    a = p.parse_args()
    if not set(a.modules.split(",")) <= {"dns", "services", "smb", "ldap", "tls"}:
        p.error("Unknown module")
    if a.timeout < 1:
        p.error("--timeout must be positive")
    if "." not in a.domain or re.fullmatch(r"[0-9.]+", a.domain):
        p.error("--domain must be a DNS domain, e.g. example.test")
    os.umask(0o077)
    try:
        r = Runner(a)
    except FileExistsError:
        p.error("Output directory already exists; use a fresh directory to preserve evidence")
    with tempfile.TemporaryDirectory(prefix="dc-checks-") as temp:
        if a.bind_user and "ldap" in a.modules.split(",") and not a.plan:
            password = getpass.getpass("LDAP password: ")
            if not password:
                p.error("Empty bind passwords are rejected to avoid an unauthenticated LDAP bind")
            r.secret = str(Path(temp) / "password")
            Path(r.secret).write_text(password)
            del password
        try:
            collect(r)
        except KeyboardInterrupt:
            r.skip("interrupted", "Collection interrupted by operator")
            return 130
    print(f"Evidence: {r.out / 'results.json'}")
    if any(x.get("reason", "").startswith("Missing executable:") for x in r.results):
        return 2
    return 1 if any(x["status"] in {"error", "timeout", "authentication_failed", "partial"}
                    for x in r.results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
