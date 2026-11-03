#!/usr/bin/env python3
"""Run named DC lab probes with NetExec/Nmap and retain complete evidence."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import tempfile

if __package__:
    from .dc_checks import Runner, host, parse_nmap
    from .lab_catalog import CHECKS
else:
    from dc_checks import Runner, host, parse_nmap
    from lab_catalog import CHECKS

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PROFILES = {"access", "inventory", "vulns", "coercion", "secrets"}
AUTH_ERRORS = ("STATUS_LOGON_FAILURE", "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_PASSWORD_EXPIRED",
               "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_RESTRICTION", "KDC_ERR_PREAUTH_FAILED",
               "invalidCredentials", "data 52e", "data 775")


def output(runner, result):
    return ANSI.sub("", "\n".join((runner.out / result[key]).read_text()
                                 for key in ("stdout", "stderr") if key in result))


def command(check, args, password_file):
    cmd = [args.nxc, check.protocol, args.dc]
    if check.protocol != 'ftp':
        cmd += ['-d', args.domain]
    if check.name == 'ftp-anonymous':
        cmd += ['-u', 'anonymous', '-p', 'kiss@example.test']
    else:
        cmd += ['-u', args.username or '', '-p', password_file if args.username else '']
    cmd += ['--no-bruteforce', '--no-progress', '--dns-server', args.dc]
    cmd += [x.replace("{out}", str(Path(args.out).resolve())) for x in check.args]
    if check.profile == "coercion" and args.listener:
        cmd += ["LISTENER=" + args.listener]
    return cmd


def tag_result(r, result, check):
    result["profile"] = check.profile
    result["tool"] = "NetExec"
    result["protocol"] = check.protocol
    result["evidence_kind"] = "tool_observation"
    if check.profile == "coercion":
        result["evidence_kind"] = "coercion_attempt" if r.args.listener else "rpc_interface_exposure"
        result["listener"] = r.args.listener
        result["callback_confirmed"] = None
        result["assessment"] = "receiver_evidence_required" if r.args.listener else "requires_review"
    text = output(r, result)
    if any(marker.lower() in text.lower() for marker in AUTH_ERRORS):
        result["status"] = "authentication_failed"
    r.save()


def collect(r, selected, include_ms17):
    a = r.args
    identity = f"{a.domain}\\{a.username}" if a.username else "anonymous"
    if include_ms17:
        r.run("ms17-010", ["nmap", "-n", "-Pn", "-sT", "-p445", "--script", "smb-vuln-ms17-010",
                          "--script-timeout", "60s", "-oX", "-", a.dc], parser=parse_nmap,
              note="MS17-010/EternalBlue-family detection. No payload or code execution; absent NSE output is inconclusive.")
    available = {}
    protocol_help = {}
    if not a.plan:
        if selected:
            version = r.run("netexec-version", [a.nxc, "--version"], note="Local tool version. Some NetExec releases exit 1 after printing it.")
            if version.get("returncode") == 1 and re.search(r"\d+\.\d+\.\d+", output(r, version)):
                version["status"] = "completed"
                r.save()
        for protocol in sorted({c.protocol for c in selected}):
            if any(c.protocol == protocol and '-M' in c.args for c in selected):
                modules = r.run(f"netexec-{protocol}-modules", [a.nxc, protocol, "-L"], note="Local module preflight; no target.")
                available[protocol] = output(r, modules)
            help_result = r.run(f"netexec-{protocol}-help", [a.nxc, protocol, "-h"], note="Local CLI capability preflight; no target.")
            protocol_help[protocol] = output(r, help_result)
    stop_auth = False
    for check in selected:
        if check.authenticated and not a.username:
            r.skip(check.name, "Requires --username and a known password", identity)
            continue
        if stop_auth:
            r.skip(check.name, "Earlier authentication failed; remaining credential attempts cancelled", identity)
            continue
        if not a.plan:
            if "-M" in check.args:
                module = check.args[check.args.index("-M") + 1]
                if not re.search(r"(?<![\w-])" + re.escape(module) + r"(?![\w-])", available[check.protocol]):
                    r.skip(check.name, f"Installed NetExec does not advertise module {module}", identity)
                    continue
            elif any(flag not in protocol_help[check.protocol] for flag in check.args if flag.startswith("--")):
                r.skip(check.name, "Installed NetExec does not advertise the options required by this check", identity)
                continue
        result = r.run(check.name, command(check, a, r.secret or "<temporary-password-file>"), identity, note=check.note)
        tag_result(r, result, check)
        if result["status"] == "authentication_failed" and a.username:
            stop_auth = True
    # NXC writes these directly; preserve filenames and full content in the report too.
    for name in ("asrep.txt", "kerberoast.txt"):
        path = r.out / name
        if path.is_file():
            r.results.append({"id": "artifact-" + name, "status": "completed", "target": a.dc,
                              "identity": identity, "path": name, "content": path.read_text(errors="replace")})
    if a.adcs:
        if not a.username:
            r.skip("certipy-adcs", "Requires --username", identity)
        elif stop_auth:
            r.skip("certipy-adcs", "Earlier authentication failed; no additional credential attempt", identity)
        else:
            password = Path(r.secret).read_text()[:-1] if r.secret else "<password>"
            upn = a.username if "@" in a.username else a.username + "@" + a.domain
            argv = [a.certipy, "find", "-u", upn, "-p", password, "-dc-ip", a.dc,
                    "-json", "-text", "-stdout", "-output", str(r.out.resolve() / "adcs")]
            if a.adcs_dc_only:
                argv += ["-dc-only"]
            r.run("certipy-adcs", argv, identity, redact_values=(password,),
                  note="Certipy template/CA/ESC analysis. Without --adcs-dc-only, contacts discovered CAs and web enrollment endpoints. Discovered secrets retained; supplied password omitted from saved command.")
            for path in sorted(r.out.glob("adcs*")):
                if path.is_file():
                    r.results.append({"id": "artifact-" + path.name, "status": "completed", "target": a.dc,
                                      "identity": identity, "path": path.name})
    r.save()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dc", type=host)
    p.add_argument("--domain", type=host)
    p.add_argument("--username", help="One domain account (sAMAccountName), not a user list")
    p.add_argument("--password-env", help="Read the single password from this environment variable instead of prompting")
    p.add_argument("--profiles", default="inventory", help="inventory,vulns,coercion,secrets or all")
    p.add_argument("--checks", help="Select exact check names instead of profiles; see --list")
    p.add_argument("--listener", type=host, help="Your lab receiver; enables actual coercion attempts")
    p.add_argument("--nxc", default="nxc", help="NetExec executable or full path")
    p.add_argument("--adcs", action="store_true", help="Also run Certipy find including discovered CAs")
    p.add_argument("--adcs-dc-only", action="store_true", help="Limit Certipy to DC LDAP; no CA endpoint checks")
    p.add_argument("--certipy", default="certipy", help="Certipy AD executable (some installs use certipy-ad)")
    p.add_argument("--timeout", type=int, default=600, help="Per-check deadline; Zerologon can take several minutes")
    p.add_argument("--out", help="New evidence directory")
    p.add_argument("--plan", action="store_true")
    p.add_argument("--list", action="store_true", help="List checks without network access")
    a = p.parse_args()
    if a.list:
        print("ms17-010              vulns      anonymous  MS17-010/EternalBlue-family Nmap detection")
        for check in CHECKS:
            print(f"{check.name:21} {check.profile:10} {'account' if check.authenticated else 'anonymous':10} {check.note}")
        return 0
    if not a.dc or not a.domain or not a.out:
        p.error("--dc, --domain and --out are required")
    if a.timeout < 1:
        p.error("--timeout must be positive")
    if a.adcs_dc_only and not a.adcs:
        p.error("--adcs-dc-only requires --adcs")
    if a.username and (not re.fullmatch(r"[\w.@$-]+", a.username) or Path(a.username).is_file()):
        p.error("Use a single account name, not a file or a domain\\user expression")
    profiles = PROFILES if a.profiles == "all" else set(a.profiles.split(","))
    if not profiles <= PROFILES:
        p.error("Unknown profile")
    names = set(a.checks.split(",")) if a.checks else None
    if names and not names <= {c.name for c in CHECKS} | {"ms17-010"}:
        p.error("Unknown check; use --list")
    selected = [c for c in CHECKS if c.name in names] if names else [c for c in CHECKS if c.profile in profiles]
    ms17 = "ms17-010" in names if names else "vulns" in profiles
    if a.listener and not any(c.profile == "coercion" for c in selected):
        p.error("--listener requires a coercion check/profile")
    os.umask(0o077)
    try:
        r = Runner(a)
    except FileExistsError:
        p.error("Use a new output directory")
    with tempfile.TemporaryDirectory(prefix="dc-lab-") as temp:
        if a.username and (selected or a.adcs) and not a.plan:
            if a.password_env:
                if a.password_env not in os.environ:
                    p.error("Password environment variable is unset")
                password = os.environ[a.password_env]
            else:
                password = getpass.getpass("Domain password: ")
            if any(c in password for c in "\r\n\x00"):
                p.error("Password files require a single line")
            r.secret = str(Path(temp) / "password")
            Path(r.secret).write_text(password + "\n")
            del password
        try:
            collect(r, selected, ms17)
        except KeyboardInterrupt:
            r.skip("interrupted", "Operator interrupted collection")
            return 130
    print(f"Evidence: {r.out / 'results.json'}")
    return 1 if any(x["status"] != "completed" for x in r.results) and not a.plan else 0


if __name__ == "__main__":
    raise SystemExit(main())
