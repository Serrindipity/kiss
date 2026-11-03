#!/usr/bin/env python3
"""Inspect a mounted/copied share and preserve full matching file and secret evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone

TEXT_EXTENSIONS = {".xml", ".ps1", ".bat", ".cmd", ".vbs", ".ini", ".config", ".conf",
                   ".txt", ".yml", ".yaml", ".json", ".env", ".properties", ".rdp",
                   ".pem", ".key", ".sql", ".ldif", ".csv", ".rdg", ".tfstate", ".kubeconfig"}
PATTERNS = {
    "gpp-cpassword": re.compile(r'\bcpassword\s*=\s*["\'][^"\']+["\']', re.I),
    "password-assignment": re.compile(r'''(?ix)(?:password|passwd|pwd|secret|api[_-]?key)\s*["']?\s*[:=]\s*\S+'''),
    "powershell-plaintext-secret": re.compile(r"ConvertTo-SecureString.*-AsPlainText", re.I),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "unattended-password": re.compile(r"<(?:AdministratorPassword|AutoLogon|Credentials)(?:\s|>)", re.I),
    "net-use-credential": re.compile(r"\bnet\s+use\b.*(?:/user:|/u:)", re.I),
    "xml-password": re.compile(r"<(?:Password|DefaultPassword|ConnectionString)(?:\s|>)", re.I),
    "ldap-secret": re.compile(r"^(?:userPassword|unicodePwd|ms-Mcs-AdmPwd|msLAPS-Password)::?", re.I),
    "credential-uri": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.I),
}


def indicators(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                found.append({"indicator": name, "line": number, "evidence": line,
                              "assessment": "requires_review"})
    return found


def scan(root, max_bytes, max_files):
    results, visited, limited = [], 0, False
    def walk_error(exc):
        results.append({"path": str(exc.filename), "status": "error", "error": str(exc)})
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in list(dirs):
            if (Path(folder) / name).is_symlink():
                dirs.remove(name)
                results.append({"path": str((Path(folder) / name).relative_to(root)),
                                "status": "not_tested", "reason": "symlink_directory"})
        for name in files:
            path = Path(folder) / name
            relative = str(path.relative_to(root))
            if visited >= max_files:
                limited = True
                return {"files_considered": visited, "limited": limited, "results": results}
            visited += 1
            record = {"path": relative, "status": "completed"}
            results.append(record)
            if path.is_symlink():
                record.update(status="not_tested", reason="symlink")
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS and not name.lower().startswith(".env"):
                record.update(status="not_tested", reason="unsupported_file_type")
                continue
            try:
                with path.open("rb") as stream:
                    data = stream.read(max_bytes + 1)
                if len(data) > max_bytes:
                    record.update(status="not_tested", reason="size_limit")
                    continue
                record["sha256"] = hashlib.sha256(data).hexdigest()
                encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
                try:
                    text = data.decode(encoding)
                except UnicodeDecodeError:
                    # Preserve ASCII patterns in legacy Windows code-page files.
                    text = data.decode("latin-1")
                    record["encoding_note"] = "Latin-1 fallback; non-ASCII text requires review"
                record["indicators"] = indicators(text)
                if record["indicators"]:
                    record["content"] = text
            except OSError as exc:
                record.update(status="error", error=str(exc))
    return {"files_considered": visited, "limited": limited, "results": results}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    p.add_argument("--out", type=Path, required=True, help="New JSON file outside the scanned tree")
    p.add_argument("--max-bytes", type=int, default=2_000_000)
    p.add_argument("--max-files", type=int, default=10000)
    a = p.parse_args()
    root, output = a.root.resolve(), a.out.resolve()
    if not root.is_dir() or a.max_bytes < 1 or a.max_files < 1:
        p.error("A directory and positive limits are required")
    if output == root or root in output.parents:
        p.error("Place output outside the scanned tree")
    os.umask(0o077)
    # Reserve the destination before scanning so an existing report is never overwritten.
    with output.open("x") as handle:
        report = {"schema_version": 1, "root": str(root), "time": datetime.now(timezone.utc).isoformat(),
                  "note": "Full matched file contents and secrets retained. No writes to the input share.",
                  **scan(root, a.max_bytes, a.max_files)}
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(f"Evidence: {output}")
    return 1 if report["limited"] or any(r["status"] == "error" for r in report["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
