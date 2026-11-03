"""KISS adapter: private stdin configuration, never password command arguments."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from .dc_checks import Runner, collect
from .lab_checks import collect as collect_lab
from .lab_catalog import CHECKS


def main():
    os.umask(0o077)
    config = json.load(sys.stdin)
    password = config.pop('password', '')
    collector = config.pop('collector', 'directory')
    selected_names = config.pop('checks', [])
    runner = Runner(argparse.Namespace(**config))
    with tempfile.TemporaryDirectory(prefix='dc-secret-', dir=runner.out.parent) as private:
        if password:
            runner.secret = str(Path(private) / 'password')
            Path(runner.secret).write_text(password + ('\n' if collector == 'lab' else ''))
        try:
            if collector == 'lab':
                collect_lab(runner, [check for check in CHECKS if check.name in selected_names], 'ms17-010' in selected_names)
            else:
                collect(runner)
        except KeyboardInterrupt:
            runner.skip('interrupted', 'Collection stopped; partial evidence retained')
            return 130
    if collector == 'lab':
        return int(not runner.args.plan and any(row['status'] != 'completed' for row in runner.results))
    return 1 if any(row['status'] in {'error', 'timeout', 'authentication_failed', 'partial'}
                    or row.get('reason', '').startswith('Missing executable:') for row in runner.results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
