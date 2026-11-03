#!/usr/bin/env python3
"""Command-line front end for firewall-lab.

Default mode is dry-run only: it prints the simulation results and the
equivalent ``ufw`` commands as text. It never touches the host firewall.

Real application is behind ``--apply`` and is LAB-ONLY: only ever run it
inside a disposable VM where locking yourself out of SSH does not matter.
``--apply`` additionally requires ``--i-understand-this-changes-the-firewall``
so it cannot be triggered by accident.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from firewall_lab import (format_verdict, parse_rules, parse_traffic,
                          simulate)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="UFW rule builder and dry-run simulator (safe by default).")
    parser.add_argument("--rules", default="examples/rules.txt",
                        help="rules file (default: examples/rules.txt)")
    parser.add_argument("--traffic", default="examples/traffic.txt",
                        help="traffic file (default: examples/traffic.txt)")
    parser.add_argument("--show-ufw", action="store_true",
                        help="also print the equivalent ufw commands")
    parser.add_argument("--apply", action="store_true",
                        help="LAB ONLY: actually run the ufw commands")
    parser.add_argument("--i-understand-this-changes-the-firewall",
                        action="store_true",
                        help="required together with --apply")
    args = parser.parse_args(argv)

    with open(args.rules, encoding="utf-8") as fh:
        rules, defaults = parse_rules(fh.read())
    with open(args.traffic, encoding="utf-8") as fh:
        packets = parse_traffic(fh.read())

    print(f"Loaded {len(rules)} rule(s); "
          f"default in={defaults['in']}, out={defaults['out']}")
    print()
    for verdict in simulate(packets, rules, defaults):
        print(format_verdict(verdict))

    if args.show_ufw:
        print()
        print("Equivalent ufw commands (text only, not executed):")
        for rule in rules:
            print(f"  {rule.to_ufw()}")

    if args.apply:
        if not args.i_understand_this_changes_the_firewall:
            print("\nRefusing --apply without "
                  "--i-understand-this-changes-the-firewall.",
                  file=sys.stderr)
            return 2
        print("\nLAB-ONLY APPLY: running ufw commands for real. "
              "If this is not a disposable VM, stop now.", file=sys.stderr)
        for rule in rules:
            cmd = rule.to_ufw().split()
            print(f"$ {' '.join(cmd)}")
            subprocess.run(cmd, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
