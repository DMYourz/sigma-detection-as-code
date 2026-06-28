"""Command-line interface: validate / convert / coverage."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .convert import convert_all
from .coverage import write_layer
from .validate import validate_all


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sigmatools",
        description="Author, validate, and compile Sigma rules (detection-as-code).",
    )
    parser.add_argument("--version", action="version", version=f"sigmatools {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="Structurally validate every rule and confirm it parses in pySigma")

    c = sub.add_parser("convert", help="Compile all rules to Splunk SPL")
    c.add_argument("-o", "--output", default="generated/splunk")

    cov = sub.add_parser("coverage", help="Write a MITRE ATT&CK Navigator layer")
    cov.add_argument("-o", "--output", default="generated/attack-navigator-layer.json")

    args = parser.parse_args(argv)

    if args.cmd == "validate":
        ok, problems = validate_all()
        if ok:
            print("[+] All rules valid.")
            return 0
        for p in problems:
            print(f"[!] {p}", file=sys.stderr)
        print(f"[x] {len(problems)} problem(s) found.", file=sys.stderr)
        return 1

    if args.cmd == "convert":
        results = convert_all(Path(args.output))
        for path, _rule, spl in results:
            print(f"[+] {path.stem}.spl")
            print(f"      {spl}")
        print(f"[=] wrote {len(results)} SPL file(s) + savedsearches.conf to {args.output}")
        return 0

    if args.cmd == "coverage":
        layer = write_layer(Path(args.output))
        print(f"[+] wrote ATT&CK layer with {len(layer['techniques'])} techniques to {args.output}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
