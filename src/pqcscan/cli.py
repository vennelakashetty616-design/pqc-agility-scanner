from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pqcscan import __version__
from pqcscan.baseline import compare_baseline, load_baseline, write_baseline
from pqcscan.disclaimer import DISCLAIMER, SANDBOX_DISCLAIMER
from pqcscan.dashboard import render_dashboard
from pqcscan.engine import scan_path
from pqcscan.report import render_json, render_markdown
from pqcscan.web import serve_platform
from pqcscan.sandbox.provider import (
    OperationUnavailable,
    UnsupportedProfile,
    list_profiles,
    load_provider,
    run_demo,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqcscan",
        description=(
            "Inventory cryptographic algorithms, libraries, certificates, and protocol settings, "
            "then draft a migration checklist. A scan does not prove quantum safety."
        ),
    )
    parser.add_argument("--version", action="version", version=f"pqcscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository or configuration tree.")
    scan.add_argument("--path", required=True, help="Directory to scan.")
    scan.add_argument("--out", help="Directory for report.md, report.json, and migration-graph.mmd.")

    baseline = sub.add_parser("baseline", help="Write a CI baseline of confirmed fingerprints.")
    baseline.add_argument("--path", required=True)
    baseline.add_argument("--out", required=True)

    ci = sub.add_parser("ci", help="Fail when new confirmed cryptographic fingerprints appear.")
    ci.add_argument("--path", required=True)
    ci.add_argument("--baseline", required=True)

    web = sub.add_parser("web", help="Open the local dashboard. Scan the starting folder or any other folder.")
    web.add_argument("--path", default="samples/legacy-billing", help="Directory to scan and explain.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)

    sandbox = sub.add_parser("sandbox", help="Run the classical crypto-agility sandbox.")
    sandbox.add_argument("--list", action="store_true", help="List classical profiles.")
    sandbox.add_argument("--profile", help="Profile name to exercise.")
    sandbox.add_argument("--config", help="JSON config with a profile field.")
    sandbox.add_argument("--demo", action="store_true", help="Exercise more than one profile through the same interface.")
    sandbox.add_argument("--message", default="crypto-agility-demo")
    return parser


def _cmd_scan(path: str, out: str | None) -> int:
    result = scan_path(Path(path))
    markdown = render_markdown(result)
    payload = render_json(result)
    if out:
        destination = Path(out)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "report.md").write_text(markdown, encoding="utf-8")
        (destination / "report.json").write_text(payload, encoding="utf-8")
        (destination / "migration-graph.mmd").write_text(result.migration_graph + "\n", encoding="utf-8")
        (destination / "dashboard.html").write_text(render_dashboard(result), encoding="utf-8")
        confirmed = sum(1 for item in result.findings if item.confidence == "confirmed")
        uncertain = sum(1 for item in result.findings if item.confidence == "uncertain")
        print(f"Wrote {destination / 'dashboard.html'}")
        print(f"Wrote {destination / 'report.md'}")
        print(f"Confirmed findings: {confirmed}. Uncertain matches: {uncertain}.")
        print(DISCLAIMER)
        return 0
    print(markdown)
    return 0


def _cmd_ci(path: str, baseline: str) -> int:
    baseline_path = Path(baseline)
    if not baseline_path.is_file():
        print(f"Baseline not found: {baseline_path}", file=sys.stderr)
        return 2
    result = scan_path(Path(path))
    try:
        document = load_baseline(baseline_path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    added, removed = compare_baseline(result, document)
    print("Crypto-agility CI check")
    print(DISCLAIMER)
    if removed:
        print("No longer detected (not a failure):")
        for item in removed:
            print(f"  - {item}")
    if added:
        print("New confirmed cryptographic dependencies or configurations:")
        for item in added:
            print(f"  + {item}")
        print("Review the new fingerprints. Update the baseline only when the change is intentional.")
        return 3
    print("No new confirmed fingerprints.")
    return 0


def _cmd_sandbox(args: argparse.Namespace) -> int:
    print(SANDBOX_DISCLAIMER)
    if args.list:
        for profile in list_profiles():
            print(f"{profile.profile_id}: {profile.description}")
        return 0
    if args.demo or (not args.profile and not args.config):
        print(run_demo())
        return 0
    try:
        provider = load_provider(Path(args.config)) if args.config else None
        if provider is None:
            from pqcscan.sandbox.provider import ClassicalProvider

            provider = ClassicalProvider(args.profile)
    except UnsupportedProfile as exc:
        print(str(exc), file=sys.stderr)
        return 2
    message = args.message.encode("utf-8")
    print(f"Profile {provider.profile_id} library={provider.library}")
    try:
        if "sign" in provider.capabilities():
            signature = provider.sign(message)
            print(f"verify={provider.verify(message, signature)}")
        if "protect" in provider.capabilities():
            token = provider.protect(message, b"pqcscan")
            print(f"round_trip={provider.open(token, b'pqcscan') == message}")
    except OperationUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args.path, args.out)
    if args.command == "baseline":
        result = scan_path(Path(args.path))
        write_baseline(result, Path(args.out))
        print(f"Wrote {args.out}")
        print(DISCLAIMER)
        return 0
    if args.command == "ci":
        return _cmd_ci(args.path, args.baseline)
    if args.command == "web":
        root = Path(args.path)
        if not root.is_dir():
            print(f"Scan path is not a directory: {root}", file=sys.stderr)
            return 2
        serve_platform(root, host=args.host, port=args.port)
        return 0
    if args.command == "sandbox":
        return _cmd_sandbox(args)
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
