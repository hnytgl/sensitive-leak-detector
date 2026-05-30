from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .scanner import SEVERITY_RANK, Finding, has_failure, scan_path
from .web import EndpointFinding, scan_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sld",
        description="Scan files for accidentally exposed secrets and sensitive data.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan.")
    parser.add_argument(
        "--url",
        help="HTTP/HTTPS base URL to test for common exposed sensitive endpoints.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_RANK.keys()),
        default="medium",
        help="Exit with code 1 when findings at this severity or higher are detected.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Directory, file name, or glob pattern to skip. Can be provided more than once.",
    )
    return parser


def render_text(findings: list[Finding], endpoint_findings: list[EndpointFinding] | None) -> str:
    lines: list[str] = []
    if not findings:
        lines.append("No local sensitive data findings detected.")
    else:
        lines.append(f"{len(findings)} local finding(s) detected:")
        for finding in findings:
            lines.append(
                f"{finding.path}:{finding.line}:{finding.column} "
                f"[{finding.severity}] {finding.rule_id} - {finding.description} ({finding.match})"
            )

    if endpoint_findings:
        lines.append("")
        lines.append(f"{len(endpoint_findings)} exposed endpoint finding(s) detected:")
        for finding in endpoint_findings:
            lines.append(
                f"{finding.url} [{finding.status}] "
                f"[{finding.severity}] {finding.rule_id} - {finding.description} ({finding.evidence})"
            )
    elif endpoint_findings == []:
        lines.append("")
        lines.append("No exposed endpoint findings detected.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path)

    if not target.exists():
        parser.error(f"path does not exist: {target}")

    findings = scan_path(target, excludes=set(args.exclude))
    endpoint_findings = scan_url(args.url) if args.url else None

    if args.format == "json":
        payload = {
            "local_findings": [finding.to_dict() for finding in findings],
            "endpoint_findings": [finding.to_dict() for finding in endpoint_findings or []],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(findings, endpoint_findings))

    web_failure = any(SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[args.fail_on] for finding in endpoint_findings or [])
    return 1 if has_failure(findings, args.fail_on) or web_failure else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
