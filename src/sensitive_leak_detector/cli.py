from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .scanner import SEVERITY_RANK, Finding, has_failure, scan_path
from .web import EndpointFinding, crawl_pages, scan_url


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
        "--api-path",
        action="append",
        default=[],
        help="Additional API path to test, such as /api/v1/users. Can be provided more than once.",
    )
    parser.add_argument(
        "--api-path-file",
        help="Text file containing API paths to test, one path per line.",
    )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=0,
        help="Crawl same-origin pages to this depth and scan page source. 0 disables page crawling.",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Maximum number of pages to crawl when --depth is greater than 0.",
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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show local scan, endpoint probe, and page crawl activity.",
    )
    return parser


def load_api_paths(values: list[str], path_file: str | None) -> list[str]:
    paths = [value.strip() for value in values if value.strip()]
    if path_file:
        for line in Path(path_file).read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                paths.append(stripped)
    return paths


def log_verbose(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[sld] {message}", file=sys.stderr)


def render_text(
    findings: list[Finding],
    endpoint_findings: list[EndpointFinding] | None,
    page_findings: list[Finding] | None,
    discovered_api_paths: list[str] | None,
) -> str:
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

    if page_findings:
        lines.append("")
        lines.append(f"{len(page_findings)} page source finding(s) detected:")
        for finding in page_findings:
            lines.append(
                f"{finding.path}:{finding.line}:{finding.column} "
                f"[{finding.severity}] {finding.rule_id} - {finding.description} ({finding.match})"
            )
    elif page_findings == []:
        lines.append("")
        lines.append("No page source findings detected.")

    if discovered_api_paths:
        lines.append("")
        lines.append(f"{len(discovered_api_paths)} API path(s) discovered from page source:")
        for api_path in discovered_api_paths:
            lines.append(f"- {api_path}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path)

    if not target.exists():
        parser.error(f"path does not exist: {target}")
    if args.depth < 0:
        parser.error("--depth must be 0 or greater")
    if args.max_pages < 1:
        parser.error("--max-pages must be 1 or greater")

    log_verbose(args.verbose, f"Scanning local path: {target.resolve()}")
    findings = scan_path(target, excludes=set(args.exclude))
    log_verbose(args.verbose, f"Local scan complete: {len(findings)} finding(s)")

    api_paths = load_api_paths(args.api_path, args.api_path_file)
    if api_paths:
        log_verbose(args.verbose, f"Loaded {len(api_paths)} custom API path(s)")

    endpoint_findings = None
    page_findings = None
    discovered_api_paths: list[str] = []
    if args.url:
        log_verbose(args.verbose, f"Starting endpoint scan for {args.url}")
        endpoint_findings = scan_url(
            args.url,
            api_paths=api_paths,
            progress=lambda message: log_verbose(args.verbose, message),
        )
        log_verbose(args.verbose, f"Endpoint scan complete: {len(endpoint_findings)} finding(s)")
        if args.depth > 0:
            log_verbose(args.verbose, f"Starting page source crawl for {args.url}")
            crawl_result = crawl_pages(
                args.url,
                depth=args.depth,
                max_pages=args.max_pages,
                progress=lambda message: log_verbose(args.verbose, message),
            )
            page_findings = crawl_result.findings
            discovered_api_paths = crawl_result.discovered_api_paths
            log_verbose(args.verbose, f"Page source crawl complete: {len(page_findings)} finding(s)")
            known_api_paths = set(api_paths)
            new_api_paths = [path for path in discovered_api_paths if path not in known_api_paths]
            if new_api_paths:
                log_verbose(args.verbose, f"Testing {len(new_api_paths)} API path(s) discovered from page source")
                discovered_endpoint_findings = scan_url(
                    args.url,
                    api_paths=new_api_paths,
                    include_common=False,
                    progress=lambda message: log_verbose(args.verbose, message),
                )
                endpoint_findings.extend(discovered_endpoint_findings)
                log_verbose(
                    args.verbose,
                    f"Discovered API scan complete: {len(discovered_endpoint_findings)} finding(s)",
                )

    if args.format == "json":
        payload = {
            "local_findings": [finding.to_dict() for finding in findings],
            "endpoint_findings": [finding.to_dict() for finding in endpoint_findings or []],
            "page_findings": [finding.to_dict() for finding in page_findings or []],
            "discovered_api_paths": discovered_api_paths,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(findings, endpoint_findings, page_findings, discovered_api_paths))

    web_failure = any(SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[args.fail_on] for finding in endpoint_findings or [])
    page_failure = has_failure(page_findings or [], args.fail_on)
    return 1 if has_failure(findings, args.fail_on) or web_failure or page_failure else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
