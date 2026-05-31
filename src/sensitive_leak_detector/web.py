from __future__ import annotations

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import json
import socket
import ssl
from typing import Callable
from urllib import error, parse, request

from .scanner import Finding, scan_text


@dataclass(frozen=True)
class EndpointProbe:
    path: str
    rule_id: str
    description: str
    severity: str
    method: str = "GET"
    body: bytes | None = None
    content_type: str | None = None
    signatures: tuple[str, ...] = ()
    api_probe: bool = False


@dataclass(frozen=True)
class EndpointFinding:
    url: str
    status: int
    rule_id: str
    severity: str
    description: str
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


COMMON_PROBES: tuple[EndpointProbe, ...] = (
    EndpointProbe("/.env", "env-file", "Exposed environment file", "critical", signatures=("APP_KEY=", "DB_PASSWORD=", "AWS_SECRET")),
    EndpointProbe("/.git/config", "git-config", "Exposed Git repository metadata", "critical", signatures=("[core]", "repositoryformatversion")),
    EndpointProbe("/config.json", "config-json", "Public config file may contain secrets", "medium", signatures=("password", "secret", "token", "apiKey")),
    EndpointProbe("/config.yml", "config-yaml", "Public YAML config may contain secrets", "medium", signatures=("password", "secret", "token")),
    EndpointProbe("/backup.zip", "backup-archive", "Public backup archive", "high"),
    EndpointProbe("/database.sql", "database-dump", "Public database dump", "critical", signatures=("CREATE TABLE", "INSERT INTO")),
    EndpointProbe("/dump.sql", "database-dump", "Public database dump", "critical", signatures=("CREATE TABLE", "INSERT INTO")),
    EndpointProbe("/phpinfo.php", "phpinfo", "Public phpinfo page", "high", signatures=("phpinfo()", "PHP Version")),
    EndpointProbe("/server-status", "apache-status", "Public Apache server-status", "medium", signatures=("Apache Server Status", "Server Version")),
    EndpointProbe("/actuator/env", "spring-actuator-env", "Public Spring Actuator environment endpoint", "critical", signatures=("propertySources", "systemEnvironment")),
    EndpointProbe("/actuator/configprops", "spring-actuator-config", "Public Spring Actuator config endpoint", "high", signatures=("contexts", "beans")),
    EndpointProbe("/actuator/heapdump", "spring-heapdump", "Public Spring heap dump endpoint", "critical"),
    EndpointProbe("/swagger.json", "swagger-spec", "Public Swagger specification", "medium", signatures=("swagger", "paths")),
    EndpointProbe("/swagger/v1/swagger.json", "swagger-spec", "Public Swagger specification", "medium", signatures=("swagger", "openapi", "paths")),
    EndpointProbe("/v2/api-docs", "swagger-spec", "Public Swagger API docs", "medium", signatures=("swagger", "paths")),
    EndpointProbe("/v3/api-docs", "openapi-spec", "Public OpenAPI API docs", "medium", signatures=("openapi", "paths")),
    EndpointProbe("/openapi.json", "openapi-spec", "Public OpenAPI specification", "medium", signatures=("openapi", "paths")),
    EndpointProbe(
        "/graphql",
        "graphql-introspection",
        "GraphQL introspection appears enabled",
        "medium",
        method="POST",
        body=json.dumps({"query": "{__schema{queryType{name}}}"}).encode("utf-8"),
        content_type="application/json",
        signatures=("__schema", "queryType"),
    ),
)

COMMON_API_PATHS = (
    "/api/users",
    "/api/user",
    "/api/admin/users",
    "/api/customers",
    "/api/orders",
    "/api/order/list",
    "/api/products",
    "/api/accounts",
    "/api/profiles",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/logs",
    "/api/tokens",
    "/api/auth/user",
    "/api/me",
    "/api/profile",
    "/api/export",
    "/api/v1/users",
    "/api/v1/user",
    "/api/v1/admin/users",
    "/api/v1/customers",
    "/api/v1/orders",
    "/api/v1/accounts",
    "/api/v1/config",
    "/api/v1/settings",
    "/api/v1/debug",
    "/api/v1/logs",
    "/api/v1/me",
    "/api/v1/profile",
    "/api/v2/users",
    "/api/v2/customers",
    "/api/v2/orders",
    "/api/v2/config",
)

SENSITIVE_WORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
)

SENSITIVE_API_WORDS = SENSITIVE_WORDS + (
    "email",
    "phone",
    "mobile",
    "idcard",
    "identity",
    "address",
    "cardno",
    "bank",
    "balance",
    "amount",
    "order",
    "user_id",
    "username",
    "realname",
    "name",
    "customer",
)

LIST_HINTS = ("[", '"data"', '"items"', '"records"', '"rows"', '"list"', '"total"')

PAGE_EXTENSIONS_TO_SKIP = (
    ".7z",
    ".avi",
    ".css",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
)


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        interesting_attrs = {"a": "href", "link": "href", "script": "src", "iframe": "src"}
        attr_name = interesting_attrs.get(tag.lower())
        if not attr_name:
            return
        for name, value in attrs:
            if name.lower() == attr_name and value:
                self.links.append(value)


def normalize_base_url(value: str) -> str:
    parsed = parse.urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are supported")
    return parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def build_url(base_url: str, path: str) -> str:
    return parse.urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


def normalize_page_url(base_url: str, candidate: str) -> str | None:
    absolute = parse.urljoin(base_url, candidate)
    parsed_base = parse.urlparse(base_url)
    parsed = parse.urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc != parsed_base.netloc:
        return None
    if parsed.path.lower().endswith(PAGE_EXTENSIONS_TO_SKIP):
        return None
    return parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def extract_page_links(base_url: str, html: str) -> list[str]:
    parser = LinkExtractor()
    parser.feed(html)

    seen: set[str] = set()
    links: list[str] = []
    for raw_link in parser.links:
        normalized = normalize_page_url(base_url, raw_link)
        if normalized and normalized not in seen:
            seen.add(normalized)
            links.append(normalized)
    return links


def summarize_evidence(body: str, signatures: tuple[str, ...]) -> str:
    lowered = body.lower()
    for signature in signatures:
        index = lowered.find(signature.lower())
        if index >= 0:
            start = max(0, index - 24)
            end = min(len(body), index + len(signature) + 48)
            return body[start:end].replace("\r", " ").replace("\n", " ")[:120]

    for word in SENSITIVE_WORDS:
        index = lowered.find(word)
        if index >= 0:
            start = max(0, index - 24)
            end = min(len(body), index + len(word) + 48)
            return body[start:end].replace("\r", " ").replace("\n", " ")[:120]
    return "Endpoint returned a potentially sensitive response."


def is_json_response(content_type: str, body: str) -> bool:
    stripped = body.lstrip()
    return "json" in content_type.lower() or stripped.startswith("{") or stripped.startswith("[")


def looks_like_sensitive_api_response(content_type: str, body: str) -> bool:
    if not is_json_response(content_type, body):
        return False

    lowered = body.lower()
    sensitive_hits = sum(1 for word in SENSITIVE_API_WORDS if word in lowered)
    has_collection_shape = any(hint in lowered for hint in LIST_HINTS)
    has_object_shape = lowered.startswith("{") or lowered.startswith("[")

    if sensitive_hits >= 2 and has_object_shape:
        return True
    if sensitive_hits >= 1 and has_collection_shape:
        return True
    return False


def looks_interesting(status: int, content_type: str, body: str, probe: EndpointProbe) -> bool:
    if status not in {200, 206, 301, 302, 307, 308}:
        return False
    if probe.rule_id in {"backup-archive", "spring-heapdump"} and status in {200, 206}:
        return True
    lowered = body.lower()
    if probe.api_probe:
        return looks_like_sensitive_api_response(content_type, body)
    if probe.signatures and any(signature.lower() in lowered for signature in probe.signatures):
        return True
    if "json" in content_type.lower() and any(word in lowered for word in SENSITIVE_WORDS):
        return True
    return False


def fetch_probe(url: str, probe: EndpointProbe, timeout: float) -> tuple[int, str, str] | None:
    headers = {"User-Agent": "sensitive-leak-detector/0.1", "Accept": "*/*"}
    if probe.content_type:
        headers["Content-Type"] = probe.content_type
    req = request.Request(url, data=probe.body, method=probe.method, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read(4096).decode("utf-8", errors="replace")
            return response.status, content_type, body
    except error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace")
        return exc.code, exc.headers.get("Content-Type", ""), body
    except (error.URLError, TimeoutError, socket.timeout, ssl.SSLError):
        return None


def fetch_page(url: str, timeout: float) -> tuple[int, str, str] | None:
    headers = {
        "User-Agent": "sensitive-leak-detector/0.1",
        "Accept": "text/html,application/xhtml+xml,application/javascript,text/plain,*/*;q=0.8",
    }
    req = request.Request(url, method="GET", headers=headers)
    try:
        with request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read(256 * 1024).decode("utf-8", errors="replace")
            return response.status, content_type, body
    except error.HTTPError as exc:
        body = exc.read(256 * 1024).decode("utf-8", errors="replace")
        return exc.code, exc.headers.get("Content-Type", ""), body
    except (error.URLError, TimeoutError, socket.timeout, ssl.SSLError):
        return None


def is_page_like(content_type: str, body: str) -> bool:
    lowered = content_type.lower()
    stripped = body.lstrip().lower()
    return (
        "text/html" in lowered
        or "application/xhtml" in lowered
        or "javascript" in lowered
        or stripped.startswith("<!doctype html")
        or stripped.startswith("<html")
    )


def build_api_probes(paths: list[str] | None = None) -> tuple[EndpointProbe, ...]:
    selected_paths = list(COMMON_API_PATHS)
    if paths:
        selected_paths.extend(path if path.startswith("/") else f"/{path}" for path in paths)

    seen: set[str] = set()
    probes: list[EndpointProbe] = []
    for path in selected_paths:
        if path in seen:
            continue
        seen.add(path)
        probes.append(
            EndpointProbe(
                path=path,
                rule_id="api-sensitive-data",
                description="API endpoint may expose sensitive business or user data",
                severity="high",
                signatures=SENSITIVE_API_WORDS,
                api_probe=True,
            )
        )
    return tuple(probes)


def scan_url(
    base_url: str,
    timeout: float = 5.0,
    probes: tuple[EndpointProbe, ...] = COMMON_PROBES,
    api_paths: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[EndpointFinding]:
    normalized = normalize_base_url(base_url)
    findings: list[EndpointFinding] = []
    all_probes = probes + build_api_probes(api_paths)
    if progress:
        progress(f"Target normalized to {normalized}")
        progress(f"Prepared {len(all_probes)} endpoint probe(s)")
    for probe in all_probes:
        url = build_url(normalized, probe.path)
        if progress:
            progress(f"Testing {probe.method} {url}")
        result = fetch_probe(url, probe, timeout)
        if result is None:
            if progress:
                progress(f"No response from {url}")
            continue
        status, content_type, body = result
        if progress:
            progress(f"Received {status} from {url}")
        if looks_interesting(status, content_type, body, probe):
            if progress:
                progress(f"Finding matched: {probe.rule_id} at {url}")
            findings.append(
                EndpointFinding(
                    url=url,
                    status=status,
                    rule_id=probe.rule_id,
                    severity=probe.severity,
                    description=probe.description,
                    evidence=summarize_evidence(body, probe.signatures),
                )
            )
    return findings


def crawl_pages(
    base_url: str,
    depth: int,
    timeout: float = 5.0,
    max_pages: int = 50,
    progress: Callable[[str], None] | None = None,
) -> list[Finding]:
    if depth <= 0:
        return []

    start_url = normalize_base_url(base_url) or base_url
    queue: list[tuple[str, int]] = [(start_url, 1)]
    queued = {start_url}
    visited: set[str] = set()
    findings: list[Finding] = []

    if progress:
        progress(f"Starting page crawl at depth {depth} with max {max_pages} page(s)")

    while queue and len(visited) < max_pages:
        current_url, current_depth = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        if progress:
            progress(f"Crawling page {len(visited)}/{max_pages}: {current_url}")

        result = fetch_page(current_url, timeout)
        if result is None:
            if progress:
                progress(f"No page response from {current_url}")
            continue

        status, content_type, body = result
        if progress:
            progress(f"Received page {status} from {current_url}")
        if status not in {200, 206}:
            continue

        page_findings = scan_text(body, current_url)
        if page_findings and progress:
            progress(f"Page findings matched at {current_url}: {len(page_findings)}")
        findings.extend(page_findings)

        if current_depth >= depth or not is_page_like(content_type, body):
            continue

        for link in extract_page_links(current_url, body):
            if link not in queued and len(queued) < max_pages:
                queued.add(link)
                queue.append((link, current_depth + 1))

    if progress:
        progress(f"Page crawl complete: {len(visited)} page(s), {len(findings)} finding(s)")
    return findings
