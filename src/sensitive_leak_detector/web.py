from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import socket
import ssl
from urllib import error, parse, request


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

SENSITIVE_WORDS = ("password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key")


def normalize_base_url(value: str) -> str:
    parsed = parse.urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are supported")
    return parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def build_url(base_url: str, path: str) -> str:
    return parse.urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))


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


def looks_interesting(status: int, content_type: str, body: str, probe: EndpointProbe) -> bool:
    if status not in {200, 206, 301, 302, 307, 308}:
        return False
    if probe.rule_id in {"backup-archive", "spring-heapdump"} and status in {200, 206}:
        return True
    lowered = body.lower()
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


def scan_url(base_url: str, timeout: float = 5.0, probes: tuple[EndpointProbe, ...] = COMMON_PROBES) -> list[EndpointFinding]:
    normalized = normalize_base_url(base_url)
    findings: list[EndpointFinding] = []
    for probe in probes:
        url = build_url(normalized, probe.path)
        result = fetch_probe(url, probe, timeout)
        if result is None:
            continue
        status, content_type, body = result
        if looks_interesting(status, content_type, body, probe):
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
