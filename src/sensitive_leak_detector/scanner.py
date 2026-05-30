from __future__ import annotations

from dataclasses import asdict, dataclass
from math import log2
from pathlib import Path
import fnmatch
import os

from .rules import RULES, SUSPICIOUS_ASSIGNMENT


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}

BINARY_EXTENSIONS = {
    ".7z",
    ".bmp",
    ".class",
    ".dll",
    ".exe",
    ".gif",
    ".ico",
    ".jar",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".zip",
}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    severity: str
    description: str
    match: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def should_skip(path: Path, root: Path, excludes: set[str]) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        relative_parts = path.parts

    for part in relative_parts:
        if part in excludes:
            return True
        if any(fnmatch.fnmatch(part, pattern) for pattern in excludes):
            return True
    return path.suffix.lower() in BINARY_EXTENSIONS


def iter_files(root: Path, excludes: set[str]) -> list[Path]:
    if root.is_file():
        return [] if should_skip(root, root.parent, excludes) else [root]

    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        current_path = Path(current_root)
        dirnames[:] = [name for name in dirnames if not should_skip(current_path / name, root, excludes)]
        for filename in filenames:
            file_path = current_path / filename
            if not should_skip(file_path, root, excludes):
                files.append(file_path)
    return files


def scan_text(text: str, display_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                findings.append(
                    Finding(
                        path=display_path,
                        line=line_number,
                        column=match.start() + 1,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        description=rule.description,
                        match=mask_secret(match.group(0)),
                    )
                )

        for match in SUSPICIOUS_ASSIGNMENT.finditer(line):
            value = match.group("value").strip("\"'")
            if shannon_entropy(value) >= 3.5:
                findings.append(
                    Finding(
                        path=display_path,
                        line=line_number,
                        column=match.start("value") + 1,
                        rule_id="high-entropy-assignment",
                        severity="medium",
                        description="High-entropy value assigned to a sensitive-looking name",
                        match=mask_secret(value),
                    )
                )
    return findings


def scan_path(root: Path, excludes: set[str] | None = None) -> list[Finding]:
    root = root.resolve()
    exclusions = set(DEFAULT_EXCLUDES)
    if excludes:
        exclusions.update(excludes)

    findings: list[Finding] = []
    for file_path in iter_files(root, exclusions):
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                text = file_path.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError:
                continue
        except OSError:
            continue

        display_path = str(file_path.relative_to(root) if root.is_dir() else file_path.name)
        findings.extend(scan_text(text, display_path))
    return sorted(findings, key=lambda item: (item.path, item.line, item.column, item.rule_id))


def has_failure(findings: list[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)
