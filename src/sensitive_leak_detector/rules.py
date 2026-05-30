from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    severity: str
    pattern: re.Pattern[str]


RULES: tuple[Rule, ...] = (
    Rule(
        "private-key",
        "Private key block",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    Rule(
        "github-token",
        "GitHub token",
        "high",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
    ),
    Rule(
        "aws-access-key",
        "AWS access key id",
        "high",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    Rule(
        "slack-token",
        "Slack token",
        "high",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    Rule(
        "stripe-key",
        "Stripe API key",
        "high",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        "high",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        "medium",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    Rule(
        "database-url",
        "Database connection URL with credentials",
        "high",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^ \t\r\n]+", re.IGNORECASE),
    ),
)


SUSPICIOUS_ASSIGNMENT = re.compile(
    r"""
    \b
    (?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|passwd|pwd|credential)
    \b
    [\w\s.'"\[\]-]{0,40}
    (?:=|:|:=)
    \s*
    (?P<quote>["'])?
    (?P<value>[A-Za-z0-9_./+=:-]{20,})
    (?P=quote)?
    """,
    re.IGNORECASE | re.VERBOSE,
)
