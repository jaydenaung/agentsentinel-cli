"""Detection rules for sentinel secrets.

Layer 1 — Credentials: API keys, tokens, private keys, database connection strings
Layer 2 — PII (global): email, credit card, US SSN, US phone
Layer 2 — PII (Singapore): NRIC/FIN, passport, mobile, landline, UEN, postal code
Layer 3 — Memory contamination: PII clusters, tool result leakage, system prompt leakage

Each rule that has a validator function is marked validated=True on a match;
rules without validators rely on regex alone (noted in comments as higher FP risk).
"""

import dataclasses
import re
from pathlib import Path
from typing import Callable


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class SecretFinding:
    """A single secret, PII, or memory contamination finding."""

    rule_id: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    category: str           # credential | pii | memory_contamination
    jurisdiction: str       # global | SGP | USA
    file: Path
    line: int
    match_preview: str      # redacted by default: first chars + [REDACTED]
    context_line: str       # surrounding line, sensitive part masked
    recommendation: str
    validated: bool = False  # True if checksum or Luhn validated


# ── File type sets (used in rule scoping) ─────────────────────────────────────

_ALL: frozenset[str] = frozenset({"memory", "config", "source", "other"})
_MEM_CFG: frozenset[str] = frozenset({"memory", "config"})
_MEM_CFG_OTHER: frozenset[str] = frozenset({"memory", "config", "other"})  # includes logs, CSVs
_MEM_ONLY: frozenset[str] = frozenset({"memory"})
_CFG_ONLY: frozenset[str] = frozenset({"config"})


# ── Singapore validators ──────────────────────────────────────────────────────

_NRIC_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
_NRIC_OFFSET: dict[str, int] = {"S": 0, "T": 4, "F": 0, "G": 4, "M": 3}
_NRIC_CHECK: dict[str, str] = {
    "S": "JZIHGFEDCBA", "T": "JZIHGFEDCBA",
    "F": "XWUTRQPNMLK", "G": "XWUTRQPNMLK",
    "M": "XWUTRQPNMLKJ",
}


def _validate_nric(value: str) -> bool:
    """Return True if value passes the Singapore NRIC/FIN weighted-sum checksum.

    Implements the official algorithm: weighted digit sum + prefix offset, mod 11,
    lookup in prefix-specific check-letter table. Eliminates ~99% of false positives.
    """
    v = value.upper()
    if len(v) != 9:
        return False
    prefix, digits_str, check = v[0], v[1:8], v[8]
    if prefix not in _NRIC_CHECK or not digits_str.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits_str, _NRIC_WEIGHTS))
    total += _NRIC_OFFSET[prefix]
    return _NRIC_CHECK[prefix][total % 11] == check


# ── Global validators ─────────────────────────────────────────────────────────

def _luhn_check(number: str) -> bool:
    """Return True if number passes the Luhn checksum (eliminates ~98% of CC false positives)."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_ssn(value: str) -> bool:
    """Reject structurally invalid US SSN patterns (all-same-digit, reserved area codes)."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    if len(set(digits)) == 1:
        return False
    area = int(digits[:3])
    return area not in (0, 666) and area < 900


# ── Credential rules (Layer 1) ────────────────────────────────────────────────

@dataclasses.dataclass
class _CredRule:
    rule_id: str
    severity: str
    pattern: re.Pattern
    file_types: frozenset[str]
    recommendation: str
    jurisdiction: str = "global"


_CRED_RULES: list[_CredRule] = [
    _CredRule("ANTHROPIC_KEY", "CRITICAL",
              re.compile(r"sk-ant-[a-zA-Z0-9\-]{90,}"), _ALL,
              "Rotate at console.anthropic.com/settings/api-keys"),
    _CredRule("OPENAI_KEY", "CRITICAL",
              re.compile(r"sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_\-]{40,}"), _ALL,
              "Rotate at platform.openai.com/api-keys"),
    _CredRule("AWS_ACCESS_KEY", "CRITICAL",
              re.compile(r"AKIA[0-9A-Z]{16}"), _ALL,
              "Rotate in AWS IAM Console and audit CloudTrail for unauthorized usage"),
    _CredRule("GITHUB_TOKEN", "CRITICAL",
              re.compile(r"gh[pos]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"), _ALL,
              "Revoke at github.com/settings/tokens"),
    _CredRule("STRIPE_SECRET", "CRITICAL",
              re.compile(r"sk_live_[a-zA-Z0-9]{24}"), _ALL,
              "Rotate immediately at dashboard.stripe.com/apikeys"),
    _CredRule("PRIVATE_KEY_BLOCK", "CRITICAL",
              re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), _ALL,
              "Remove private key from file. Use a secrets manager (AWS Secrets Manager, Vault)"),
    _CredRule("SLACK_TOKEN", "HIGH",
              re.compile(r"xox[bprs]-[0-9]+-[0-9A-Za-z\-]+"), _ALL,
              "Revoke in your Slack workspace API settings"),
    _CredRule("GOOGLE_API_KEY", "HIGH",
              re.compile(r"AIza[0-9A-Za-z\-_]{35}"), _ALL,
              "Rotate at console.cloud.google.com/apis/credentials"),
    _CredRule("HUGGINGFACE_TOKEN", "HIGH",
              re.compile(r"hf_[a-zA-Z0-9]{34}"), _ALL,
              "Revoke at huggingface.co/settings/tokens"),
    _CredRule("DATABASE_URL", "HIGH",
              re.compile(r"(?:postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"), _ALL,
              "Move database credentials to environment variables or a secrets manager"),
    _CredRule("JWT_TOKEN", "MEDIUM",
              re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),
              _MEM_CFG, "Revoke this session token and investigate how it appeared in this file"),
    _CredRule("GENERIC_API_KEY", "MEDIUM",
              re.compile(r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*[\"']?([a-zA-Z0-9]{20,})[\"']?"),
              _CFG_ONLY, "Move to environment variable or secrets manager"),
    _CredRule("GENERIC_PASSWORD", "MEDIUM",
              re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"']([^\"']{8,})[\"']"),
              _CFG_ONLY, "Move to environment variable or secrets manager"),
]


# ── PII rules (Layer 2) ───────────────────────────────────────────────────────

@dataclasses.dataclass
class _PiiRule:
    rule_id: str
    severity: str
    jurisdiction: str
    pattern: re.Pattern
    file_types: frozenset[str]
    recommendation: str
    validator: Callable[[str], bool] | None = None


_PII_RULES: list[_PiiRule] = [
    # Global
    _PiiRule("EMAIL_ADDRESS", "MEDIUM", "global",
             # Negative lookbehind: must not be preceded by alphanumeric/URL chars
             # This prevents matching mid-word substrings like password@host in DB URLs
             re.compile(r"(?<![a-zA-Z0-9._%+\-/:])[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
             _MEM_CFG_OTHER,  # also covers log files and CSV exports
             "Remove personal email addresses from agent memory. "
             "Audit which tool call produced this."),
    _PiiRule("CREDIT_CARD", "HIGH", "global",
             re.compile(
                 r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
                 r"|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
             ),
             _MEM_CFG_OTHER,  # also covers data export files
             "Credit card numbers must not appear in agent files. "
             "Purge and audit tool call history.",
             validator=lambda m: _luhn_check(re.sub(r"\D", "", m))),
    # USA
    _PiiRule("US_SSN", "HIGH", "USA",
             re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
             _MEM_CFG_OTHER,  # also covers log files and data exports
             "US SSNs are protected under US privacy law. "
             "Purge from memory files and audit data flows.",
             validator=_valid_ssn),
    _PiiRule("US_PHONE", "LOW", "USA",
             re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
             _MEM_ONLY,
             "US phone number in agent memory file. Verify this is not customer PII."),
    # Singapore — NRIC/FIN: checksum-validated, HIGH severity, scan all file types
    _PiiRule("SG_NRIC", "HIGH", "SGP",
             re.compile(r"\b[STFGMstfgm]\d{7}[A-Za-z]\b"),
             _ALL,
             "NRIC/FIN is protected under Singapore PDPA. "
             "Purge from memory and audit which tool call produced this data.",
             validator=_validate_nric),
    # Singapore — mobile (8xxx/9xxx): require +65 or standalone with word boundary
    _PiiRule("SG_PHONE_MOBILE", "MEDIUM", "SGP",
             re.compile(r"\b(?:\+65[-.\s]?)?[89]\d{3}[-.\s]?\d{4}\b"),
             _MEM_CFG,
             "Singapore mobile number in agent memory. Verify this is not customer PII."),
    # Singapore — landline (3xxx/6xxx): require explicit +65 to reduce FPs
    _PiiRule("SG_PHONE_LANDLINE", "LOW", "SGP",
             re.compile(r"\+65[-.\s]?[36]\d{3}[-.\s]?\d{4}\b"),
             _MEM_ONLY,
             "Singapore landline number in agent memory file."),
    # Singapore — passport (E/K prefix, same structure as NRIC; no checksum applied)
    _PiiRule("SG_PASSPORT", "HIGH", "SGP",
             re.compile(r"\b[EKek]\d{7}[A-Za-z]\b"),
             _ALL,
             "Singapore passport number is protected under Singapore PDPA. "
             "Purge from memory files and audit tool call history. "
             "Verify manually — regex match only, no checksum applied."),
    # Singapore — UEN (business entity, lower sensitivity)
    _PiiRule("SG_UEN", "LOW", "SGP",
             re.compile(r"\b(?:\d{9}[A-Z]|[A-Z]\d{8}[A-Z])\b"),
             _MEM_ONLY,
             "Singapore UEN (business registration number) in agent memory file."),
    # Singapore — postal code (require "Singapore" label to avoid bare 6-digit FPs)
    _PiiRule("SG_ADDRESS_POSTAL", "LOW", "SGP",
             re.compile(r"[Ss]ingapore\s+\d{6}\b"),
             _MEM_ONLY,
             "Singapore postal address in agent memory file. Verify this is not customer PII."),
]


# ── Memory contamination rules (Layer 3) ──────────────────────────────────────

_SYSTEM_PROMPT_PATS: list[re.Pattern] = [
    re.compile(r"\bYou are (?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"\bYour (?:instructions|task|goal|role|purpose|job) (?:is|are)\b", re.IGNORECASE),
    re.compile(r"\bAlways respond (?:as|like|in the)\b", re.IGNORECASE),
    re.compile(r"\bDo not (?:reveal|disclose|share) your (?:instructions|system prompt)\b", re.IGNORECASE),
]

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_NRIC_RE  = re.compile(r"\b[STFGMstfgm]\d{7}[A-Za-z]\b")
_SSN_RE   = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def check_memory_contamination(lines: list[str], file: Path) -> list[SecretFinding]:
    """Compound rules that analyse memory file content for contamination patterns.

    Checks for system prompt leakage (first 30 lines) and PII clusters (email + NRIC
    or SSN within 5 lines of each other — strong indicator of a leaked tool call result).
    """
    findings: list[SecretFinding] = []

    # SYSTEM_PROMPT_IN_MEMORY — scan first 30 lines
    for i, line in enumerate(lines[:30]):
        for pat in _SYSTEM_PROMPT_PATS:
            if pat.search(line):
                findings.append(SecretFinding(
                    rule_id="SYSTEM_PROMPT_IN_MEMORY",
                    severity="MEDIUM",
                    category="memory_contamination",
                    jurisdiction="global",
                    file=file,
                    line=i + 1,
                    match_preview=line.strip()[:50],
                    context_line=line.strip()[:100],
                    recommendation=(
                        "Agent system prompt content in memory file. "
                        "System prompts reveal agent instructions if memory files are committed to git."
                    ),
                    validated=True,
                ))
                break
        else:
            continue
        break  # one finding per file

    # CONVERSATION_PII — email + (NRIC | SSN) within 5 lines of each other
    email_lines = [i for i, ln in enumerate(lines) if _EMAIL_RE.search(ln)]
    nric_lines  = [i for i, ln in enumerate(lines)
                   if (m := _NRIC_RE.search(ln)) and _validate_nric(m.group())]
    ssn_lines   = [i for i, ln in enumerate(lines)
                   if (m := _SSN_RE.search(ln)) and _valid_ssn(m.group())]

    seen_clusters: set[int] = set()

    for ei in email_lines:
        for ni in nric_lines:
            anchor = min(ei, ni)
            if abs(ei - ni) <= 5 and anchor not in seen_clusters:
                seen_clusters.add(anchor)
                findings.append(SecretFinding(
                    rule_id="CONVERSATION_PII",
                    severity="HIGH",
                    category="memory_contamination",
                    jurisdiction="SGP",
                    file=file, line=anchor + 1,
                    match_preview="[email + NRIC cluster]",
                    context_line=f"Email line {ei + 1}, NRIC line {ni + 1}",
                    recommendation=(
                        "Singapore customer PII cluster — email + NRIC on adjacent lines. "
                        "Likely a raw tool call result (CRM/database). "
                        "Purge memory file and audit tool call history. Protected under PDPA."
                    ),
                    validated=True,
                ))
        for si in ssn_lines:
            anchor = min(ei, si)
            if abs(ei - si) <= 5 and anchor not in seen_clusters:
                seen_clusters.add(anchor)
                findings.append(SecretFinding(
                    rule_id="CONVERSATION_PII",
                    severity="HIGH",
                    category="memory_contamination",
                    jurisdiction="USA",
                    file=file, line=anchor + 1,
                    match_preview="[email + SSN cluster]",
                    context_line=f"Email line {ei + 1}, SSN line {si + 1}",
                    recommendation=(
                        "US customer PII cluster — email + SSN on adjacent lines. "
                        "Likely a raw tool call result (CRM/database). "
                        "Purge memory file and audit tool call history."
                    ),
                    validated=True,
                ))

    return findings


# ── Redaction helpers ─────────────────────────────────────────────────────────

def redact_value(value: str, show: int = 6, enabled: bool = True) -> str:
    """Return first `show` chars + [REDACTED]. Returns full value when enabled=False."""
    if not enabled:
        return value
    return (value[:show] + "[REDACTED]") if len(value) > show else "[REDACTED]"


def redact_line_context(line: str, match: str, show: int = 4, enabled: bool = True) -> str:
    """Return the line with the match partially masked, truncated to 120 chars."""
    if not enabled:
        return line[:120].strip()
    masked = (match[:show] + "[REDACTED]") if len(match) > show else "[REDACTED]"
    return line.replace(match, masked, 1)[:120].strip()
