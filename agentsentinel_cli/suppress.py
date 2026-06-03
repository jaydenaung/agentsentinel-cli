"""Finding suppression via .sentinelignore and --ignore-rule.

Suppressed findings are excluded from --fail-on evaluation and display.
A dim notice is printed in text mode listing what was suppressed.

.sentinelignore format:
    # comments are stripped
    RULE_ID            # suppress by rule ID (case-insensitive)
    MISSING_RATE_LIMIT
    SC03_HIDDEN_NETWORK_FIELDS   # known field, verified safe

The file is discovered by walking up from the target path to the filesystem root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HasRuleId(Protocol):
    rule_id: str


def load_ignore_file(search_path: Path) -> frozenset[str]:
    """Walk up from search_path looking for .sentinelignore; return suppressed rule IDs."""
    p = search_path if search_path.is_dir() else search_path.parent
    for _ in range(10):
        candidate = p / ".sentinelignore"
        if candidate.is_file():
            return _parse(candidate)
        parent = p.parent
        if parent == p:
            break
        p = parent
    return frozenset()


def _parse(path: Path) -> frozenset[str]:
    rules: set[str] = set()
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#")[0].strip()
            if line:
                rules.add(line.upper())
    except OSError:
        pass
    return frozenset(rules)


def merge(file_rules: frozenset[str], cli_rules: tuple[str, ...]) -> frozenset[str]:
    """Combine .sentinelignore rules with --ignore-rule CLI flags."""
    return file_rules | frozenset(r.upper() for r in cli_rules)


def apply(
    findings: list[Any], rules: frozenset[str]
) -> tuple[list[Any], list[Any]]:
    """Split findings into (active, suppressed).

    Works with any finding type that has a .rule_id attribute.
    Returns (active_findings, suppressed_findings).
    """
    if not rules:
        return findings, []
    active = [f for f in findings if f.rule_id not in rules]
    suppressed = [f for f in findings if f.rule_id in rules]
    return active, suppressed


def notice(suppressed: list[Any]) -> str:
    """Return a dim Rich-markup notice string, or empty string if nothing was suppressed."""
    if not suppressed:
        return ""
    rules = ", ".join(sorted({f.rule_id for f in suppressed}))
    n = len(suppressed)
    label = "finding" if n == 1 else "findings"
    return f"[dim]{n} {label} suppressed by .sentinelignore / --ignore-rule: {rules}[/dim]"
