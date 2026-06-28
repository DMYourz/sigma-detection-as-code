"""Structural + convertibility validation for the rule set (used by the CLI)."""
from __future__ import annotations

import re
from typing import List, Tuple

from sigma.collection import SigmaCollection

from .loader import iter_rules

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
REQUIRED = ["title", "id", "description", "logsource", "detection", "level"]


def validate_all() -> Tuple[bool, List[str]]:
    problems: List[str] = []
    seen_ids: dict = {}
    for path, rule in iter_rules():
        name = path.name
        for field in REQUIRED:
            if field not in rule:
                problems.append(f"{name}: missing required field '{field}'")
        rid = str(rule.get("id", ""))
        if not UUID_RE.match(rid):
            problems.append(f"{name}: invalid/missing UUID id")
        if rid in seen_ids:
            problems.append(f"{name}: duplicate id (also in {seen_ids[rid]})")
        seen_ids[rid] = name
        if "detection" in rule and "condition" not in rule["detection"]:
            problems.append(f"{name}: detection has no condition")
        if not any(str(t).lower().startswith("attack.t") for t in rule.get("tags", [])):
            problems.append(f"{name}: no ATT&CK technique tag")
        try:
            SigmaCollection.load_ruleset([str(path)])
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{name}: pySigma cannot parse: {exc}")
    return (len(problems) == 0, problems)
