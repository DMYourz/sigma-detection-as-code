"""Load Sigma rules and their paired TP/FP test-case files.

Paths default to the *current working directory* (run the tool from the repo
root), so the installed console script and a source checkout behave identically.
Every function also accepts explicit paths for programmatic use.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

DEFAULT_RULES_DIR = Path("rules")
DEFAULT_CASES_DIR = Path("tests") / "cases"


def load_yaml(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def iter_rules(rules_dir: Optional[Path] = None) -> List[Tuple[Path, Dict[str, Any]]]:
    base = Path(rules_dir) if rules_dir is not None else DEFAULT_RULES_DIR
    return [(path, load_yaml(path)) for path in sorted(base.rglob("*.yml"))]


def cases_path_for(rule_path: Path, cases_dir: Optional[Path] = None) -> Path:
    base = Path(cases_dir) if cases_dir is not None else DEFAULT_CASES_DIR
    return base / Path(rule_path).name


def load_cases_for(rule_path: Path, cases_dir: Optional[Path] = None) -> Optional[Dict[str, list]]:
    path = cases_path_for(rule_path, cases_dir)
    return load_yaml(path) if path.exists() else None


def technique_ids(rule: Dict[str, Any]) -> List[str]:
    """Extract MITRE ATT&CK technique IDs (e.g. T1059.001) from rule tags."""
    ids = []
    for tag in rule.get("tags", []):
        t = str(tag).lower()
        if t.startswith("attack.t"):
            ids.append(t[len("attack."):].upper())
    return ids
