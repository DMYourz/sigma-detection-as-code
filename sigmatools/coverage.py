"""Emit a MITRE ATT&CK Navigator layer from the rule set's technique tags."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .loader import iter_rules, technique_ids


def build_layer() -> dict:
    coverage: Dict[str, List[str]] = {}
    for _, rule in iter_rules():
        for tid in technique_ids(rule):
            coverage.setdefault(tid, []).append(rule["title"])

    max_count = max((len(v) for v in coverage.values()), default=1)
    techniques = [
        {
            "techniqueID": tid,
            "score": len(titles),
            "comment": "; ".join(sorted(titles)),
            "enabled": True,
        }
        for tid, titles in sorted(coverage.items())
    ]
    return {
        "name": "Sigma Detection-as-Code Coverage",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "ATT&CK techniques covered by this Sigma rule set.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe6e6", "#ff0000"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [],
        "sorting": 3,
        "hideDisabled": True,
    }


def write_layer(out_path: Path) -> dict:
    layer = build_layer()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return layer
