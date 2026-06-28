"""Structural validation: every rule is well-formed and pySigma-convertible."""
import re

import pytest

from sigmatools.loader import iter_rules

RULES = iter_rules()
IDS = [p.name for p, _ in RULES]
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
REQUIRED = ["title", "id", "description", "logsource", "detection", "level"]


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_required_fields(path, rule):
    for field in REQUIRED:
        assert field in rule, f"{path.name}: missing '{field}'"
    assert UUID_RE.match(str(rule["id"])), f"{path.name}: invalid UUID"
    assert "condition" in rule["detection"], f"{path.name}: detection has no condition"


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_has_attack_technique_tag(path, rule):
    tags = [str(t).lower() for t in rule.get("tags", [])]
    assert any(t.startswith("attack.t") for t in tags), f"{path.name}: no ATT&CK technique tag"


def test_unique_ids():
    ids = [str(rule["id"]) for _, rule in RULES]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate rule ids: {dupes}"


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_pysigma_can_parse(path, rule):
    """Each rule must load in pySigma so it is guaranteed convertible to SPL."""
    sigma = pytest.importorskip("sigma.collection")
    sigma.SigmaCollection.load_ruleset([str(path)])
