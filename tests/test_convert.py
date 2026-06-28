"""Smoke tests for SPL conversion and ATT&CK coverage generation."""
import pytest

from sigmatools.convert import convert_rule
from sigmatools.coverage import build_layer
from sigmatools.loader import iter_rules

RULES = iter_rules()
IDS = [p.name for p, _ in RULES]


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_rule_converts_to_nonempty_spl(path, rule):
    spl = convert_rule(path)
    assert spl and len(spl) > 5, f"{path.name}: empty SPL"


def test_coverage_layer_builds():
    layer = build_layer()
    assert layer["techniques"], "no techniques in ATT&CK layer"
    assert all(t["techniqueID"].startswith("T") for t in layer["techniques"])
