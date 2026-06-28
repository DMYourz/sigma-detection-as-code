"""Detection regression: every rule fires on its positives, not its negatives.

This is the heart of the repo — true-positive / false-positive testing of
each Sigma rule against labeled sample events, run entirely offline.
"""
import pytest

from sigmatools.loader import iter_rules, load_cases_for
from sigmatools.matcher import evaluate

RULES = iter_rules()
IDS = [p.name for p, _ in RULES]


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_rule_has_cases(path, rule):
    cases = load_cases_for(path)
    assert cases and cases.get("positive"), f"{path.name}: needs at least one positive case"
    assert cases.get("negative"), f"{path.name}: needs at least one negative case"


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_true_positives_fire(path, rule):
    detection = rule["detection"]
    for event in load_cases_for(path).get("positive", []):
        assert evaluate(detection, event), f"{path.name}: TRUE POSITIVE did not fire -> {event}"


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_false_positives_do_not_fire(path, rule):
    detection = rule["detection"]
    for event in load_cases_for(path).get("negative", []):
        assert not evaluate(detection, event), f"{path.name}: FALSE POSITIVE fired -> {event}"
