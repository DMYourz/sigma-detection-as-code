"""Offline Sigma detection evaluator.

Given a Sigma rule's parsed ``detection:`` block and an event (a dict of
field -> value), decide whether the rule fires. This is what powers the
true-positive / false-positive test suite without needing a live SIEM.

Supported subset of the Sigma specification:
  * selections as maps (fields AND'd) and lists of maps (OR'd)
  * value lists (OR) and keyword lists (substring search over all values)
  * field modifiers: contains, startswith, endswith, all, re, base64,
    windash, cased
  * wildcards ``*`` and ``?`` in values; case-insensitive by default
  * condition grammar: and / or / not / parentheses,
    "N of <pattern>", "all of <pattern>", "1 of them", "all of them"
Unsupported (intentionally, to keep the engine small): cidr, base64offset,
numeric comparison operators. Rules in this repo avoid them.
"""
from __future__ import annotations

import base64
import fnmatch
import re
from typing import Any, Dict, List

_DASHES = "[-/–—]"


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _frag(expected: Any) -> str:
    """Translate a Sigma value (with ``*``/``?`` wildcards) into a regex fragment.
    A backslash escapes a literal ``*``, ``?`` or ``\\``."""
    s = _stringify(expected)
    out: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _compile(expected: Any, modifiers: List[str]) -> re.Pattern:
    cased = "cased" in modifiers
    flags = (0 if cased else re.IGNORECASE) | re.DOTALL
    if "re" in modifiers:
        return re.compile(_stringify(expected), flags)

    value = _stringify(expected)
    if "base64" in modifiers:
        value = base64.b64encode(value.encode()).decode()

    frag = _frag(value)
    if "windash" in modifiers:
        frag = frag.replace(r"\-", _DASHES)

    if "contains" in modifiers:
        pattern = frag
    elif "startswith" in modifiers:
        pattern = f"^{frag}"
    elif "endswith" in modifiers:
        pattern = f"{frag}$"
    else:
        pattern = f"^{frag}$"
    return re.compile(pattern, flags)


def _match_scalar(event_value: Any, expected: Any, modifiers: List[str]) -> bool:
    return bool(_compile(expected, modifiers).search(_stringify(event_value)))


def _match_field(event: Dict[str, Any], key: str, expected: Any) -> bool:
    field, *modifiers = key.split("|")
    present = field in event and event[field] is not None

    if expected is None:  # explicit null match
        return not present
    if not present:
        return False

    event_values = _as_list(event[field])
    expected_values = _as_list(expected)

    def one_expected_matches(exp: Any) -> bool:
        return any(_match_scalar(ev, exp, modifiers) for ev in event_values)

    if "all" in modifiers:
        return all(one_expected_matches(e) for e in expected_values)
    return any(one_expected_matches(e) for e in expected_values)


def _match_map(event: Dict[str, Any], mapping: Dict[str, Any]) -> bool:
    return all(_match_field(event, key, exp) for key, exp in mapping.items())


def _match_keywords(event: Dict[str, Any], keywords: List[Any]) -> bool:
    haystack = " ".join(
        _stringify(v) for values in event.values() for v in _as_list(values)
    )
    return any(_match_scalar(haystack, kw, ["contains"]) for kw in keywords)


def _match_selection(event: Dict[str, Any], definition: Any) -> bool:
    if isinstance(definition, dict):
        return _match_map(event, definition)
    if isinstance(definition, list):
        if definition and all(isinstance(item, dict) for item in definition):
            return any(_match_map(event, item) for item in definition)
        return _match_keywords(event, definition)
    return _match_keywords(event, [definition])


class _ConditionParser:
    """Recursive-descent evaluator for a Sigma ``condition`` string."""

    def __init__(self, tokens: List[str], selections: Dict[str, Any], event: Dict[str, Any]):
        self.toks = tokens
        self.i = 0
        self.selections = selections
        self.event = event

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self):
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def _is_kw(self, kw: str) -> bool:
        tok = self._peek()
        return tok is not None and tok.lower() == kw

    def parse(self) -> bool:
        return self._parse_or()

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._is_kw("or"):
            self._next()
            right = self._parse_and()
            value = value or right
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._is_kw("and"):
            self._next()
            right = self._parse_not()
            value = value and right
        return value

    def _parse_not(self) -> bool:
        if self._is_kw("not"):
            self._next()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok == "(":
            self._next()
            value = self._parse_or()
            if self._peek() == ")":
                self._next()
            return value
        nxt = self.toks[self.i + 1].lower() if self.i + 1 < len(self.toks) else None
        if tok is not None and (tok.lower() == "all" or tok.isdigit()) and nxt == "of":
            count = self._next()
            self._next()  # consume 'of'
            pattern = self._next()
            return self._aggregate(count, pattern)
        return self._selection_value(self._next())

    def _selection_value(self, name: str) -> bool:
        definition = self.selections.get(name)
        return _match_selection(self.event, definition) if definition is not None else False

    def _aggregate(self, count: str, pattern: str) -> bool:
        if pattern.lower() == "them":
            names = list(self.selections.keys())
        else:
            names = [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
        results = [_match_selection(self.event, self.selections[n]) for n in names]
        if count.lower() == "all":
            return bool(results) and all(results)
        return sum(1 for r in results if r) >= int(count)


def _tokenize(condition: str) -> List[str]:
    return re.findall(r"\(|\)|[A-Za-z0-9_*]+", condition)


def evaluate(detection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True if the Sigma ``detection`` block fires for ``event``."""
    selections = {k: v for k, v in detection.items() if k != "condition"}
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    for cond in conditions:
        parser = _ConditionParser(_tokenize(str(cond)), selections, event)
        if parser.parse():
            return True
    return False
