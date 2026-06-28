"""Compile Sigma rules to Splunk SPL using pySigma."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

from .loader import iter_rules


def convert_rule(path: Path) -> str:
    collection = SigmaCollection.load_ruleset([str(path)])
    queries = SplunkBackend().convert(collection)
    return "\n".join(queries)


def _stanza_name(title: str) -> str:
    return "Sigma - " + re.sub(r"\s+", " ", title).strip()


def convert_all(out_dir: Path) -> List[Tuple[Path, dict, str]]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results: List[Tuple[Path, dict, str]] = []
    saved_searches: List[str] = []

    for path, rule in iter_rules():
        spl = convert_rule(path)
        (out / f"{path.stem}.spl").write_text(spl + "\n", encoding="utf-8")
        results.append((path, rule, spl))

        saved_searches.append(
            f"[{_stanza_name(rule['title'])}]\n"
            f"description = {rule.get('description', '').splitlines()[0] if rule.get('description') else ''}\n"
            f"search = {spl}\n"
        )

    (out / "savedsearches.conf").write_text("\n".join(saved_searches), encoding="utf-8")
    return results
